"""Python API for nth.community.

Python library for the nth.community secure, privacy-preserving
data collaboration API and platform.
"""

from __future__ import annotations
import doctest
import base64
import secrets
import uuid
import json
import requests
import oblivious
import bcl

# Maximum number of rows in a data set that can be contributed.
CONTRIBUTION_LENGTH_MAX = 10000

class collaboration(dict):
    """
    Tree data structure representing a data collaboration.
    """

class count(collaboration):
    """
    Collaboration tree node for the count operation.
    """
    def __init__(self, *arguments):
        super().__init__(self)
        self.update({
            "type": "operation",
            "value": "count",
            "arguments": list(arguments)
        })

class summation(collaboration):
    """
    Collaboration tree node for the summation operation.
    """
    def __init__(self, *arguments):
        super().__init__(self)
        self.update({
            "type": "operation",
            "value": "summation",
            "arguments": list(arguments)
        })

class intersection(collaboration):
    """
    Collaboration tree node for the intersection operation.
    """
    def __init__(self, *arguments):
        super().__init__(self)
        self.update({
            "type": "operation",
            "value": "intersection",
            "arguments": list(arguments)
        })

class integer(collaboration):
    """
    A contributed data set within a collaboration tree
    data structure.
    """
    def __init__(self, value=None, contributor=None): # pylint: disable=W0621
        super().__init__(self)
        self["type"] = "integer"
        if value is not None:
            self["value"] = value
        if contributor is not None:
            self["contributor"] = contributor

class table(collaboration):
    """
    A contributed data set within a collaboration tree
    data structure.
    """
    def __init__(self, value=None, contributor=None, limit=None): # pylint: disable=W0621
        super().__init__(self)
        self["type"] = "table"
        if contributor is not None:
            self["contributor"] = contributor
        if limit is not None:
            if limit > CONTRIBUTION_LENGTH_MAX:
                raise ValueError(
                    'maximum table length limit is ' + str(CONTRIBUTION_LENGTH_MAX)
                )
            self["limit"] = limit
        if value is not None:
            if len(value) > self.get("limit", CONTRIBUTION_LENGTH_MAX):
                raise ValueError(
                    'table length exceeds maximum of ' + \
                    str(self.get("limit", CONTRIBUTION_LENGTH_MAX))
                )
            self["value"] = value

class contributor(dict):
    """
    Data structure and methods for an individual data contributor
    within a collaboration.
    """
    def __init__(self: contributor, identifier=None):
        super().__init__(self)
        self.update({
            "type": "contributor",
            "identifier": str(uuid.uuid4()) if identifier is None else identifier
        })

    @staticmethod
    def _for_count(collaboration, contribution, material): # pylint: disable=W0621
        """
        Encrypt a data set as a contribution to a collaboration
        (or sub-collaboration) that has a `count` operation node.
        """
        argument = collaboration["arguments"][0]

        if argument["type"] == "operation" and argument["value"] == "intersection":
            # Update argument collaboration tree with contribution.
            return count(contributor._for_intersection(argument, contribution, material))

        raise ValueError("cannot contribute to collaboration due to its structure")

    @staticmethod
    def _for_summation(collaboration, contribution, material): # pylint: disable=W0621
        """
        Encrypt a data set as a contribution to a collaboration
        (or sub-collaboration) that has a `summation` operation node.
        """
        c = collaboration["arguments"][0]

        if "public" in c:
            # Extract public key to use for encrypting for the service platform.
            public_key = bcl.public.from_base64(c["public"])

            # Extract public key to use for encrypting data for the recipient.
            public_key_recipient = bcl.public.from_base64(material["public"])

            mask = (int.from_bytes(secrets.token_bytes(32), 'little') % (2**128))
            value = (contribution + mask) % (2**128)

            value_enc = bcl.asymmetric.encrypt(
                public_key_recipient,
                int(value).to_bytes(32, 'little')
            )
            mask_enc = bcl.asymmetric.encrypt(
                public_key,
                int(mask).to_bytes(32, 'little')
            )

            if c["type"] == "integer":
                # Update argument collaboration tree with contribution.
                i = integer(
                    contributor=c["contributor"],
                    value=[
                        value_enc.to_base64(),
                        mask_enc.to_base64()
                    ]
                )
                return summation(i)

        raise ValueError("cannot contribute to collaboration due to its structure")

    @staticmethod
    def _for_intersection(collaboration, contribution, material): # pylint: disable=W0621
        """
        Encrypt a data set as a contribution to a collaboration
        (or sub-collaboration) that has an `intersection` operation node.
        """
        c = collaboration["arguments"][0]
        scalar = oblivious.scalar.from_base64(material["scalar"])

        if c["type"] == "table":
            # Ensure the contribution satisfies the length limit (both
            # the universal one and the one specified in the collaboration).
            if len(contribution) > c.get("limit", CONTRIBUTION_LENGTH_MAX):
                raise ValueError(
                    'contribution length exceeds maximum of ' + \
                    str(c.get("limit", CONTRIBUTION_LENGTH_MAX))
                )

            # Result is a new instance (not in-place modification of existing collaboration).
            t = table(contributor=c["contributor"])
            t["public_key"] = c["public_key"]

            # Extract public key to use for encrypting the scalar and data
            # for the service platform (vs. the recipient).
            public_key = bcl.public.from_base64(c["public_key"])

            # Extract public key to use for encrypting data for the recipient.
            public_key_recipient = bcl.public.from_base64(material["public"])

            # Add encrypted contribution.
            t["value"] = [
                [
                    bcl.asymmetric.encrypt(
                        public_key,
                        scalar * oblivious.point.hash(bytes([0]) + row[0].encode())
                    ).to_base64(),
                    bcl.asymmetric.encrypt(
                        public_key,
                        bcl.asymmetric.encrypt(
                            public_key_recipient,
                            row[0].encode()
                        )
                    ).to_base64()
                ]
                for row in contribution
            ]

            # Add padding if an explicit contribution length limit was specified.
            lengths = [len(row[0].encode()) for row in contribution]
            if "limit" in c:
                t["value"].extend([
                    [
                        bcl.asymmetric.encrypt(
                            public_key,
                            scalar * oblivious.point.hash(bytes([1]) + secrets.token_bytes(32))
                        ).to_base64(),
                        bcl.asymmetric.encrypt(
                            public_key,
                            bcl.asymmetric.encrypt(
                                public_key_recipient,
                                secrets.token_bytes(lengths[i % len(lengths)])
                            )
                        ).to_base64()
                    ]
                    for i in range(c["limit"] - len(contribution))
                ])

            # Return modified collaboration.
            return intersection(t)

        raise ValueError("cannot contribute to collaboration due to its structure")

    def validate(self: contributor, collaboration): # pylint: disable=R0201,W0621
        """
        Validate the certificate within a collaboration obtained from
        a recipient by submitting it to the nth.community platform API.
        """
        response = requests.post(
            "https://api.nth.community/",
            data=json.dumps({
                "validate": {
                    "collaboration": collaboration
                }
            })
        )
        response_json = response.json()
        return response_json["validate"]

    def encrypt(self: contributor, collaboration, contribution): # pylint: disable=W0621
        """
        Encrypt a data set as a contribution to a collaboration.
        """
        c = collaboration

        # Validate the collaboration.
        if not self.validate(c):
            raise RuntimeError('collaboration certificate is invalid')

        # Extract cryptographic material provided by recipient.
        material = c["material"]

        # Encrypt data as necessitated by collaboration structure.
        if c["type"] == "operation":
            if c["value"] == "count":
                return contributor._for_count(c, contribution, material)
            if c["value"] == "intersection":
                return contributor._for_intersection(c, contribution, material)
            if c["value"] == "summation":
                return contributor._for_summation(c, contribution, material)

        raise ValueError("cannot contribute to collaboration due to its structure")

class recipient: # pylint: disable=R0903
    """
    Methods for a collaboration result recipient.
    """
    def __init__(self: recipient):
        self.secret = bcl.asymmetric.secret()
        self.public = bcl.asymmetric.public(self.secret)

    def _decrypt(self: recipient, collaboration): # pylint: disable=W0621
        """
        Decrypt the result of a collaboration (if it is necessary to do so).
        """
        c = collaboration

        # Raw integer outputs do not need to be decrypted
        if c["type"] == "integer":
            if isinstance(c["value"], int):
                return integer(value=c["value"])
            if isinstance(c["value"], list):
                s = 0
                for v in c["value"][:1]:
                    s = (s + int.from_bytes(base64.standard_b64decode(v), 'little')) % (2**128)
                for v in c["value"][1:]:
                    bs = bcl.asymmetric.decrypt(self.secret, bcl.cipher.from_base64(v))
                    s = (s + int.from_bytes(bs, 'little')) % (2**128)
                return integer(value=s)

        # Decrypt the contents of the table.
        if c["type"] == "table":
            c["value"] = [
                [
                    bcl.asymmetric.decrypt(
                        self.secret,
                        bcl.cipher.from_base64(row[0])
                    ).decode('utf-8')
                ]
                for row in c["value"]
            ]
            return c

        return None # pragma: no cover

    def generate(self: recipient, collaboration): # pylint: disable=R0201,W0621
        """
        Submit a collaboration via the nth.community platform
        API to receive the set of contributor keys that can be
        distributed to contributors.
        """
        response = requests.post(
            "https://api.nth.community/",
            data=json.dumps({
                "generate": {
                    "collaboration": collaboration
                }
            })
        )
        response_json = response.json()
        contribution_keys = response_json["generate"]

        # Add recipient-generated cryptographic material.
        scalar = oblivious.scalar().to_base64()
        for contribution_key in contribution_keys.values():
            contribution_key["material"] = {
                "public": self.public.to_base64(),
                "scalar": scalar
            }

        return contribution_keys

    def evaluate(self: recipient, collaborations): # pylint: disable=R0201,W0621
        """
        Evaluate a collaboration (represented as a collection of
        collaborations from contributors) by submitting it to the
        nth.community platform API.
        """
        response = requests.post(
            "https://api.nth.community/",
            data=json.dumps({
                "evaluate": {
                    "collaborations": collaborations
                }
            })
        )
        response_json = response.json()
        c = response_json["evaluate"] # pylint: disable=W0621
        c = self._decrypt(c)
        return c

if __name__ == "__main__":
    doctest.testmod() # pragma: no cover
