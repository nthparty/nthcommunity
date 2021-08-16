"""Python API for nth.community.

Python library for the nth.community secure, privacy-preserving
data collaboration API and platform.
"""

from __future__ import annotations
import doctest
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
    def __init__(self, value):
        super().__init__(self)
        self.update({
            "type": "integer",
            "value": value
        })

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
    def __init__(self, identifier=None):
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

            # Extract public key to use for encrypting scalar.
            public_key = bcl.public.from_base64(c["public_key"])

            # Add encrypted contribution.
            t["value"] = [
                [
                    bcl.asymmetric.encrypt(
                        public_key,
                        scalar * oblivious.point.hash(bytes([0]) + row[0].encode())
                    ).to_base64()
                ]
                for row in contribution
            ]

            # Add padding if an explicit contribution length limit was specified.
            if "limit" in c:
                t["value"].extend([
                    [
                        bcl.asymmetric.encrypt(
                            public_key,
                            scalar * oblivious.point.hash(bytes([1]) + secrets.token_bytes(32))
                        ).to_base64()
                    ]
                    for row in range(c["limit"] - len(contribution))
                ])

            # Return modified collaboration.
            return intersection(t)

        raise ValueError("cannot contribute to collaboration due to its structure")

    @staticmethod
    def validate(collaboration): # pylint: disable=W0621
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

    @staticmethod
    def encrypt(collaboration, contribution): # pylint: disable=W0621
        """
        Encrypt a data set as a contribution to a collaboration.
        """
        # Validate the collaboration.
        if not contributor.validate(collaboration):
            raise RuntimeError('collaboration certificate is invalid')

        # Extract cryptographic material provided by recipient.
        material = collaboration["material"]

        # Encrypt data as necessitated by collaboration structure.
        if collaboration["type"] == "operation":
            if collaboration["value"] == "count":
                return contributor._for_count(collaboration, contribution, material)

        raise ValueError("cannot contribute to collaboration due to its structure")

class recipient: # pylint: disable=R0903
    """
    Methods for a collaboration result recipient.
    """
    @staticmethod
    def generate(collaboration): # pylint: disable=W0621
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
                "scalar": scalar
            }

        return contribution_keys

    @staticmethod
    def evaluate(collaborations): # pylint: disable=W0621
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
        collaboration = response_json["evaluate"] # pylint: disable=W0621
        return collaboration

if __name__ == "__main__":
    doctest.testmod() # pragma: no cover
