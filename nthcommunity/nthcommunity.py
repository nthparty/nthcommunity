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
CONTRIBUTION_MAX = 10000

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
    def __init__(self, value=None, contributor=None): # pylint: disable=W0621
        super().__init__(self)
        self["type"] = "table"
        if value is not None:
            self["value"] = value
        if contributor is not None:
            self["contributor"] = contributor

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
            ] + [
                [
                    bcl.asymmetric.encrypt(
                        public_key,
                        scalar * oblivious.point.hash(bytes([1]) + secrets.token_bytes(32))
                    ).to_base64()
                ]
                for row in range(CONTRIBUTION_MAX - len(contribution))
            ]

            # Return modified collaboration.
            return intersection(t)

        raise ValueError("cannot contribute to collaboration due to its structure")

    @staticmethod
    def encrypt(collaboration, contribution): # pylint: disable=W0621
        """
        Encrypt a data set as a contribution to a collaboration.
        """
        if len(contribution) > CONTRIBUTION_MAX:
            raise ValueError("contribution length cannot exceed " + str(CONTRIBUTION_MAX))

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

if __name__ == "__main__":
    doctest.testmod()
