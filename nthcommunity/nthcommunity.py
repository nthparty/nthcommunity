"""Python API for nth.community.

Python library for the nth.community secure, privacy-preserving
data collaboration API and platform.
"""

from __future__ import annotations
import doctest
import uuid
import json
import requests
import oblivious

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
