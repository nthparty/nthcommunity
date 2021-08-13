"""Python API for nth.community.

Python library for the nth.community secure, privacy-preserving
data collaboration API and platform.
"""

from __future__ import annotations
import uuid
import doctest

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
            "arguments": arguments
        })

class intersect(collaboration):
    """
    Collaboration tree node for the intersection operation.
    """
    def __init__(self, *arguments):
        super().__init__(self)
        self.update({
            "type": "operation",
            "value": "intersect",
            "arguments": arguments
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
    Data structure for an individual data contributor
    within a collaboration.
    """
    def __init__(self, identifier=None):
        super().__init__(self)
        self.update({
            "type": "contributor",
            "identifier": str(uuid.uuid4()) if identifier is None else identifier
        })

if __name__ == "__main__":
    doctest.testmod()
