"""
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

class share:
    """
    Data structure for additive secret shares of an integer.
    """
    @staticmethod
    def from_bytes(bs: bytes) -> share:
        """
        Convert a share instance represented as a bytes-like object
        into a share object.
        """
        return share(
            value=int.from_bytes(bs[1:], 'little'),
            exponent=bs[0]
        )

    @staticmethod
    def from_base64(s: str) -> share:
        """
        Convert a share instance represented as a Base64 encoding of
        a bytes-like object into a share object.
        """
        return share.from_bytes(base64.standard_b64decode(s))

    def __init__(self: share, value: int, exponent: int = 32):
        self.value = value
        self.exponent = exponent

    def __add__(self: share, other: share) -> share:
        """
        Add two share instances (with base case support for
        the Python `sum` operator).
        """
        if isinstance(other, int) and other == 0:
            return self # pragma: no cover
        if self.exponent == other.exponent:
            return share(
                (self.value + other.value) % (2 ** self.exponent),
                self.exponent
            )
        return None # pragma: no cover

    def __radd__(self: share, other: share) -> share:
        """
        Add two share instances (with base case support for
        the Python `sum` operator).
        """
        if isinstance(other, int) and other == 0:
            return self
        return other + self # pragma: no cover

    def to_int(self: share):
        """
        Obtain the integer value represented by a fully reconstructed
        aggregate share (no checking is performed that a share is fully
        reconstructed).
        """
        return self.value

    def to_bytes(self: share):
        """
        Return this share object encoded as a bytes-like object.
        """
        return \
            bytes([self.exponent]) + \
            self.value.to_bytes(self.exponent // 8, 'little')

    def to_base64(self: share): # pragma: no cover
        """
        Return this share instance as a Base64 string.
        """
        return base64.standard_b64encode(self.to_bytes()).decode('utf-8')

def shares(value: int, quantity: int = 2, exponent: int = 32):
    """
    Convert an integer into the specified number of additive secret shares.
    """
    (ss, t) = ([], 0)
    for _ in range(quantity - 1):
        bs = secrets.token_bytes(exponent)
        v = int.from_bytes(bs, 'little') % (2 ** exponent)
        ss.append(share(v, exponent))
        t = (t + v) % (2 ** exponent)
    ss.append(
        share(
            (value + ((2 ** exponent) - t)) % (2 ** exponent),
            exponent
        )
    )
    return ss

class ServiceError(RuntimeError): # pylint: disable=C0103
    """
    Exception the service platform responded to an API request
    but indicated an error has occurred service-side (due to
    either an improperly configured service instance or an improper
    request).
    """

def _service(method, request):
    """
    Send a request to the service API, raise exceptions for any
    unexpected responses, and returned a parsed result.
    """
    response = requests.post(
        "https://api.nth.community/",
        data=json.dumps({method: request})
    )

    # Attempt to parse response and handle error conditions associated
    # with the response format and/or content.
    try:
        response_dict = response.json()
    except: # pragma: no cover
        raise ServiceError("service did not return a valid response") from None

    if "error" in response_dict:
        raise ServiceError(response_dict['error'])
    if method not in response_dict:
        raise ServiceError("service did not return a valid response") # pragma: no cover

    return response_dict

class collaboration(dict):
    """
    Tree data structure representing a data collaboration.
    """

class count(collaboration):
    """
    Collaboration tree node for the count operation.

    >>> count(integer(123))
    Traceback (most recent call last):
      ...
    TypeError: count operation must be applied to a single intersection collaboration
    """
    def __init__(self, *arguments, _internal=False):
        if not _internal and (
            len(arguments) != 1 or not isinstance(arguments[0], intersection)
        ):
            raise TypeError(
                "count operation must be applied to a single intersection collaboration"
            )

        super().__init__(self)
        self.update({
            "type": "operation",
            "value": "count",
            "arguments": list(arguments)
        })

class summation(collaboration):
    """
    Collaboration tree node for the summation operation.

    >>> summation(integer(123))
    Traceback (most recent call last):
      ...
    TypeError: summation operation must be applied to two or more integers
    """
    def __init__(self, *arguments, _internal=False):
        if not _internal and (
            len(arguments) < 2 or not (
                all(isinstance(argument, integer) for argument in arguments)
            )
        ):
            raise TypeError(
                "summation operation must be applied to two or more integers"
            )

        super().__init__(self)
        self.update({
            "type": "operation",
            "value": "summation",
            "arguments": list(arguments)
        })

class intersection(collaboration):
    """
    Collaboration tree node for the intersection operation.

    >>> intersection(table())
    Traceback (most recent call last):
      ...
    TypeError: intersection operation must be applied to two or more tables
    """
    def __init__(self, *arguments, _internal=False):
        if not _internal and (
            len(arguments) < 2 or not (
                all(isinstance(argument, table) for argument in arguments)
            )
        ):
            raise TypeError(
                "intersection operation must be applied to two or more tables"
            )

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

    >>> integer(-123)
    Traceback (most recent call last):
      ...
    ValueError: integer value must be a non-negative 32-bit integer
    """
    def __init__(self, value=None, contributor=None, _internal=False): # pylint: disable=W0621
        if not _internal and (
            value is not None and not (
                isinstance(value, int) and 0 <= value < 2**32
            )
        ):
            raise ValueError(
                "integer value must be a non-negative 32-bit integer"
            )

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

    >>> table(['a', 'b', 'c'])
    Traceback (most recent call last):
      ...
    ValueError: table value must be a list of single-item lists, each containing a string
    """
    def __init__(
            self, value=None, contributor=None, limit=None, # pylint: disable=W0621
            _internal=False
        ):
        if not _internal and (
            value is not None and not (
                isinstance(value, list) and all(
                    isinstance(row, list) and len(row) == 1 and isinstance(row[0], str)
                    for row in value
                )
            )
        ):
            raise ValueError(
                "table value must be a list of single-item lists, each containing a string"
            )

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

            (value, mask) = shares(contribution) # pylint: disable=W0632
            value_enc = bcl.asymmetric.encrypt(public_key_recipient, value.to_bytes())
            mask_enc = bcl.asymmetric.encrypt(public_key, mask.to_bytes())

            if c["type"] == "integer":
                # Update argument collaboration tree with contribution.
                i = integer(
                    contributor=c["contributor"],
                    value=[
                        value_enc.to_base64(),
                        mask_enc.to_base64()
                    ],
                    _internal=True
                )
                return summation(i, _internal=True)

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
            return intersection(t, _internal=True)

        raise ValueError("cannot contribute to collaboration due to its structure")

    def validate(self: contributor, collaboration): # pylint: disable=R0201,W0621
        """
        Validate the certificate within a collaboration obtained from
        a recipient by submitting it to the nth.community platform API.
        """
        response = _service("validate", {"collaboration": collaboration})
        return response["validate"]

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
                    s = s + share.from_base64(v)
                for v in c["value"][1:]:
                    bs = bcl.asymmetric.decrypt(self.secret, bcl.cipher.from_base64(v))
                    s = s + share.from_bytes(bs)
                return integer(value=s.to_int())

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
        response = _service("generate", {"collaboration": collaboration})
        contribution_keys = response["generate"]

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
        response = _service("evaluate", {"collaborations": collaborations})
        c = response["evaluate"]

        # Decrypt the response.
        c = self._decrypt(c)

        return c

if __name__ == "__main__":
    doctest.testmod() # pragma: no cover
