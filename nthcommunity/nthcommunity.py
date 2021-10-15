"""
Python library for the nth.community secure, privacy-preserving
data collaboration service platform and API.

An end-to-end example is presented in the documentation for the
:obj:`recipient` class.
"""
from __future__ import annotations
from typing import Union
import doctest
import secrets
import uuid
import json
import requests
import additive
import oblivious
import bcl

# The nth.community service platform API endpoint.
API_URL = "https://api.nth.community/0.1.0/"

# Upper bounds on table and table field sizes.
CONTRIBUTION_MAX_TABLE_LENGTH = 1000
CONTRIBUTION_MAX_TABLE_ROW_FIELD_LENGTH = 256

class collaboration(dict):
    """
    Base class for tree data structure representing a data collaboration.
    Consult definitions of derived classes such as :obj:`intersection`
    and :obj:`table` for more details, and find in-context usage examples
    in the documentation for the :obj:`recipient` class.
    """
    @staticmethod
    def from_json(argument: Union[str, dict]) -> collaboration:
        """
        Parse a dictionary or JSON string into an instance of this class.
        Find usage examples in the documentation for the :obj:`recipient`
        class.
        """
        if isinstance(argument, str):
            argument = json.loads(argument)

        if argument.get("type") == "operation":
            arguments = argument.get("arguments")
            if isinstance(arguments, list):
                cs = [collaboration.from_json(a) for a in arguments]

            if argument.get("value") == "count":
                c = count(*cs, _internal=True)
            elif argument.get("value") == "intersection":
                c = intersection(*cs, _internal=True)
            elif argument.get("value") == "summation":
                c = summation(*cs, _internal=True)

            if "material" in argument:
                c["material"] = argument["material"]
            if "certificate" in argument:
                c["certificate"] = argument["certificate"]

            return c

        if argument.get("type") == "integer" and "contributor" in argument:
            i = integer(
                value=argument.get("value"),
                contributor=contributor.from_json(argument["contributor"]),
                _internal=True
            )

            if "public" in argument:
                i["public"] = argument["public"]

            return i

        if argument.get("type") == "table" and "contributor" in argument:
            t = table(
                value=argument.get("value"),
                limit=argument.get("limit"),
                contributor=contributor.from_json(argument["contributor"]),
                _internal=True
            )

            if "public" in argument:
                t["public"] = argument["public"]

            return t

        raise ValueError(
            "supplied JSON string or dictionary does not represent a " + \
            "collaboration with correct internal structure"
        )

    def to_json(self, *args, **kwargs) -> str:
        """
        Convert an instance of this class into a JSON string. This method
        is a wrapper for the ``json.dumps`` method found in the built-in
        `json <https://docs.python.org/3/library/json.html>`_ library.
        Find usage examples in the documentation for the :obj:`recipient`
        class.
        """
        return json.dumps(self, *args, **kwargs)

class recipient: # pylint: disable=R0903
    """
    A collaboration begins with a recipient party represented by a
    :obj:`recipient` object. The recipient defines a :obj:`collaboration`
    workflow, generates keys for individual contributors, accepts encrypted
    contributions, and computes the results in concert with the nth.community
    service platform.

    >>> r = recipient()

    Individual :obj:`contributor` objects represent and uniquely identify
    individual contributors.

    >>> c_a = contributor()
    >>> c_b = contributor()

    The :obj:`contributor` class is derived from ``dict`` and contains a
    value under the ``'identifier'`` key that corresponds to the unique
    identifier for that contributor. This value can also be retrieved using
    the :obj:`contributor.identifier` method.

    >>> 'identifier' in c_a
    True
    >>> c_a.identifier() is not None
    True

    A :obj:`collaboration` is a tree-like data structure that defines how the
    overall result of the collaboration is computed. Each leaf node of
    the data structure must indicate which contributor must supply the
    encrypted data corresponding to that node. The internal, non-leaf nodes
    represent data operations such as :obj:`count`, :obj:`summation`, and
    :obj:`intersection`.

    >>> w = count(intersection(table(contributor=c_a), table(contributor=c_b)))

    The recipient can use the :obj:`recipient.generate` method (which internally
    leverages the nth.community service platform) to create a dictionary that
    maps each contributor identifier to its respective contribution key *for
    that specific collaboration workflow*.

    >>> id_to_key = r.generate(w)

    Each of these individual keys ``id_to_key[c_a.identifier()]`` and
    ``id_to_key[c_b.identifier()]`` can be converted to JSON using the
    :obj:`collaboration.to_json` method and delivered to their corresponding
    contributor.

    >>> key_a_json = id_to_key[c_a.identifier()].to_json()
    >>> key_b_json = id_to_key[c_b.identifier()].to_json()

    Contributors can parse the JSON strings using :obj:`collaboration.from_json`.

    >>> key_a = collaboration.from_json(key_a_json)
    >>> key_b = collaboration.from_json(key_b_json)

    Each contributor can then use the :obj:`contributor.encrypt` method to
    encrypt their data contribution using their key. After validating the
    contribution key, this method *does not perform any external communications*
    and encrypts the input data *entirely within the host environment belonging
    to the contributor*. In particular, it does **not** communicate with the
    nth.community service platform or the recipient during this process.

    >>> table_a = [['a'], ['b'], ['c'], ['d']]
    >>> enc_a = c_a.encrypt(key_a, table_a)
    >>> table_b = [['b'], ['c'], ['d'], ['e']]
    >>> enc_b = c_b.encrypt(key_b, table_b)

    Because encrypted contributions are also :obj:`collaboration` objects, they
    can be easily converted to and from JSON strings. The recipient can then use
    the :obj:`recipient.evaluate` method (which again internally leverages the
    nth.community service platform) to evaluate the encrypted contributions
    and obtain a result.

    >>> result = r.evaluate({c_a.identifier(): enc_a, c_b.identifier(): enc_b})
    >>> result["value"]
    3
    """
    def __init__(self):
        self.secret = bcl.asymmetric.secret()
        self.public = bcl.asymmetric.public(self.secret)

    def _decrypt(self, collaboration): # pylint: disable=W0621
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
                    s = s + additive.share.from_base64(v)
                for v in c["value"][1:]:
                    bs = bcl.asymmetric.decrypt(self.secret, bcl.cipher.from_base64(v))
                    s = s + additive.share.from_bytes(bs)
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

    def generate(self, collaboration) -> dict: # pylint: disable=W0621
        """
        Submit a collaboration via the nth.community service platform API to
        receive the set of contributor keys that can be distributed to
        contributors. Find an in-context usage example in the
        documentation for the :obj:`recipient` class.
        """
        response = _service("generate", {"collaboration": collaboration})
        contribution_keys = response["generate"]

        # Add recipient-generated cryptographic material.
        scalar = oblivious.scalar().to_base64()
        for identifier in contribution_keys:
            contribution_keys[identifier]["material"] = {
                "public": self.public.to_base64(),
                "scalar": scalar
            }
            contribution_keys[identifier] = collaboration.from_json(
                contribution_keys[identifier]
            )

        return contribution_keys

    def evaluate(self, collaborations) -> collaboration: # pylint: disable=W0621
        """
        Evaluate a collaboration workflow instantiated with encrypted data
        contributions (represented as a dictionary that maps each contributor's
        identifier to that contributor's encrypted contribution) by submitting
        it to the nth.community service platform. Find an in-context usage example
        in the documentation for the :obj:`recipient` class.
        """
        response = _service("evaluate", {"collaborations": collaborations})
        c = response["evaluate"]

        # Decrypt the response.
        c = self._decrypt(c)

        return c

class contributor(dict):
    """
    Data structure and methods for an individual data contributor within
    a collaboration. A contributor receives a collaboration key from a
    recipient and encrypts their data contribution using that key.

    >>> (r, c_a, c_b) = (recipient(), contributor(), contributor())
    >>> w = count(intersection(table(contributor=c_a), table(contributor=c_b)))
    >>> id_to_key = r.generate(w)

    Each of the individual keys in ``id_to_key.values()`` can be delivered
    to their corresponding contributor. Each contributor can then use the
    key to encrypt their data contribution via the :obj:`contributor.encrypt` 
    method, as shown below.

    >>> id_a = c_a.identifier()
    >>> table_a = [['a'], ['b'], ['c'], ['d']]
    >>> table_a_encrypted = c_a.encrypt(id_to_key[id_a], table_a)
    """
    def __init__(self, identifier=None):
        super().__init__(self)
        self.update({
            "type": "contributor",
            "identifier": str(uuid.uuid4()) if identifier is None else identifier
        })

    def identifier(self) -> str:
        """
        Return this contributor's unique identifier.

        >>> c = contributor()
        >>> isinstance(c.identifier(), str)
        True
        """
        return self["identifier"]

    @staticmethod
    def from_json(argument: Union[str, dict]) -> contributor:
        """
        Parse a dictionary or JSON string into an instance of this class.

        >>> s = '{"type": "contributor", "identifier": "b1a63caf"}'
        >>> isinstance(contributor.from_json(s), contributor)
        True
        """
        if isinstance(argument, str):
            argument = json.loads(argument)

        if argument.get("type") == "contributor" and "identifier" in argument:
            return contributor(
                identifier=argument.get("identifier")
            )

        raise ValueError(
            "supplied JSON string or dictionary does not represent a " + \
            "contributor with correct internal structure"
        )

    def to_json(self, *args, **kwargs) -> str:
        """
        Convert an instance of this class into a JSON string. This method
        is a wrapper for the ``json.dumps`` method found in the built-in
        `json <https://docs.python.org/3/library/json.html>`_ library.

        >>> c = contributor('b1a63caf-a549-429e-8ed0-44cd5fbb0eeb')
        >>> c.to_json()
        '{"type": "contributor", "identifier": "b1a63caf-a549-429e-8ed0-44cd5fbb0eeb"}'
        """
        return json.dumps(self, *args, **kwargs)

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
        Encrypt an integer as a contribution to a collaboration
        (or sub-collaboration) that has a `summation` operation node.
        """
        c = collaboration["arguments"][0]

        if c.get("type") == "integer" and "public" in c:
            # Extract public key to use for encrypting for the service platform.
            public_key_platform = bcl.public.from_base64(c["public"])

            # Extract public key to use for encrypting data for the recipient.
            public_key_recipient = bcl.public.from_base64(material["public"])

            (value, mask) = additive.shares(contribution) # pylint: disable=W0632
            value_enc = bcl.asymmetric.encrypt(public_key_recipient, value.to_bytes())
            mask_enc = bcl.asymmetric.encrypt(public_key_platform, mask.to_bytes())

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
            if len(contribution) > c.get("limit", CONTRIBUTION_MAX_TABLE_LENGTH):
                raise ValueError(
                    'contribution length exceeds maximum of ' + \
                    str(c.get("limit", CONTRIBUTION_MAX_TABLE_LENGTH))
                )

            # Result is a new instance (not in-place modification of existing collaboration).
            t = table(contributor=c["contributor"])
            t["public"] = c["public"]

            # Extract public key to use for encrypting the scalar and data
            # for the service platform (vs. the recipient).
            public_key_platform = bcl.public.from_base64(c["public"])

            # Extract public key to use for encrypting data for the recipient.
            public_key_recipient = bcl.public.from_base64(material["public"])

            # Add encrypted contribution.
            t["value"] = [
                [
                    bcl.asymmetric.encrypt(
                        public_key_platform,
                        scalar * oblivious.point.hash(bytes([0]) + row[0].encode())
                    ).to_base64(),
                    bcl.asymmetric.encrypt(
                        public_key_platform,
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
                            public_key_platform,
                            scalar * oblivious.point.hash(bytes([1]) + secrets.token_bytes(32))
                        ).to_base64(),
                        bcl.asymmetric.encrypt(
                            public_key_platform,
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

    def validate(self, collaboration) -> bool: # pylint: disable=R0201,W0621
        """
        Validate the certificate within a contribution key obtained from
        a recipient by submitting it to the nth.community service platform.
        The :obj:`contributor.encrypt` method automatically invokes this
        method before encrypting a contribution.

        >>> (r, c_a, c_b) = (recipient(), contributor(), contributor())
        >>> w = count(intersection(table(contributor=c_a), table(contributor=c_b)))
        >>> key_a = r.generate(w)[c_a.identifier()]
        >>> c_a.validate(key_a)
        True
        """
        response = _service("validate", {"collaboration": collaboration})
        return response["validate"]

    def encrypt(self, collaboration, contribution) -> collaboration: # pylint: disable=W0621
        """
        Encrypt a data set as a contribution to a collaboration. Find an in-context
        usage example in the documentation for the :obj:`recipient` class.

        >>> (r, c_a, c_b) = (recipient(), contributor(), contributor())
        >>> w = count(intersection(table(contributor=c_a), table(contributor=c_b)))
        >>> key_a = r.generate(w)[c_a.identifier()]
        >>> table_a = [['a'], ['b'], ['c'], ['d']]
        >>> enc_a = c_a.encrypt(key_a, table_a)

        After validating the contribution key, this method *does not perform any
        external communications* and encrypts the input data *entirely within the
        host environment belonging to the contributor*. In particular, it does
        **not** communicate with the nth.community service platform or the recipient
        during this process.
        """
        c = collaboration

        # Validate the collaboration.
        if not self.validate(c):
            raise RuntimeError('collaboration certificate is invalid')

        # Extract cryptographic material provided by recipient.
        if "material" in c:
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

class count(collaboration):
    """
    Collaboration tree node for the count operation. A count operation can be
    applied to a single intersection collaboration.

    >>> (c_a, c_b) = (contributor(), contributor())
    >>> w = count(intersection(table(contributor=c_a), table(contributor=c_b)))

    Any attempt to apply a count operation to a collaboration workflow that is
    not compatible with a count operation raises an exception.

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
    Collaboration tree node for the summation operation. A summation operation
    can be applied to two or more contributors' integer contributions.

    >>> (c_a, c_b) = (contributor(), contributor())
    >>> w = summation(integer(contributor=c_a), integer(contributor=c_b))

    Any attempt to apply a summation operation to a collaboration workflow that
    is not compatible with a summation operation raises an exception.

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
    Collaboration tree node for the intersection operation. An intersection
    operation can be applied to two or more contributors' table contributions.

    >>> (c_a, c_b) = (contributor(), contributor())
    >>> w = intersection(table(contributor=c_a), table(contributor=c_b))

    Any attempt to apply an intersection operation to a collaboration workflow
    that is not compatible with an intersection operation raises an exception.

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
    Collaboration tree leaf node for a contributed integer value within
    a collaboration tree data structure. Only 32-bit non-negative integers
    are supported.

    >>> c = contributor()
    >>> w = integer(value=123, contributor=c)

    Any attempt to construct an invalid integer contribution raises an
    exception.

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
    Collaboration tree leaf node for a contributed data table within a
    collaboration tree data structure. A contributed table must be a
    list of rows, and each row must a single-element list that contains
    exactly one string.

    >>> c = contributor()
    >>> w = table(value=[['a'], ['b'], ['c']], contributor=c)

    Any attempt to construct a data table contribution that is invalid or
    that exceeds size limits raises an exception.

    >>> table(['a', 'b', 'c'])
    Traceback (most recent call last):
      ...
    ValueError: table value must be a list of single-item lists, each containing a string
    >>> table([['a']] * 1001)
    Traceback (most recent call last):
      ...
    ValueError: table length exceeds maximum of 1000
    >>> table([['a'  * 257]])
    Traceback (most recent call last):
      ...
    ValueError: table field value length exceeds maximum of 256
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
            if limit > CONTRIBUTION_MAX_TABLE_LENGTH:
                raise ValueError(
                    'maximum table length limit is ' + str(CONTRIBUTION_MAX_TABLE_LENGTH)
                )
            self["limit"] = limit
        if value is not None:
            if len(value) > self.get("limit", CONTRIBUTION_MAX_TABLE_LENGTH):
                raise ValueError(
                    'table length exceeds maximum of ' + \
                    str(self.get("limit", CONTRIBUTION_MAX_TABLE_LENGTH))
                )
            if any(len(row[0]) > CONTRIBUTION_MAX_TABLE_ROW_FIELD_LENGTH for row in value):
                raise ValueError(
                    'table field value length exceeds maximum of ' + \
                    str(CONTRIBUTION_MAX_TABLE_ROW_FIELD_LENGTH)
                )
            self["value"] = value

class ServiceError(RuntimeError): # pylint: disable=C0103
    """
    Exception indicating that the service platform responded to an API
    request but indicated an error has occurred service-side (due to either
    an improperly configured service instance or an improper request).

    >>> (c_a, c_b) = (contributor(), contributor())
    >>> w = count(intersection(table(contributor=c_a), table(contributor=c_b)))
    >>> del w["type"]
    >>> try:
    ...     recipient().generate(w)
    ... except ServiceError as e:
    ...     print(e)
    service did not return a valid response
    """

def _service(method, request):
    """
    Send a request to the service API, raise exceptions for any
    unexpected responses, and returned a parsed result.
    """
    response = requests.post(API_URL, data=json.dumps({method: request}))

    # Attempt to parse response and handle error conditions associated
    # with the response format and/or content.
    try:
        response_dict = response.json()
    except: # pragma: no cover
        raise ServiceError('service did not return a valid response') from None

    if "error" in response_dict:
        raise ServiceError(response_dict['error'])
    if method not in response_dict:
        raise ServiceError('service did not return a valid response')

    return response_dict

if __name__ == "__main__":
    doctest.testmod() # pragma: no cover
