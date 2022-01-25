============
nthcommunity
============

Open-source Python library that allows developers to leverage the nth.community service platform and API to implement secure, privacy-preserving data collaborations within their web services and applications.

|pypi| |readthedocs| |actions| |coveralls|

.. |pypi| image:: https://badge.fury.io/py/nthcommunity.svg
   :target: https://badge.fury.io/py/nthcommunity
   :alt: PyPI version and link.

.. |readthedocs| image:: https://readthedocs.org/projects/nthcommunity/badge/?version=latest
   :target: https://nthcommunity.readthedocs.io/en/latest/?badge=latest
   :alt: Read the Docs documentation status.

.. |actions| image:: https://github.com/nthparty/nthcommunity/workflows/lint-test-cover-docs/badge.svg
   :target: https://github.com/nthparty/nthcommunity/actions/workflows/lint-test-cover-docs.yml
   :alt: GitHub Actions status.

.. |coveralls| image:: https://coveralls.io/repos/github/nthparty/nthcommunity/badge.svg?branch=main
   :target: https://coveralls.io/github/nthparty/nthcommunity?branch=main
   :alt: Coveralls test coverage summary.

Purpose and Features
--------------------
This library is a client-side component and Python API for the nth.community secure, privacy-preserving data collaboration service platform. Together, this library and the nth.community service platform make it possible to define and execute data workflows (called *collaborations*) that operate on encrypted input data without decrypting it.

This open-source library supports a very limited set of input data types (non-negative 32-bit integers and single-column tables of strings) and operations (intersection of tables, row count of an intersection of tables, and summation of integers). The secure data collaboration workflows enabled by nth.community protect contributor inputs by relying on secure multi-party computation protocols, including `private set intersection <https://en.wikipedia.org/wiki/Private_set_intersection>`_ (via the `oblivious <https://pypi.org/project/oblivious/>`_ library) and `additive secret sharing <https://en.wikipedia.org/wiki/Secret_sharing>`_ (via the `additive <https://pypi.org/project/additive/>`_ library).

Designed to be integrated easily into full-stack web applications, this library organizes secure multi-party computation workflows into a familiar structure that resembles `public-key cryptographic systems <https://en.wikipedia.org/wiki/Public-key_cryptography>`_. In order to improve portability of data and to allow programmers to leverage native Python features, data structures in the library are derived from built-in Python types and can be converted in a straightforward way to and from ubiquitous formats such as JSON.

Package Installation and Usage
------------------------------
The package is available on `PyPI <https://pypi.org/project/nthcommunity/>`_::

    python -m pip install nthcommunity

The library can be imported in the usual ways::

    import nthcommunity
    from nthcommunity import *

Example: Secure Intersection Size
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
A secure, privacy-preserving data collaboration begins when a recipient party is created. This party is responsible for defining the collaboration data workflow, distributing contribution keys to contributors, and performing the computation on the encrypted data contributions in concert with the nth.community service platform::

    >>> from nthcommunity import *
    >>> r = recipient()

Individual contributor objects encapsulate individual contributors. Two contributors are defined below::

    >>> c_a = contributor()
    >>> c_b = contributor()

Each contributor is assigned a unique identifier when the ``contributor`` object is created::

    >>> c_a.identifier()
    '57728767-55bf-4833-ab36-d3733a0e8448'

A collaboration is a tree-like data structure that defines how the overall result of a collaborative data workflow is computed. Every leaf node in the data structure must indicate which contributor must supply the encrypted data corresponding to that node. The internal, non-leaf nodes represent data operations such as ``count``, ``intersection``, and ``summation``. The collaboration workflow defined below computes the size of the intersection between two tables (one from each contributor)::

    >>> w = count(intersection(table(contributor=c_a), table(contributor=c_b)))

The recipient can (by leveraging the nth.community service platform API) generate a dictionary that maps each of the contributor identifiers to their respective contribution key::

    >>> id_to_key = r.generate(w)

Each of these individual keys ``id_to_key[c_a.identifier()]`` and ``id_to_key[c_b.identifier()]`` can be delivered to their corresponding contributor. Note that the ``collaboration`` class is derived from ``dict``, making conversion to JSON straightforward (using either the built-in `json <https://docs.python.org/3/library/json.html>`_ library or the wrapper method used below)::

    >>> print(id_to_key[c_a.identifier()].to_json(indent=2))
    {
      "type": "operation",
      "value": "count",
      "arguments": [
        {
          "type": "operation",
          "value": "intersection",
          "arguments": [
            {
              "type": "table",
              "contributor": {
                "type": "contributor",
                "identifier": "6a8dd844-6003-4475-aea7-b4182400bb90"
              },
              "public": "tdeJzrPIEpsFcykqnlN4M/hiP8gnNAJiSBRysLIutwo="
            }
          ]
        }
      ],
      "material": {
        "public": "F/RIe6jQ38Uk1CUdW7JKwd7Q9b+J+HlnOARSM70zERg=",
        "scalar": "A4f8MRxKsxZnKiScaJPw/O6uPzqBfREeNaPAaOdlnAU="
      },
      "certificate": "U4HFZcQ1hCplmec50gEDYnMxHn/ILclPmR6KC04uz1i5sJBwpEq0HB+tMlRPzWZu6dpPNuAjOzlIOshSgw7EXA=="
    }

Each contributor can then encrypt their data contribution using their key::

    >>> table_a = [['a'], ['b'], ['c'], ['d']]
    >>> enc_a = c_a.encrypt(id_to_key[c_a.identifier()], table_a)
    >>> table_b = [['b'], ['c'], ['d'], ['e']]
    >>> enc_b = c_b.encrypt(id_to_key[c_b.identifier()], table_b)

As with contributor keys, encrypted contributions can be converted to and from JSON in a straightforward way::

    >>> payload = enc_a.to_json(indent=2)
    >>> print(payload)
    {
      "type": "operation",
      "value": "count",
      "arguments": [
        {
          "type": "operation",
          "value": "intersection",
          "arguments": [
            {
              "type": "table",
              "contributor": {
                "type": "contributor",
                "identifier": "6a8dd844-6003-4475-aea7-b4182400bb90"
              },
              "public": "tdeJzrPIEpsFcykqnlN4M/hiP8gnNAJiSBRysLIutwo=",
              "value": [
                [
                  "0Ch4F9+RVGu+e0dmK+ydFvOZSLld/xMk4xcXX8U2TGY5/CUiwCtPb0bM6nwJrbZPVBIAWa5tgVCGR2Tu8LdfalxDwpGqyNuWPcUtQP8T6P8=",
                  "F1CZ5kRyYpEoZhlwTLu1gShLsH1HDZxQnQnypgDncyG+HGCrHn+UtKb9B4bvDaxbb8Nl92TV+U5ouE8MePbnFkslfwZyD6g5hWh4SOv1UhWl4uOuW4fSX8rnLsVg5VKc2Q=="
                ],
                [
                  "4noLjc9aSpY1owBlSHv9IYZr6bvxkQUhhKOhV9Ty2kZTJP7UbXgSyxjsqEr1qbEWXQ1vP1uWS+JMN+rWqtpblcitqcg/epuPYWvJi6vr9vE=",
                  "JC1L0t4JeVDr/+40c/JAsnpTqQUZLELZ5hJukDlX1Uxxf5MqZXglNc1aR9p+A5fvIZPj1P3YHOMS1Cbjpy1R3iZNUMsTOkn7pjhkZdkGE+XzHVRKz9TQdmkQZ2hk+13INQ=="
                ],
                [
                  "TmQcw0iFgnnUofuJj4hhof6oqNp1iQ94E+jqNCdQT3i8kcL4D7I33lJdLyiUwAQHm1BE6SrU+ZS+jOrfle5mfY91PuuxFsB6UBlcc8MP+Do=",
                  "puSkEfdRdNiIO668GG5jwV/zp84OhFN9rs5UjOoYNEUHif1BzrNDMq8huDJxFW8k78GbjMPZ/D4Yn5S3bjg/CwmGFPb99o4p7OwBYP1pGuds8smzUaVqcPt5FCCJxZWGYQ=="
                ],
                [
                  "PcBEJUe6IjiJ5EKUBTfeebzlLo2s291sAEdi9UnSQ3O1yg+ttOVxQQNN2QVvc4V8Swj6J+FBbC+S3+av1yV/57yW88J8YJYBTLlK0awWYqw=",
                  "ubwDp7Up8bRvznbOSmKlTDJ4MlC1JIz8zFaOHQIdfiCK1LPCKeyqIOaX/BPRbmNUkGQA9raLdsgUvWH9TQzGd3c7nvmbjltL9e4WWofM72+fBdj+/Dgg16+YAdEY6fXoog=="
                ]
              ]
            }
          ]
        }
      ]
    }
    >>> collaboration.from_json(payload) is not None
    True

Once all the encrypted contributions are received, the recipient can (by again leveraging the nth.community service platform API) execute the workflow on the encrypted contributions to obtain a result::

    >>> result = r.evaluate({c_a.identifier(): enc_a, c_b.identifier(): enc_b})
    >>> result["value"]
    3

Documentation
-------------
.. include:: toc.rst

The documentation can be generated automatically from the source files using `Sphinx <https://www.sphinx-doc.org/>`_::

    cd docs
    python -m pip install -r requirements.txt
    sphinx-apidoc -f -E --templatedir=_templates -o _source .. ../setup.py && make html

Testing and Conventions
-----------------------
All unit tests are executed and their coverage is measured when using `nose <https://nose.readthedocs.io/>`_ (see ``setup.cfg`` for configuration details)::

    python -m pip install nose coverage
    nosetests --cover-erase

Style conventions are enforced using `Pylint <https://www.pylint.org/>`_::

    python -m pip install pylint
    pylint nthcommunity test/test_nthcommunity.py

Contributions
-------------
In order to contribute to the source code, open an issue or submit a pull request on the `GitHub page <https://github.com/nthparty/nthcommunity>`_ for this library.

Versioning
----------
Beginning with version 0.1.0, the version number format for this library and the changes to the library associated with version number increments conform with `Semantic Versioning 2.0.0 <https://semver.org/#semantic-versioning-200>`_.
