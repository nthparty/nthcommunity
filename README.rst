============
nthcommunity
============

Open-source Python library that allows developers to leverage the nth.community API and platform to implement secure, privacy-preserving data collaborations within their web services and applications.

Package Usage
------------------------------
The library can be imported in the usual ways::

    import nthcommunity
    from nthcommunity import *

Testing and Conventions
-----------------------
All unit tests are executed and their coverage is measured when using `nose <https://nose.readthedocs.io/>`_ (see ``setup.cfg`` for configuration details)::

    nosetests

Style conventions are enforced using `Pylint <https://www.pylint.org/>`_::

    pylint nthcommunity test/test_nthcommunity.py

Contributions
-------------
In order to contribute to the source code, open an issue or submit a pull request on the GitHub page for this library.

Versioning
----------
Beginning with version 0.1.0, the version number format for this library and the changes to the library associated with version number increments conform with `Semantic Versioning 2.0.0 <https://semver.org/#semantic-versioning-200>`_.
