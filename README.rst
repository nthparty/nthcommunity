============
nthcommunity
============

Open-source Python library that allows developers to leverage the nth.community API and platform to implement secure, privacy-preserving data collaborations within their web services and applications.

|readthedocs| |travis| |coveralls|

.. |readthedocs| image:: https://readthedocs.org/projects/mr4mp/badge/?version=latest
   :target: https://mr4mp.readthedocs.io/en/latest/?badge=latest
   :alt: Read the Docs documentation status.

.. |travis| image:: https://app.travis-ci.com/nthparty/nthcommunity.svg?branch=main
   :target: https://app.travis-ci.com/nthparty/nthcommunity
   :alt: Travis CI build status.

.. |coveralls| image:: https://coveralls.io/repos/github/nthparty/nthcommunity/badge.svg?branch=main
   :target: https://coveralls.io/github/nthparty/nthcommunity?branch=main
   :alt: Coveralls test coverage summary.

Package Usage
------------------------------
The library can be imported in the usual ways::

    import nthcommunity
    from nthcommunity import *

Documentation
-------------
.. include:: toc.rst

The documentation can be generated automatically from the source files using `Sphinx <https://www.sphinx-doc.org/>`_::

    python -m pip install sphinx sphinx-rtd-theme
    cd docs
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
