from setuptools import setup

with open("README.rst", "r") as fh:
    long_description = fh.read().replace(".. include:: toc.rst\n\n", "")

# The line below can be parsed by `docs/conf.py`.
name = "nthcommunity"
version = "1.0.0"

setup(
    name=name,
    version=version,
    packages=[name,],
    install_requires=[
        "requests~=2.26",
        "oblivious~=4.0",
        "bcl~=2.0",
        "additive~=0.1"
    ],
    license="MIT",
    url="https://github.com/nthparty/nthcommunity",
    author="Nth Party, Ltd.",
    author_email="team@nthparty.com",
    description="Python API for the nth.community "+\
                "secure data collaboration platform.",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    test_suite="nose.collector",
    tests_require=["nose"],
)
