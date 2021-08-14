from setuptools import setup

with open("README.rst", "r") as fh:
    long_description = fh.read()

setup(
    name="nthcommunity",
    version="0.1.0",
    packages=["nthcommunity",],
    install_requires=[
        "requests~=2.26.0",
        "oblivious~=2.3.0",
        "bcl~=1.0.0"
    ],
    license="MIT",
    url="https://github.com/nthparty/nthcommunity",
    author="Andrei Lapets",
    author_email="a@lapets.io",
    description="Python API for the nth.community "+\
                "secure data collaboration platform.",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    test_suite="nose.collector",
    tests_require=["nose"],
)
