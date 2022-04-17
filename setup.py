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
        "requests~=2.27",
        "oblivious~=5.0",
        "bcl~=2.1",
        "additive~=0.3"
    ],
    license="MIT",
    url="https://github.com/nthparty/nthcommunity",
    author="Nth Party, Ltd.",
    author_email="team@nthparty.com",
    description="Python API for the nth.community "+\
                "secure data collaboration platform.",
    long_description=long_description,
    long_description_content_type="text/x-rst",
)
