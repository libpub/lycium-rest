#!/usr/bin/python
#-*- coding:utf-8 -*-

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="lycium-rest",
    version="0.0.1",
    author="kevinyjn",
    author_email="kevinyjn@gmail.com",
    description="common python programing encapsulation library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/libpub/lycium-rest",
    packages=setuptools.find_packages(exclude=[".tests", ".tests.", "tests.*", "tests"]),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=[
        "pycrypto",
        "sqlalchemy==1.4.25",
        "IPy",
        "requests",
        "tornado",
        "hawthorn",
        "PyJWT",
        "python-i18n[YAML]"
    ]
)
