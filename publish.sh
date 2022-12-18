#!/bin/sh

if [ -e dist ]; then
    rm -rf dist/*
fi

python3 setup.py sdist bdist_wheel

python3 -m twine upload dist/*
