#!/bin/sh

if [ -e dist ]; then
    rm -rf dist/*
fi

python3 setup.py sdist bdist_wheel

pip3 uninstall -y lycium-rest
pip3 install dist/lycium_rest-*.whl
