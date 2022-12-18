#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import bcrypt

def get_current_timestamp():
    """
    Get current timestamp as milli seconds
    """
    return int(time.time() * 1000)

def generate_password(pwd: str):
    if isinstance(pwd, str):
        pwd = pwd.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd, salt)
    return hashed

def verify_password(pwd: str, password_hash: str):
    if isinstance(pwd, str):
        pwd = pwd.encode('utf-8')
    if isinstance(password_hash, str):
        password_hash = password_hash.encode('utf-8')
    if bcrypt.checkpw(pwd, password_hash):
        return True
    return False
