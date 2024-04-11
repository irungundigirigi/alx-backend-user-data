#!/usr/bin/env python3
"""
Defines functions related to hashing and validating passwords
"""

import bcrypt
from bcrypt import hashpw


def hash_password(password: str) -> bytes:
    """
    Returns a hashed password
    Args:
        password (str): The password to be hashed
    Returns:
        bytes: The hashed password
    """
    b = password.encode()
    hashed = hashpw(b, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Check whether a password matches its hashed version
    Args:
        hashed_password (bytes): The hashed password
        password (str): The plain text password
    Returns:
        bool: True if the password matches the hashed version, False otherwise
    """
    return bcrypt.checkpw(password.encode(), hashed_password)

