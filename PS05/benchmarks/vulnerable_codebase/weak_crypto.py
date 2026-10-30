"""Vulnerable Weak Cryptography benchmark."""

import hashlib


def hash_user_password(password: str):
    # Dangerous Sink: MD5 algorithm for password hashing
    digest = hashlib.md5(password.encode("utf-8")).hexdigest()
    return digest


if __name__ == "__main__":
    hash_user_password("secret123")

