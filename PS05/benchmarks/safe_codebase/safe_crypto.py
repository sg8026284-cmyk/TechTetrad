"""Safe Cryptography benchmark (SHA-256)."""

import hashlib


def hash_user_password(password: str):
    # Safe: standard cryptographically strong SHA-256 algorithm
    digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return digest


if __name__ == "__main__":
    pass

