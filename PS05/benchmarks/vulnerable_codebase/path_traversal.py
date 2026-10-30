"""Vulnerable Path Traversal benchmark."""

import os


def read_uploaded_report(filename: str):
    # Parameter 'filename' received from untrusted caller
    # Dangerous Sink: open() without path canonicalization or base check
    with open(filename, "r") as f:
        return f.read()


if __name__ == "__main__":
    read_uploaded_report("../../etc/passwd")

