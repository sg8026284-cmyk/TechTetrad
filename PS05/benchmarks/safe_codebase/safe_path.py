"""Safe Path Traversal benchmark (os.path.basename / canonicalization)."""

import os


def read_uploaded_report(filename: str):
    # Safe: sanitized using os.path.basename to strip directory traversal sequences
    safe_name = os.path.basename(filename)
    safe_path = os.path.join("./uploads", safe_name)
    with open(safe_path, "r") as f:
        return f.read()


if __name__ == "__main__":
    pass

