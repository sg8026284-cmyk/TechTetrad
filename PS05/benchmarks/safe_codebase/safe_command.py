"""Safe Command Execution benchmark (Parameterized list, shell=False)."""

import sys
import subprocess


def execute_diagnostics():
    if len(sys.argv) > 1:
        target_host = sys.argv[1]
    else:
        target_host = "localhost"

    # Safe: Passing command arguments as a list with shell=False
    result = subprocess.run(["ping", "-c", "1", target_host], shell=False, capture_output=True, text=True)
    return result.stdout


if __name__ == "__main__":
    execute_diagnostics()

