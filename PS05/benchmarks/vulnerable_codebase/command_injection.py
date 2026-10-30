"""Vulnerable Command Injection benchmark."""

import sys
import subprocess


def execute_diagnostics():
    # Source: sys.argv[1] (untrusted external input)
    if len(sys.argv) > 1:
        target_host = sys.argv[1]
    else:
        target_host = "localhost"

    # Propagation: formatted string command
    diag_cmd = f"ping -c 1 {target_host}"

    # Dangerous Sink: subprocess.run with shell=True without sanitization
    result = subprocess.run(diag_cmd, shell=True, capture_output=True, text=True)
    return result.stdout


if __name__ == "__main__":
    execute_diagnostics()

