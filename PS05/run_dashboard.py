#!/usr/bin/env python
"""Local Web Server to serve the Astraea DevSecOps AI Auditor Dashboard."""

import http.server
import socketserver
import os
import webbrowser
import sys

PORT = 8080
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")


class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)


def start_server():
    print(f"Starting Astraea DevSecOps Dashboard Server on http://localhost:{PORT}")
    print(f"Serving directory: {WEB_DIR}")
    
    with socketserver.TCPServer(("", PORT), CustomHandler) as httpd:
        print("[OK] Server listening on http://localhost:8080. Press Ctrl+C to terminate.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")


if __name__ == "__main__":
    start_server()

