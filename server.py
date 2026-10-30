"""Root entrypoint for Render and cloud production hosting.

Proxies to the PS05 Astraea DevSecOps FastAPI application.
"""

import os
import sys

# Add PS05 to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PS05_DIR = os.path.join(BASE_DIR, "PS05")
if PS05_DIR not in sys.path:
    sys.path.insert(0, PS05_DIR)

from PS05.server import app

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=True)

