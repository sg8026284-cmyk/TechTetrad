#!/usr/bin/env python
"""Render Cloud Deployment Utility for Astraea DevSecOps AI Auditor.

Supports:
1. Automated deployment via Render REST API using RENDER_API_KEY
2. Direct Render Blueprint One-Click Deploy URL generation
"""

import os
import sys
import json
import argparse
import time
import requests

GITHUB_REPO = "https://github.com/sg8026284-cmyk/TechTetrad"
SERVICE_NAME = "astraea-devsecops-backend"
ONE_CLICK_URL = f"https://render.com/deploy?repo={GITHUB_REPO}"


def load_env_token() -> str:
    """Retrieve Render token from environment or .env file."""
    token = os.environ.get("RENDER_API_KEY") or os.environ.get("RENDER_TOKEN")
    if token:
        return token.strip()

    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("RENDER_API_KEY=") or line.startswith("RENDER_TOKEN="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


def deploy_via_api(token: str):
    """Deploy web service to Render using the Render REST API."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    print("[*] Contacting Render REST API (https://api.render.com/v1)...")

    # Step 1: Retrieve Owner/Account ID
    owners_res = requests.get("https://api.render.com/v1/owners", headers=headers, timeout=30)
    if owners_res.status_code != 200:
        print(f"[!] Authentication failed ({owners_res.status_code}): {owners_res.text}")
        sys.exit(1)

    owners_data = owners_res.json()
    if not owners_data:
        print("[!] No owner accounts associated with this Render API key.")
        sys.exit(1)

    owner_id = owners_data[0]["owner"]["id"]
    owner_name = owners_data[0]["owner"].get("name", "Account")
    print(f"[OK] Authenticated as Render Owner: {owner_name} ({owner_id})")

    # Step 2: Check for existing service
    print(f"[*] Checking for existing service named '{SERVICE_NAME}'...")
    services_res = requests.get("https://api.render.com/v1/services?limit=50", headers=headers, timeout=30)
    existing_service = None

    if services_res.status_code == 200:
        for item in services_res.json():
            svc = item.get("service", {})
            if svc.get("name") == SERVICE_NAME:
                existing_service = svc
                break

    if existing_service:
        service_id = existing_service["id"]
        service_url = existing_service.get("serviceDetails", {}).get("url") or f"https://{SERVICE_NAME}.onrender.com"
        print(f"[OK] Found existing service: {service_id}")
        print(f"[*] Triggering new deployment on {service_url}...")
        deploy_res = requests.post(f"https://api.render.com/v1/services/{service_id}/deploys", headers=headers, json={"clearCache": "do_cache"}, timeout=30)
        if deploy_res.status_code in (200, 201):
            deploy_data = deploy_res.json()
            print(f"[OK] Deployment successfully triggered!")
            print(f"     Deployment ID: {deploy_data.get('id')}")
            print(f"     Live Service URL: {service_url}")
            return service_url
        else:
            print(f"[!] Failed to trigger deployment: {deploy_res.text}")
            sys.exit(1)

    # Step 3: Create new Web Service
    print(f"[*] Creating new Render Python Web Service for {GITHUB_REPO}...")
    payload = {
        "type": "web_service",
        "name": SERVICE_NAME,
        "ownerId": owner_id,
        "repo": GITHUB_REPO,
        "branch": "main",
        "autoDeploy": "yes",
        "serviceDetails": {
            "env": "python",
            "plan": "free",
            "region": "oregon",
            "buildCommand": "pip install -r requirements.txt",
            "startCommand": "uvicorn server:app --host 0.0.0.0 --port $PORT",
            "healthCheckPath": "/health",
            "envVars": [
                {"key": "PYTHON_VERSION", "value": "3.11.0"},
                {"key": "ALLOW_NETWORK", "value": "true"}
            ]
        }
    }

    create_res = requests.post("https://api.render.com/v1/services", headers=headers, json=payload, timeout=30)
    if create_res.status_code in (200, 201):
        svc_data = create_res.json().get("service", {})
        service_url = svc_data.get("serviceDetails", {}).get("url") or f"https://{SERVICE_NAME}.onrender.com"
        print(f"[OK] Render Web Service created successfully!")
        print(f"     Service ID: {svc_data.get('id')}")
        print(f"     Service URL: {service_url}")
        print(f"     Dashboard: https://dashboard.render.com/web/{svc_data.get('id')}")
        return service_url
    else:
        print(f"[!] Service creation failed ({create_res.status_code}): {create_res.text}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Deploy Astraea DevSecOps Backend to Render")
    parser.add_argument("--token", "-t", default="", help="Render API Key (rnd_...)")
    args = parser.parse_args()

    token = args.token or load_env_token()

    print("=====================================================================")
    print("      ASTRAEA DEVSECOPS AUDITOR - RENDER DEPLOYMENT ORCHESTRATOR     ")
    print("=====================================================================")
    print(f"GitHub Repository: {GITHUB_REPO}")
    print(f"Service Name:      {SERVICE_NAME}")
    print(f"Blueprint Spec:    render.yaml")
    print("---------------------------------------------------------------------")

    if token:
        masked = token[:6] + "..." + token[-4:] if len(token) > 10 else "[PROVIDED]"
        print(f"Render API Token:  {masked}")
        deploy_via_api(token)
    else:
        print("[i] No RENDER_API_KEY detected in environment or .env file.")
        print("")
        print("You can deploy to Render in two ways:")
        print("")
        print("OPTION 1: One-Click Render Blueprint (Recommended, No API key needed)")
        print("  Click the direct Render deployment URL below:")
        print(f"  --> {ONE_CLICK_URL}")
        print("")
        print("  Render will automatically parse `render.yaml`, configure the Python 3.11")
        print("  environment, install requirements, and launch uvicorn with health checks.")
        print("")
        print("OPTION 2: Automated CLI API Deployment")
        print("  1. Generate an API Key at: https://dashboard.render.com/u/settings#api-keys")
        print("  2. Run:")
        print("     python deploy_to_render.py --token <your_render_api_key>")
        print("     OR add RENDER_API_KEY=<key> to .env and re-run.")
        print("=====================================================================")


if __name__ == "__main__":
    main()
