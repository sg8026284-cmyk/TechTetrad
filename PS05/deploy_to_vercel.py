#!/usr/bin/env python
"""Automated deployment script to host the Astraea DevSecOps Dashboard on Vercel via REST API."""

import os
import sys
import hashlib
import requests
import json

# Ensure parent directory is loaded
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(ROOT_DIR, ".env")


def load_token():
    token = os.environ.get("VERCEL_TOKEN")
    if not token and os.path.isfile(ENV_FILE):
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("VERCEL_TOKEN="):
                    token = line.split("=", 1)[1].strip()
                    break
    if not token:
        print("[Error] No VERCEL_TOKEN found in environment or .env file.")
        sys.exit(1)
    return token


def calculate_file_sha_and_size(file_path):
    sha1 = hashlib.sha1()
    size = 0
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha1.update(chunk)
            size += len(chunk)
    return sha1.hexdigest(), size


def upload_file_to_vercel(file_path, rel_path, token):
    sha, size = calculate_file_sha_and_size(file_path)
    with open(file_path, "rb") as f:
        file_data = f.read()

    upload_headers = {
        "Authorization": f"Bearer {token}",
        "x-vercel-digest": sha,
        "Content-Type": "application/octet-stream",
    }

    print(f"Uploading {rel_path} ({size} bytes, SHA-1: {sha[:10]}...)...")
    res = requests.post("https://api.vercel.com/v2/now/files", headers=upload_headers, data=file_data)
    if res.status_code not in (200, 201, 304):
        print(f"Warning/Error on file upload {rel_path}: HTTP {res.status_code} - {res.text}")
    return {"file": rel_path, "sha": sha, "size": size}


def deploy():
    token = load_token()
    print("Verifying Vercel authentication token...")
    user_res = requests.get("https://api.vercel.com/v2/user", headers={"Authorization": f"Bearer {token}"})
    if user_res.status_code != 200:
        print(f"[Error] Failed to authenticate with Vercel API: {user_res.status_code} {user_res.text}")
        sys.exit(1)

    user_info = user_res.json().get("user", {})
    username = user_info.get("username", "user")
    print(f"[OK] Authenticated as Vercel user: {username}")

    web_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
    index_html = os.path.join(web_dir, "index.html")

    if not os.path.isfile(index_html):
        print(f"[Error] {index_html} not found.")
        sys.exit(1)

    # Prepare files
    files_payload = []
    file_info = upload_file_to_vercel(index_html, "index.html", token)
    files_payload.append(file_info)

    # Optional vercel.json
    vercel_json_path = os.path.join(web_dir, "vercel.json")
    with open(vercel_json_path, "w", encoding="utf-8") as f:
        json.dump({"cleanUrls": True}, f)
    
    vj_info = upload_file_to_vercel(vercel_json_path, "vercel.json", token)
    files_payload.append(vj_info)

    # Create Deployment
    print("Creating deployment on Vercel...")
    deployment_url = "https://api.vercel.com/v13/deployments"
    payload = {
        "name": "astraea-devsecops-auditor",
        "files": files_payload,
        "projectSettings": {
            "framework": None
        }
    }

    dep_res = requests.post(
        deployment_url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=payload
    )

    if dep_res.status_code in (200, 201):
        data = dep_res.json()
        dep_id = data.get("id")
        dep_url = f"https://{data.get('url')}"
        alias = data.get("alias", [])
        print("\n=======================================================")
        print("[SUCCESS] Deployment created successfully!")
        print(f"Deployment ID: {dep_id}")
        print(f"Live URL: {dep_url}")
        if alias:
            print(f"Production Aliases: {', '.join(alias)}")
        print("=======================================================\n")
        return dep_url
    else:
        print(f"[Error] Deployment creation failed: HTTP {dep_res.status_code} {dep_res.text}")
        sys.exit(1)


if __name__ == "__main__":
    deploy()
