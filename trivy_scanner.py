"""
==========================================================
Trivy Vulnerability Scanner 
==========================================================

Purpose:
This script performs vulnerability scanning using Trivy.
It checks:
 Software vulnerabilities in the project files
 Container vulnerabilities (if Docker is available)

The script automatically downloads the latest version of Trivy
and is designed in a simple way so that non-technical users can use it easily.

References:
https://github.com/aquasecurity/trivy
https://aquasecurity.github.io/trivy/
https://docs.docker.com/get-docker/
==========================================================
"""

import os
import subprocess
import urllib.request
import zipfile
import shutil
import sys
import json

# Fixing encoding issues on Windows
sys.stdout.reconfigure(encoding='utf-8')


# ----------------------------------------
# Checking if Trivy is already installed
# ----------------------------------------
def is_trivy_installed():
    return shutil.which("trivy") is not None


# ----------------------------------------
# Getting latest Trivy download link
# ----------------------------------------
def get_latest_trivy_url():
    try:
        api_url = "https://api.github.com/repos/aquasecurity/trivy/releases/latest"

        # Fetching release details from GitHub
        with urllib.request.urlopen(api_url) as response:
            data = json.loads(response.read().decode())

        # Finding correct Windows 64-bit zip file
        for asset in data["assets"]:
            name = asset["name"].lower()
            if "windows" in name and "64bit" in name and name.endswith(".zip"):
                return asset["browser_download_url"]

    except Exception as e:
        print("[!] Error getting latest version:", e)

    return None


# ----------------------------------------
# Installing Trivy automatically
# ----------------------------------------
def install_trivy():
    try:
        print("[*] Installing Trivy...\n")

        url = get_latest_trivy_url()
        if not url:
            print("[!] Could not find download link")
            return False

        zip_path = "trivy.zip"
        extract_folder = "trivy_local"

        print("[*] Downloading Trivy...")
        urllib.request.urlretrieve(url, zip_path)

        print("[*] Extracting files...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_folder)

        # Adding Trivy to PATH temporarily
        trivy_path = os.path.abspath(extract_folder)
        os.environ["PATH"] += os.pathsep + trivy_path

        print("[✓] Trivy installed successfully\n")
        return True

    except Exception as e:
        print("[!] Installation failed:", e)
        return False


# ----------------------------------------
# Running filesystem scan
# ----------------------------------------
def run_filesystem_scan():
    print("\n[*] Running filesystem scan...\n")

    try:
        result = subprocess.run(
            ["trivy", "fs", "."],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        print(result.stdout)

    except Exception as e:
        print("[!] Scan failed:", e)


# ----------------------------------------
# Running container scan
# ----------------------------------------
def run_container_scan():
    print("\n[*] Checking for Docker...")

    # Checking if Docker exists
    if not shutil.which("docker"):
        print("[!] Docker not found. Skipping container scan.")
        return

    print("[*] Running container scan...\n")

    try:
        result = subprocess.run(
            ["trivy", "image", "nginx:latest"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        print(result.stdout)

    except Exception as e:
        print("[!] Container scan failed:", e)


# ----------------------------------------
# Main execution
# ----------------------------------------
def main():
    print("[*] Starting Trivy scan...\n")

    # Checking and installing Trivy if needed
    if not is_trivy_installed():
        if not install_trivy():
            print("[!] Cannot continue without Trivy.")
            return

    # Running scans
    run_filesystem_scan()
    run_container_scan()

    print("\n[✓] Scan completed\n")


# ----------------------------------------
# Running script directly
# ----------------------------------------
if __name__ == "__main__":
    main()