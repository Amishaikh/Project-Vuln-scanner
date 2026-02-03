# ==========================================
# Client Vulnerability Scanner (Base Script)
# ==========================================
# This script is designed for non-technical users.
# All credentials are stored and validated on the web server.
# The client only handles tokens and scan execution.
# ==========================================

import sys
import os
import ctypes
import platform
import subprocess
import socket
import urllib.request
import tempfile
import shutil
import time
import json
from datetime import datetime
import webbrowser


def main():
    # 1) Ensure we're running inside an elevated console first
    if not is_admin():
        request_admin_privileges()
        return

    # 2) Now we're admin — show UI
    display_welcome()
    display_preparing_system()

    # 3) Preflight checks + auto-install
    if not system_preflight_check():
        display_setup_failed()
        exit_program(1)

    # 4) Run vulnerability scan
    scan_results = run_vulnerability_scan()
    if scan_results is None:
        display_scan_failed()
        exit_program(1)

    # 5) Generate local report
    if not generate_report(scan_results):
        print("[!] Failed to generate report.")
        exit_program(1)

    # 6) Finish
    display_scan_complete()
    cleanup()
    exit_program(0)


# ==========================================
# DISPLAY / USER INTERFACE FUNCTIONS
# ==========================================

def display_welcome():
    """
    Display a simple, friendly welcome message.
    Should not include any technical details.
    """
    print("\n" + "="*60)
    print(r"""
>>====================================================================================================<<
|| ██████╗ ██████╗ ███████╗███╗   ██╗    ███████╗ ██████╗ ██╗   ██╗██████╗  ██████╗███████╗           ||
||██╔═══██╗██╔══██╗██╔════╝████╗  ██║    ██╔════╝██╔═══██╗██║   ██║██╔══██╗██╔════╝██╔════╝           ||
||██║   ██║██████╔╝█████╗  ██╔██╗ ██║    ███████╗██║   ██║██║   ██║██████╔╝██║     █████╗             ||
||██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║    ╚════██║██║   ██║██║   ██║██╔══██╗██║     ██╔══╝             ||
||╚██████╔╝██║     ███████╗██║ ╚████║    ███████║╚██████╔╝╚██████╔╝██║  ██║╚██████╗███████╗           ||
|| ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚══════╝           ||
||                                                                                                    ||
||██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗██████╗  █████╗ ██████╗ ██╗██╗     ██╗████████╗██╗   ██╗||
||██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔══██╗██╔══██╗██╔══██╗██║██║     ██║╚══██╔══╝╚██╗ ██╔╝||
||██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██████╔╝███████║██████╔╝██║██║     ██║   ██║    ╚████╔╝ ||
||╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██╔══██╗██╔══██║██╔══██╗██║██║     ██║   ██║     ╚██╔╝  ||
|| ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████╗██║  ██║██║  ██║██████╔╝██║███████╗██║   ██║      ██║   ||
||  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚══════╝╚═╝   ╚═╝      ╚═╝   ||
||                                                                                                    ||
||███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗                                         ||
||██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗                                        ||
||███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝                                        ||
||╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗                                        ||
||███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║                                        ||
||╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝                                        ||
>>====================================================================================================<<   
                                                                                                                                                                                                   
    """)
    print(" " * 20 + "Welcome! This tool will guide you through a full vulnerability scan.".center(40, " "))
    print("="*60 + "\n")

def display_preparing_system():
    """
    Inform the user that system preparation is in progress.
    This message hides technical dependency checks.
    """
    print("Preparing your system for the security scan...")
    print("This may take a few moments.")
    print()
    

def display_admin_required():
    """
    Display message indicating administrator permission is required.
    Used when user denies UAC elevation.
    """
    print("Administrator permission is required to run this scan.")
    print("Please run again and click 'Yes' on the permission prompt.")
    print()


def display_setup_failed():
    """
    Display a generic failure message if system setup cannot be completed.
    Should not expose technical error details.
    """
    print("System setup could not be completed.")
    print("Please contact your administrator.")
    print()


def display_scan_failed():
    print("[!] Scan failed.")
    print("Please try again or contact your administrator.")
    print()


def display_upload_failed():
    print("[!] Upload failed.")
    print("Please check your internet connection and try again.")
    print()


def display_scan_complete():
    print("[✓] Scan completed successfully!")
    print("Your report is ready in the web dashboard.")
    print()


# ==========================================
# PRIVILEGE HANDLING
# ==========================================

def is_admin():
    """
    Check whether the script is running with administrator privileges.
    Returns True if admin, False otherwise.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1
    except Exception:
        return False


def request_admin_privileges():
    """
    Relaunch the script with administrator privileges using UAC prompt.
    No logic should continue after this function call.
    """
    try:
        script_path = os.path.abspath(sys.argv[0])
        python_exe = os.path.abspath(sys.executable)
        cwd = os.getcwd()

        pwsh = shutil.which("pwsh") or shutil.which("powershell")
        if not pwsh:
            sys.exit(1)

        # Run the script in the elevated shell (keep window open)
        ps_inner = f"& '{python_exe}' '{script_path}'"

        ps_command = (
            f"Start-Process -Verb RunAs -FilePath '{pwsh}' "
            f"-WorkingDirectory '{cwd}' "
            f"-ArgumentList @('-NoExit','-NoProfile','-Command',\"{ps_inner}\")"
        )

        subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_command],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except Exception:
        pass

    # Exit current non-admin instance
    sys.exit(0)


# ==========================================
# SYSTEM CHECKS & AUTO-  INSTALLATION
# ==========================================

def system_preflight_check():
    """
    Perform all required system checks.
    - OS validation
    - PowerShell availability
    - Internet connectivity
    - Python presence
    - Nmap presence
    Returns True if system is ready, False otherwise.
    """
    # Check OS
    if not check_windows_os():
        return False

    # Check PowerShell
    if not check_powershell():
        return False

    # Check Internet
    if not check_internet():
        print("Internet connection is required to continue.")
        return False

    # Python check + auto-install
    if not check_python():
        if not install_python():
            print("Failed to set up Python.")
            return False

    # Nmap check + auto-install
    if not check_nmap():
        if not install_nmap():
            print("Failed to set up scanning tools.")
            return False

    return True


def check_windows_os():
    """
    Verify that the operating system is Windows.
    """
    try:
        return platform.system().lower() == "windows"
    except Exception:
        return False


def check_powershell():
    """
    Verify PowerShell is available and executable.
    """
    try:
        result = subprocess.run(
            ["powershell", "-Command", "Get-Host"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False


def check_internet():
    """
    Check internet connectivity by reaching the web server.
    """
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=5)
        print("Internet check: OK")
        return True
    except Exception:
        #print("Internet connection is required to continue.")
        return False


def check_python():
    """
    Check if Python is installed and accessible.
    """
    try:
        result = subprocess.run(
            ["python", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False    

def install_python():
    """
    Download and silently install Python if missing.
    Verify installation after completion.
    """
    try:
        print("Setting up required components...")

        python_url = "https://www.python.org/ftp/python/3.12.1/python-3.12.1-amd64.exe"
        installer_path = os.path.join(tempfile.gettempdir(), "python_installer.exe")

        urllib.request.urlretrieve(python_url, installer_path)

        subprocess.run(
            [
                installer_path,
                "/quiet",
                "InstallAllUsers=1",
                "PrependPath=1"
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        return check_python()

    except Exception:
        return False


def check_nmap():
    """
    Check if Nmap is installed and accessible.
    """
    # 1) Try PATH first
    try:
        result = subprocess.run(
            ["nmap", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if result.returncode == 0:
            return True
    except Exception:
        pass

    # 2) Fallback: common install locations (64-bit + 32-bit)
    possible_paths = [
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
    ]
    return any(os.path.exists(p) for p in possible_paths)

def _get_nmap_path():
    """
    Return a working Nmap executable path.
    """
    n = shutil.which("nmap")
    if n:
        return n
    for p in [r"C:\Program Files\Nmap\nmap.exe", r"C:\Program Files (x86)\Nmap\nmap.exe"]:
        if os.path.exists(p):
            return p
    return None

def install_nmap():
    """
    Auto-install Npcap then Nmap (best possible automation on Windows).
    Note: Windows may still show a driver permission prompt for Npcap.
    Returns True if Nmap is installed successfully, otherwise False.
    """
    try:
        print("\n[*] Setting up scanning tools...")

    
        # -----------------------
        # 2) Install Nmap
        # -----------------------
        print("[*] Installing Nmap...\n")

        nmap_url = "https://nmap.org/dist/nmap-7.94-setup.exe"
        nmap_installer = os.path.join(tempfile.gettempdir(), "nmap_installer.exe")

        urllib.request.urlretrieve(nmap_url, nmap_installer)

        nmap_proc = subprocess.run(
            [nmap_installer, "/S"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Give Windows a moment to update PATH/registry
        time.sleep(3)

        # -----------------------
        # 3) Verify Nmap installed
        # -----------------------
        if check_nmap():
            print("[✓] Nmap setup complete.\n")
            return True

        # If PATH not updated, still might exist in Program Files
        print("[!] Nmap installation may have completed, but not detected in PATH.")
        print("    Try closing/reopening PowerShell and run: nmap --version\n")
        return check_nmap()

    except Exception as e:
        print(f"[!] Auto-install failed: {e}")
        return False
    

# ==========================================
# VULNERABILITY SCANNING
# ==========================================

def _run_powershell(cmd: str) -> str:
    r = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
        capture_output=True,
        text=True
    )
    return (r.stdout or r.stderr or "").strip()

def run_vulnerability_scan():
    """
    Orchestrates the entire scan:
    - Windows security checks
    - Network scanning
    - Data aggregation
    """
    try:
        print("[*] Starting vulnerability scan...\n")

        print("[*] Collecting OS information...")
        os_info = collect_os_information()
        if not os_info:
            return None

        print("[*] Collecting Windows security posture...")
        win_sec = collect_windows_security()

        print("[*] Running Nmap port scan...")
        port_scan = run_port_scan()
        if port_scan is None:
            return None

        print("[*] Running Nmap vulnerability scripts...")
        vuln_scan = run_vulnerability_scripts()
        if vuln_scan is None:
            return None

        print("[*] Processing results...\n")
        return process_scan_results(os_info, win_sec, port_scan, vuln_scan)

    except Exception as e:
        print(f"[!] Scan error: {e}")
        return None


# -------- WINDOWS SECURITY CHECKS --------

def collect_os_information():
    try:
        hostname = platform.node()
        os_name = platform.system()
        os_release = platform.release()
        os_version = platform.version()

        ps_cmd = (
            "Get-CimInstance Win32_OperatingSystem | "
            "Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate | "
            "ConvertTo-Json -Compress"
        )

        details = {}
        raw = _run_powershell(ps_cmd)
        try:
            details = json.loads(raw) if raw else {}
        except Exception:
            details = {"raw": raw}

        return {
            "hostname": hostname,
            "platform": os_name,
            "release": os_release,
            "version": os_version,
            "details": details
        }
    except Exception:
        return {}

def collect_windows_security():
    """
    Collect:
    - Firewall status
    - Defender status
    - SMBv1
    - RDP
    - Users
    - Password policy
    - Installed patches
    """
    def _safe_json(txt: str):
        try:
            return json.loads(txt) if txt else {}
        except Exception:
            return {"raw": txt}

    try:
        firewall_out = _run_powershell(
            "Get-NetFirewallProfile | Select Name, Enabled | ConvertTo-Json -Compress"
        )

        defender_out = _run_powershell(
            "Try { Get-MpComputerStatus | "
            "Select AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled | "
            "ConvertTo-Json -Compress } Catch { '{}' }"
        )

        smbv1_out = _run_powershell(
            "Try { Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | "
            "Select State | ConvertTo-Json -Compress } Catch { '{}' }"
        )

        rdp_val = _run_powershell(
            r"(Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections').fDenyTSConnections"
        )
        rdp_enabled = str(rdp_val).strip() == "0"

        return {
            "firewall_profiles": _safe_json(firewall_out),
            "defender_status": _safe_json(defender_out),
            "smbv1": _safe_json(smbv1_out),
            "rdp_enabled": rdp_enabled
        }
    except Exception:
        return {}


# -------- NETWORK SCANNING --------

def run_port_scan():
    """Run Nmap port scan on local system"""
    try:
        target = "127.0.0.1"
        nmap = _get_nmap_path()
        if not nmap:
            print("[!] Nmap executable not found.")
            return None

        cmd = [nmap, "-Pn", "-T3", "--top-ports", "100", target]
        proc = subprocess.run(cmd, capture_output=True, text=True)

        return {
            "target": target,
            "command": " ".join(cmd),
            "return_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr
        }
    except Exception:
        return None

def run_vulnerability_scripts():
    """Run Nmap vulnerability scripts"""
    try:
        target = "127.0.0.1"
        nmap = _get_nmap_path()
        if not nmap:
            print("[!] Nmap executable not found.")
            return None

        cmd = [nmap, "-sV", "-Pn", "--script", "vuln", target]
        proc = subprocess.run(cmd, capture_output=True, text=True)

        return {
            "target": target,
            "command": " ".join(cmd),
            "return_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr
        }
    except Exception:
        return None


# -------- DATA PROCESSING --------

def process_scan_results(os_info, win_sec, port_scan, vuln_scan):
    """
    Normalize Windows + Nmap data
    Assign severity (High / Medium / Low)
    """
    findings = []

    # Firewall profiles disabled => High
    fw = win_sec.get("firewall_profiles", [])
    profiles = fw if isinstance(fw, list) else ([fw] if isinstance(fw, dict) else [])
    for p in profiles:
        if isinstance(p, dict) and p.get("Enabled") is False:
            findings.append({
                "severity": "High",
                "title": f"Firewall profile disabled: {p.get('Name', 'Unknown')}",
                "recommendation": "Enable Windows Firewall for Domain/Private/Public profiles.",
                "evidence": str(p)
            })

    # Defender checks
    d = win_sec.get("defender_status", {})
    if isinstance(d, dict) and d:
        if d.get("AntivirusEnabled") is False:
            findings.append({
                "severity": "High",
                "title": "Microsoft Defender Antivirus is disabled",
                "recommendation": "Enable antivirus protection and keep definitions updated.",
                "evidence": str(d)
            })
        if d.get("RealTimeProtectionEnabled") is False:
            findings.append({
                "severity": "Medium",
                "title": "Real-time protection is disabled",
                "recommendation": "Enable real-time protection.",
                "evidence": str(d)
            })

    # SMBv1 enabled => High
    smb = win_sec.get("smbv1", {})
    smb_state = smb.get("State") if isinstance(smb, dict) else None
    if smb_state and str(smb_state).lower() == "enabled":
        findings.append({
            "severity": "High",
            "title": "SMBv1 protocol is enabled",
            "recommendation": "Disable SMBv1 and use SMBv2/SMBv3.",
            "evidence": str(smb)
        })

    # RDP enabled => Medium
    if win_sec.get("rdp_enabled") is True:
        findings.append({
            "severity": "Medium",
            "title": "Remote Desktop (RDP) is enabled",
            "recommendation": "If required, restrict access (VPN/MFA). Otherwise disable.",
            "evidence": "Registry indicates fDenyTSConnections=0"
        })

    # Nmap open ports => Low summary
    port_out = (port_scan.get("stdout") or "") if port_scan else ""
    if port_scan and port_scan.get("return_code") == 0 and "open" in port_out.lower():
        findings.append({
            "severity": "Low",
            "title": "Open ports detected on local system",
            "recommendation": "Review open services and disable anything not required.",
            "evidence": "See Nmap Port Scan output section in report."
        })

    # Nmap NSE hints => Medium summary
    vuln_out = (vuln_scan.get("stdout") or "") if vuln_scan else ""
    if vuln_scan and vuln_scan.get("return_code") == 0:
        if ("cve" in vuln_out.lower()) or ("vulnerab" in vuln_out.lower()):
            findings.append({
                "severity": "Medium",
                "title": "Potential vulnerability indicators found by Nmap scripts",
                "recommendation": "Validate, patch affected services, and re-scan.",
                "evidence": "See Nmap Vulnerability Scripts output section in report."
            })

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "os_info": os_info,
        "windows_security": win_sec,
        "nmap_port_scan": port_scan,
        "nmap_vuln_scan": vuln_scan,
        "findings": findings
    }


# ==========================================
# REPORTING
# ==========================================

def generate_report(scan_data):
    """
    Generate:
    - Executive summary
    - Technical findings
    - Risk levels
    - Recommendations
    Output: HTML / TXT file
    """
    try:
        reports_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(reports_dir, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(reports_dir, f"scan_report_{ts}.html")

        findings = scan_data.get("findings", [])
        high = sum(1 for f in findings if f.get("severity") == "High")
        med = sum(1 for f in findings if f.get("severity") == "Medium")
        low = sum(1 for f in findings if f.get("severity") == "Low")

        hostname = scan_data.get("os_info", {}).get("hostname", "Unknown")
        generated_at = scan_data.get("generated_at", "")

        win_sec_pretty = json.dumps(scan_data.get("windows_security", {}), indent=2)
        port_scan_text = (scan_data.get("nmap_port_scan", {}).get("stdout") or "") + "\n" + (scan_data.get("nmap_port_scan", {}).get("stderr") or "")
        vuln_scan_text = (scan_data.get("nmap_vuln_scan", {}).get("stdout") or "") + "\n" + (scan_data.get("nmap_vuln_scan", {}).get("stderr") or "")

        html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Vulnerability Scan Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; }}
    h1 {{ margin-bottom: 6px; }}
    .meta {{ color: #444; margin-bottom: 18px; }}
    .badge {{ display:inline-block; padding:3px 8px; border-radius:10px; font-size:12px; }}
    .High {{ background:#ffd6d6; }}
    .Medium {{ background:#fff1c7; }}
    .Low {{ background:#dff5d8; }}
    pre {{ background:#f6f6f6; padding:12px; overflow:auto; white-space: pre-wrap; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
    th {{ background: #f0f0f0; }}
  </style>
</head>
<body>
  <h1>Vulnerability Scan Report</h1>
  <div class="meta">
    Generated: {generated_at}<br>
    Host: {hostname}
  </div>

  <h2>Executive Summary</h2>
  <p>This report summarizes basic Windows security checks and local Nmap scan results. It highlights configuration risks and provides recommendations.</p>

  <h3>Risk Overview</h3>
  <ul>
    <li><span class="badge High">High</span> {high}</li>
    <li><span class="badge Medium">Medium</span> {med}</li>
    <li><span class="badge Low">Low</span> {low}</li>
  </ul>

  <h2>Findings</h2>
  <table>
    <tr><th>Severity</th><th>Title</th><th>Recommendation</th><th>Evidence</th></tr>
"""
        for f in findings:
            sev = f.get("severity", "Low")
            title = (f.get("title") or "")
            rec = (f.get("recommendation") or "")
            ev = (f.get("evidence") or "")
            html += f"<tr><td><span class='badge {sev}'>{sev}</span></td><td>{title}</td><td>{rec}</td><td><pre>{ev}</pre></td></tr>\n"

        html += f"""
  </table>

  <h2>Technical Details</h2>

  <h3>Windows Security Checks</h3>
  <pre>{win_sec_pretty}</pre>

  <h3>Nmap Port Scan Output</h3>
  <pre>{port_scan_text}</pre>

  <h3>Nmap Vulnerability Script Output</h3>
  <pre>{vuln_scan_text}</pre>

</body>
</html>
"""

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"[✓] Report saved locally: {report_path}")

        # Optional: open report automatically
        try:
            webbrowser.open(report_path)
        except Exception:
            pass

        return True

    except Exception as e:
        print(f"[!] Report generation failed: {e}")
        return False


# ==========================================
# UTILITIES
# ==========================================

def exit_program(code: int = 0):
    sys.exit(code)


def cleanup():
    """
    Clean up temporary installer files if they exist.
    """
    try:
        temp_dir = tempfile.gettempdir()
        for name in ["python_installer.exe", "nmap_installer.exe", "npcap_installer.exe"]:
            p = os.path.join(temp_dir, name)
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass
    except Exception:
        pass


# ==========================================
# SCRIPT ENTRY POINT
# ==========================================

if __name__ == "__main__":
    main()
