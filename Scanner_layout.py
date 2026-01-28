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
<<<<<<< Updated upstream
=======
import shutil
import time
import json
from datetime import datetime

>>>>>>> Stashed changes

def main():
    """
    Main controller function.
    - Displays welcome message
    - Ensures administrator privileges
    - Performs system checks and setup
    - Handles authentication
    - Executes vulnerability scan
    - Uploads results to server
    - Cleans up and exits
    """
    display_welcome()

    if not is_admin():
        request_admin_privileges()
        if not is_admin():
            display_admin_required()
            exit_program()

<<<<<<< Updated upstream
=======
    # 2) Now we're admin — show UI
    display_welcome()
>>>>>>> Stashed changes
    display_preparing_system()

    # 3) Preflight checks + auto-install
    if not system_preflight_check():
        display_setup_failed()
<<<<<<< Updated upstream
        exit_program()

    if not authentication_menu():
        exit_program()
=======
    exit_program()
>>>>>>> Stashed changes

    # 4) Run vulnerability scan
    scan_results = run_vulnerability_scan()
    if scan_results is None:
        display_scan_failed()
    exit_program()

<<<<<<< Updated upstream
    if not upload_results(scan_results):
        display_upload_failed()
        exit_program()
=======
    # 5) Generate local report
    if not generate_report(scan_results):
        print("[!] Failed to generate report.")
    exit_program()
>>>>>>> Stashed changes

    # 6) Finish
    display_scan_complete()
    cleanup()
    exit_program()



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
    pass


def display_setup_failed():
    """
    Display a generic failure message if system setup cannot be completed.
    Should not expose technical error details.
    """
    pass


def display_scan_failed():
    """
    Display message when vulnerability scan execution fails.
    """
    pass


def display_upload_failed():
    """
    Display message when scan results fail to upload to the server.
    """
    pass


def display_scan_complete():
    """
    Display final success message and instruct user to check web dashboard.
    """
    pass


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
        params = " ".join([f'"{arg}"' for arg in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            params,
            None,
            1
        )
    except Exception:
        pass

    # Exit current (non-admin) process
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
        print("Internet connection is required to continue.")
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

    # Fallback: check default install path
    default_nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
    return os.path.exists(default_nmap_path)


def install_nmap():
    """
    Download and silently install Nmap if missing.
    Verify installation after completion.
    """
    try:
        print("Setting up scanner...")

        nmap_url = "https://nmap.org/dist/nmap-7.94-setup.exe"
        installer_path = os.path.join(tempfile.gettempdir(), "nmap_installer.exe")

        urllib.request.urlretrieve(nmap_url, installer_path)

        subprocess.run(
            [installer_path, "/S"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        return check_nmap()

    except Exception:
        return False


# ==========================================
# AUTHENTICATION & TOKEN MANAGEMENT
# ==========================================

def authentication_menu():
    """
    Display authentication menu:
    - Login (existing user)
    - Register (new user)
    - Exit
    Returns True on successful authentication, False otherwise.
    """
    pass


def register_user():
    """
    Collect registration details from user.
    Send data securely to server.
    Receive client ID and authentication token.
    """
    pass


def login_user():
    """
    Prompt user for client ID and password.
    Send credentials to server for validation.
    Receive authentication token if successful.
    """
    pass


def save_auth_token(token):
    """
    Save authentication token locally in encrypted or protected format.
    Token is short-lived and not a password.
    """
    pass


def load_auth_token():
    """
    Load stored authentication token if available.
    Used to avoid repeated logins.
    """
    pass


def invalidate_token():
    """
    Remove stored authentication token when expired or invalid.
    """
    pass


# ==========================================
# VULNERABILITY SCANNING
# ==========================================

def run_vulnerability_scan():
    """
    Main scanning controller.
    - Collect system information
    - Run port scans
    - Execute vulnerability scripts
    - Process results into structured format
    Returns scan data or None on failure.
    """
    try:
        print("[*] Starting vulnerability scan...\n")

        print("[*] Collecting system information...")
        os_info = collect_os_information()
        if not os_info:
            return None

        print("[*] Collecting Windows security checks...")
        win_sec = collect_windows_security()
        if win_sec is None:
            return None

        print("[*] Running Nmap port scan (this may take a minute)...")
        port_scan = run_port_scan()
        if port_scan is None:
            return None

        print("[*] Running Nmap vulnerability scripts (this may take longer)...")
        vuln_scan = run_vulnerability_scripts()
        if vuln_scan is None:
            return None

        print("[*] Processing scan results...\n")
        scan_data = process_scan_results(os_info, win_sec, port_scan, vuln_scan)

        if not scan_data:
            return None

        print("[✓] Scan finished.\n")
        return scan_data

    except Exception as e:
        print(f"[!] Scan error: {e}")
        return None


def collect_os_information():
<<<<<<< Updated upstream
=======
    """
    Collect basic OS + system identity information (Windows).
    Returns a dict.
    """
    try:
        hostname = platform.node()
        os_name = platform.system()
        os_release = platform.release()
        os_version = platform.version()

        # Try to get nicer Windows details via PowerShell
        ps_cmd = (
            "Get-CimInstance Win32_OperatingSystem | "
            "Select-Object Caption, Version, BuildNumber, OSArchitecture | "
            "ConvertTo-Json -Compress"
        )

        details = {}
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True
            )
            if result.returncode == 0 and result.stdout.strip():
                import json
                details = json.loads(result.stdout.strip())
            else:
                details = {"raw": (result.stderr or "").strip()}
        except Exception:
            details = {"raw": "PowerShell OS query failed"}

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
>>>>>>> Stashed changes
    """
    Use PowerShell to collect OS version, hostname, and system info.
    """
    def _ps(cmd: str) -> str:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True,
            text=True
        )
        return (r.stdout or "").strip()

    def _safe_json(text_value: str):
        try:
            import json
            return json.loads(text_value) if text_value else {}
        except Exception:
            return {"raw": text_value}

    try:
        # Firewall (all profiles)
        firewall_out = _ps(
            "Get-NetFirewallProfile | Select Name, Enabled | ConvertTo-Json -Compress"
        )

        # Defender (may not exist on some editions)
        defender_out = _ps(
            "Try { Get-MpComputerStatus | "
            "Select AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled | "
            "ConvertTo-Json -Compress } Catch { '{}' }"
        )

        # SMBv1 status
        smbv1_out = _ps(
            "Try { Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | "
            "Select State | ConvertTo-Json -Compress } Catch { '{}' }"
        )

        # RDP enabled? (fDenyTSConnections = 0 means enabled)
        rdp_val = _ps(
            "(Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
            "-Name 'fDenyTSConnections').fDenyTSConnections"
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


def run_port_scan():
    """
<<<<<<< Updated upstream
    Run Nmap port scan against the local system.
    """
    pass
=======
    Run an Nmap port scan against the local system.
    Scans top 100 common ports on localhost.
    Returns a dictionary with scan results or None on failure.
    """
    try:
        target = "127.0.0.1"

        # Locate nmap executable
        nmap_path = shutil.which("nmap")
        if not nmap_path:
            possible_paths = [
                r"C:\Program Files\Nmap\nmap.exe",
                r"C:\Program Files (x86)\Nmap\nmap.exe"
            ]
            for path in possible_paths:
                if os.path.exists(path):
                    nmap_path = path
                    break

        if not nmap_path:
            print("[!] Nmap executable not found.")
            return None

        print("[*] Scanning open ports on local system...")

        # Safe scan arguments
        command = [
            nmap_path,
            "-Pn",
            "-T3",
            "--top-ports", "100",
            target
        ]

        process = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        return {
            "target": target,
            "command": " ".join(command),
            "return_code": process.returncode,
            "stdout": process.stdout,
            "stderr": process.stderr
        }

    except Exception as e:
        print(f"[!] Port scan error: {e}")
        return None

    
>>>>>>> Stashed changes


def run_vulnerability_scripts():
    """
<<<<<<< Updated upstream
    Execute basic Nmap vulnerability detection scripts.
    """
    pass


def process_scan_results():
    """
    Normalize scan output and assign risk levels.
    Convert data into JSON-ready format.
=======
    Execute basic Nmap vulnerability detection scripts (NSE) on the local system.
    Returns a dictionary with scan results or None on failure.
    """
    try:
        target = "127.0.0.1"

        # Locate nmap executable
        nmap_path = shutil.which("nmap")
        if not nmap_path:
            possible_paths = [
                r"C:\Program Files\Nmap\nmap.exe",
                r"C:\Program Files (x86)\Nmap\nmap.exe"
            ]
            for path in possible_paths:
                if os.path.exists(path):
                    nmap_path = path
                    break

        if not nmap_path:
            print("[!] Nmap executable not found.")
            return None

        print("[*] Running vulnerability scripts (this may take a few minutes)...")

        command = [
            nmap_path,
            "-sV",              # service/version detection
            "-Pn",              # no ping
            "--script", "vuln", # NSE vulnerability category scripts
            target
        ]

        process = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        return {
            "target": target,
            "command": " ".join(command),
            "return_code": process.returncode,
            "stdout": process.stdout,
            "stderr": process.stderr
        }

    except Exception as e:
        print(f"[!] Vulnerability script scan error: {e}")
        return None



# -------- DATA PROCESSING --------

def process_scan_results(os_info, win_sec, port_scan, vuln_scan):
    """
    Normalize Windows + Nmap data
    Assign severity (High / Medium / Low)
    Returns a structured dict for reporting.
>>>>>>> Stashed changes
    """
    findings = []

    # -------------------------
    # Windows Security Findings
    # -------------------------

    # Firewall profiles
    fw = win_sec.get("firewall_profiles", [])
    profiles = fw if isinstance(fw, list) else ([fw] if isinstance(fw, dict) else [])
    for p in profiles:
        if isinstance(p, dict) and p.get("Enabled") is False:
            findings.append({
                "severity": "High",
                "title": f"Firewall profile disabled: {p.get('Name', 'Unknown')}",
                "recommendation": "Enable Windows Firewall for all profiles (Domain/Private/Public).",
                "evidence": str(p)
            })

    # Defender status
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
                "recommendation": "Enable real-time protection to reduce malware risk.",
                "evidence": str(d)
            })

    # SMBv1
    smb = win_sec.get("smbv1", {})
    smb_state = smb.get("State") if isinstance(smb, dict) else None
    if smb_state and str(smb_state).lower() == "enabled":
        findings.append({
            "severity": "High",
            "title": "SMBv1 protocol is enabled",
            "recommendation": "Disable SMBv1 (legacy) and use SMBv2/SMBv3.",
            "evidence": str(smb)
        })

    # RDP
    if win_sec.get("rdp_enabled") is True:
        findings.append({
            "severity": "Medium",
            "title": "Remote Desktop (RDP) is enabled",
            "recommendation": "If needed, restrict with VPN/MFA and allowlisted IPs. Otherwise disable.",
            "evidence": "Registry indicates fDenyTSConnections=0"
        })

    # -------------------------
    # Nmap Findings (simple)
    # -------------------------
    port_out = (port_scan.get("stdout") or "")
    vuln_out = (vuln_scan.get("stdout") or "")

    # Open ports summary
    if port_scan.get("return_code") == 0 and "open" in port_out.lower():
        findings.append({
            "severity": "Low",
            "title": "Open ports detected on local system",
            "recommendation": "Review open services and disable anything not required.",
            "evidence": "See Nmap Port Scan output in report."
        })

    # Vulnerability hints (CVE / VULNERABLE keyword)
    if vuln_scan.get("return_code") == 0:
        if ("cve" in vuln_out.lower()) or ("vulnerab" in vuln_out.lower()):
            findings.append({
                "severity": "Medium",
                "title": "Potential vulnerability indicators found by Nmap scripts",
                "recommendation": "Validate results, patch affected services, and re-scan.",
                "evidence": "See Nmap Vulnerability Script output in report."
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
# SERVER COMMUNICATION
# ==========================================

def upload_results(scan_data):
    """
<<<<<<< Updated upstream
    Upload scan results to the web server using HTTPS.
    Uses authentication token for authorization.
    Returns True on success, False otherwise.
    """
    pass


def send_https_request():
    """
    Generic helper for sending authenticated HTTPS requests to server.
=======
    Generate HTML report locally.
    Includes:
    - Executive summary
    - Risk levels
    - Findings + recommendations
    - Raw technical outputs
    Returns True on success, False on failure.
>>>>>>> Stashed changes
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
    pre {{ background:#f6f6f6; padding:12px; overflow:auto; }}
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
            html += f"<tr><td><span class='badge {sev}'>{sev}</span></td><td>{f.get('title','')}</td><td>{f.get('recommendation','')}</td><td><pre>{f.get('evidence','')}</pre></td></tr>\n"

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
        return True

    except Exception as e:
        print(f"[!] Report generation failed: {e}")
        return False


# ==========================================
# UTILITIES
# ==========================================

def cleanup():
    """
    Clean up temporary files and sensitive data before exiting.
    (Safe: removes installers if they exist.)
    """
    try:
        temp_dir = tempfile.gettempdir()
        files_to_remove = [
            os.path.join(temp_dir, "python_installer.exe"),
            os.path.join(temp_dir, "nmap_installer.exe"),
            os.path.join(temp_dir, "npcap_installer.exe"),
        ]

        for f in files_to_remove:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass

<<<<<<< Updated upstream
def exit_program():
    """
    Safely terminate the program.
    """
    pass


# ==========================================
# SCRIPT ENTRY POINT
# ==========================================

if __name__ == "__main__":
    main()
=======
    except Exception:
        pass
>>>>>>> Stashed changes
