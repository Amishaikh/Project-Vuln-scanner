# ==========================================
# Client Vulnerability Scanner (Base Script)
# ==========================================
# This script is designed for non-technical users.
# All credentials are stored and validated on the web server.
# The client only handles tokens and scan execution.
# ==========================================

import os
import re
import platform
import subprocess
import urllib.request
import zipfile
import tempfile
from datetime import datetime
import time
import json
import xml.etree.ElementTree as ET
import html
import webbrowser
from pathlib import Path

def main():

    # Just a sweet welcome meesage
    display_welcome()

    # Check Nmap and if not present would download it auto-install
    if not check_nmap():
        if not install_nmap():
            print("Failed to set up scanning tools.")
            return False
        
    # autorun download to check autorun vulnerability    
    autorun_download()

    # Trivy Installation
    if not is_trivy_installed():
        print("[*] Setting up advanced scanning tools (Trivy)...")
        install_trivy()

    report_data = {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "system_info": {},
        "nmap": [],
        "privilege": [],
        "firewall": [],
        "trivy": [],
        "autorun": []
    }

    # Basic System info check 
    report_data["system_info"] = show_system_info()

    # port check report using nmap
    report_data["nmap"] = port_check()

    # Privilage check for users
    report_data["privilege"] = privilage_check()

    # Firewall configuration reporting 
    report_data["firewall"] = firewall_check()

    # Advanced Trivy scanning
    report_data["trivy"] = trivy_check()

    # autorun check reporting
    report_data["autorun"] = autorun_check()

    # HTML report
    html_reporting(report_data)




def display_welcome():
    """
        Sweet welcome message
    """
    print(r"""
||====================================================================================================||
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
||====================================================================================================||   
                                                                                                                                                                                                   
    """)
    print(" " * 20 + "Welcome! This tool will guide you through a full vulnerability scan.".center(40, " "))
    now = datetime.now()
    time = now.strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n                                   Reporting time: {time}\n")
    print("Preparing your system for the security scan...")
    print("This may take a few moments.")
    print()

def show_system_info():
    print("\n                                   ===== System Information =====\n")

    adapters = []
    result = subprocess.run(
        ["powershell", "-Command",
         "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty Name"],
        capture_output=True,
        text=True
    )

    for adapter in result.stdout.strip().split("\n"):
        if adapter.strip():
            adapters.append(adapter.strip())

    info = {
        "Computer Name": platform.node(),
        "User": os.getlogin(),
        "Operating System": f"{platform.system()} {platform.release()}",
        "Operating System Version": platform.version(),
        "Operating System Architecture": platform.architecture()[0],
        "Processor": platform.processor() if platform.processor() else "N/A",
        "Domain": os.environ.get("USERDOMAIN", "N/A"),
        "Logon Server": os.environ.get("LOGONSERVER", "N/A"),
        "Network Cards": adapters
    }

    for key, value in info.items():
        if isinstance(value, list):
            print(f"{key}:")
            for item in value:
                print(f" - {item}")
        else:
            print(f"{key}: {value}")

    print()
    return info

# ------------------------------------------------Nmap Setup Begin------------------------------------------------- 

def get_nmap_path():
    """
    Return the full path to nmap.exe if found, otherwise None.
    """
    possible_paths = [
        "nmap",
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
    ]

    for path in possible_paths:
        try:
            result = subprocess.run(
                [path, "--version"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if result.returncode == 0:
                return path
        except Exception:
            continue

    return None


def check_nmap():
    """
    Check if Nmap is installed and accessible.
    """
    return get_nmap_path() is not None


def install_nmap():
    """
    Auto-install Nmap on Windows.
    Returns True if Nmap is installed successfully, otherwise False.
    """
    try:
        print("\n[*] Setting up scanning tools...")
        print("[*] Installing Nmap...\n")

        nmap_url = "https://nmap.org/dist/nmap-7.94-setup.exe"
        nmap_installer = os.path.join(tempfile.gettempdir(), "nmap_installer.exe")

        urllib.request.urlretrieve(nmap_url, nmap_installer)

        subprocess.run(
            [nmap_installer, "/S"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        time.sleep(5)

        if check_nmap():
            print("[✓] Nmap setup complete.\n")
            return True

        print("[!] Nmap installation may have completed, but it was not detected.")
        print("Try reopening PowerShell or Command Prompt and run: nmap --version\n")
        return False

    except Exception as e:
        print(f"[!] Auto-install failed: {e}")
        return False

def run_nmap(args):
    """
    Run Nmap safely using the detected path.
    """
    nmap_path = get_nmap_path()
    if not nmap_path:
        print("[!] Nmap is not installed or not found.")
        return None

    try:
        result = subprocess.run(
            [nmap_path] + args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=300
        )
        return result
    except subprocess.TimeoutExpired:
        print("[!] Nmap scan timed out.")
        return None
    except Exception as e:
        print(f"[!] Failed to run Nmap: {e}")
        return None

# ------------------------------------------------Nmap Setup End-------------------------------------------------

def autorun_download():
    url = "https://download.sysinternals.com/files/Autoruns.zip"
    
    download_path = os.path.join(os.getenv("TEMP"), "Autoruns.zip")
    extract_path = os.path.join(os.getenv("TEMP"), "Autoruns")

    print("[*] Downloading Autoruns...")

    # Download
    urllib.request.urlretrieve(url, download_path)

    print("[*] Extracting Autoruns...")

    # Extract
    with zipfile.ZipFile(download_path, 'r') as zip_ref:
        zip_ref.extractall(extract_path)

    # Path to autorunsc.exe
    autoruns_path = os.path.join(extract_path, "autorunsc.exe")

    if os.path.exists(autoruns_path):
        print("[✓] Autoruns ready")
        #print("Path:", autoruns_path)
        return autoruns_path
    else:
        print("[!] autorunsc.exe not found")
        return None
    return




# ------------------------------------------------Nmap Script Begin-------------------------------------------------


RISKY_NMAP_PORTS = {
    "21": ("FTP Port Open", "High", "FTP is insecure and can expose files or credentials."),
    "23": ("Telnet Port Open", "High", "Telnet is insecure because login data is not encrypted."),
    "135": ("RPC Port Open", "Medium", "RPC exposure can increase the attack surface of the system."),
    "139": ("NetBIOS Port Open", "High", "NetBIOS should not be exposed unless it is truly needed."),
    "445": ("SMB Port Open", "High", "SMB exposure can allow file-sharing attacks or unauthorized access attempts."),
    "1433": ("SQL Server Port Open", "High", "SQL Server should not be exposed unless required and properly restricted."),
    "3389": ("Remote Desktop Port Open", "High", "Remote Desktop exposure can allow remote login attempts."),
    "5900": ("VNC Port Open", "High", "VNC exposure can allow remote control attempts if not properly restricted."),
}


def add_port_finding(findings, title, severity, details, problem, fix):
    findings.append({
        "title": title,
        "severity": severity,
        "details": details,
        "problem": problem,
        "fix": fix
    })


def parse_nmap_open_ports(nmap_output):
    open_ports = []

    for line in nmap_output.splitlines():
        line = line.strip()

        if "/tcp" in line and " open " in line:
            parts = line.split()
            if len(parts) >= 3:
                port = parts[0].split("/")[0]
                service = parts[2]
                version = " ".join(parts[3:]) if len(parts) > 3 else "Unknown"

                open_ports.append({
                    "port": port,
                    "service": service,
                    "version": version
                })

    return open_ports


def analyze_open_ports(open_ports, findings):
    for item in open_ports:
        port = item["port"]
        service = item["service"]
        version = item["version"]

        if port in RISKY_NMAP_PORTS:
            title, severity, desc = RISKY_NMAP_PORTS[port]

            add_port_finding(
                findings,
                title,
                severity,
                {
                    "Port": port,
                    "Service": service,
                    "Version": version
                },
                desc,
                "Disable this service if it is not needed, or restrict access to trusted users and systems only."
            )
        else:
            add_port_finding(
                findings,
                "Open Port Detected",
                "Medium",
                {
                    "Port": port,
                    "Service": service,
                    "Version": version
                },
                "A network service is listening on this port. Open ports increase exposure if the service is unnecessary or outdated.",
                "Review whether this service is required. Disable it if not needed and keep it fully updated."
            )


def analyze_vuln_output(vuln_output, findings):
    current_port = None
    vuln_lines = []

    for line in vuln_output.splitlines():
        stripped = line.strip()

        if "/tcp" in stripped and "open" in stripped:
            if current_port and vuln_lines:
                add_port_finding(
                    findings,
                    "Possible Service Vulnerability Detected",
                    "High",
                    {
                        "Port": current_port
                    },
                    "Nmap reported a possible vulnerability for this open service.",
                    "Review the affected service, apply security updates, and disable the service if it is not needed."
                )

            current_port = stripped.split("/")[0]
            vuln_lines = []

        elif "VULNERABLE" in stripped or "CVE-" in stripped:
            vuln_lines.append(stripped)

    if current_port and vuln_lines:
        add_port_finding(
            findings,
            "Possible Service Vulnerability Detected",
            "High",
            {
                "Port": current_port
            },
            "Nmap reported a possible vulnerability for this open service.",
            "Review the affected service, apply security updates, and disable the service if it is not needed."
        )


def print_port_summary(findings):
    high_count = sum(1 for f in findings if f["severity"] == "High")
    medium_count = sum(1 for f in findings if f["severity"] == "Medium")
    low_count = sum(1 for f in findings if f["severity"] == "Low")

    if high_count > 0:
        overall = "High"
    elif medium_count > 0:
        overall = "Medium"
    else:
        overall = "Low"

    print("=== Ports Vulnerability Report ===")
    print(f"Overall Risk: {overall}")
    print(f"High Findings: {high_count}")
    print(f"Medium Findings: {medium_count}")
    print(f"Low Findings: {low_count}")
    print("==================================\n")


def print_port_finding(finding):
    print(f"[!] {finding['title']} ({finding['severity']})\n")

    for key, value in finding["details"].items():
        print(f"{key}: {value}")

    if finding["details"]:
        print()

    print(f"Problem: {finding['problem']}")
    print(f"Fix: {finding['fix']}")
    print("---------------------------------------------\n")


def port_check():
    print("\n                                   ===== Nmap Vulnerability Report =====\n")
    print("[*] Running Nmap scan on localhost...\n")

    findings = []

    initial_scan = run_nmap(["-Pn", "-T4", "-sV", "--top-ports", "100", "127.0.0.1"])

    if not initial_scan:
        print("[!] Nmap scan could not be started.")
        findings.append({
            "title": "Nmap Scan Failed",
            "severity": "Medium",
            "details": {},
            "problem": "Nmap scan could not be started.",
            "fix": "Verify that Nmap is installed correctly and try again."
        })
        return findings

    if initial_scan.returncode != 0 and not initial_scan.stdout.strip():
        print("[!] Nmap scan failed.")
        if initial_scan.stderr.strip():
            print(initial_scan.stderr.strip())

        findings.append({
            "title": "Nmap Scan Failed",
            "severity": "Medium",
            "details": {},
            "problem": "Nmap scan returned an error.",
            "fix": "Check Nmap installation and permissions, then run the scan again."
        })
        return findings

    open_ports = parse_nmap_open_ports(initial_scan.stdout)

    if not open_ports:
        findings.append({
            "title": "No Open Common Ports Found",
            "severity": "Low",
            "details": {},
            "problem": "No open TCP ports were found in the most common 100 ports on localhost.",
            "fix": "Keep unnecessary services disabled and continue monitoring for new open ports."
        })

        print_port_summary(findings)
        for finding in findings:
            print_port_finding(finding)
        return findings

    analyze_open_ports(open_ports, findings)

    port_list = ",".join(item["port"] for item in open_ports)
    print("[*] Running vulnerability checks on detected open ports...\n")

    vuln_scan = run_nmap([
        "-Pn",
        "-sV",
        "--script", "vuln",
        "-p", port_list,
        "127.0.0.1"
    ])

    if vuln_scan and vuln_scan.stdout.strip():
        analyze_vuln_output(vuln_scan.stdout, findings)

    unique_findings = []
    seen = set()

    for item in findings:
        key = (
            item["title"],
            tuple(item["details"].items()),
            item["problem"]
        )
        if key not in seen:
            unique_findings.append(item)
            seen.add(key)

    print_port_summary(unique_findings)

    for finding in unique_findings:
        print_port_finding(finding)

    return unique_findings



# ------------------------------------------------Privilage Escalation Script Begin-------------------------------------------------


def privilage_check():
    print("\n                                   ===== Privilage Escalation Reporting =====\n")
    findings = run_security_audit()
    print_console(findings)
    return findings

RISKY_IDENTITIES = [
    "BUILTIN\\Users",
    "Everyone",
    "Authenticated Users",
    "Users"
]

PERMISSION_LABELS = {
    "(F)": "Full Control",
    "(M)": "Modify",
    "(W)": "Write"
}


def run_cmd(cmd):
    try:
        return subprocess.check_output(
            cmd,
            shell=True,
            text=True,
            stderr=subprocess.DEVNULL,
            encoding="utf-8",
            errors="ignore"
        )
    except:
        return ""


def get_current_user():
    return run_cmd("whoami").strip() or "Unknown"


def normalize_permission(perm_text):
    for code, label in PERMISSION_LABELS.items():
        if code in perm_text:
            return label
    return perm_text.strip()


# -------------------------------
# CHECK 1: AlwaysInstallElevated
# -------------------------------
def check_always_install_elevated():
    findings = []

    hklm = run_cmd(
        r'reg query "HKLM\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated'
    )
    hkcu = run_cmd(
        r'reg query "HKCU\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated'
    )

    if "0x1" in hklm and "0x1" in hkcu:
        findings.append({
            "id": "always_install_elevated",
            "title": "Dangerous Installer Setting Enabled",
            "severity": "High",
            "category": "Privilege Escalation",
            "details": {
                "Setting": "AlwaysInstallElevated"
            },
            "problem": "All users on this computer can install software with administrator rights.",
            "fix": "Disable this setting in system policies."
        })

    return findings


# -------------------------------
# CHECK 2: User Privileges
# -------------------------------
def check_user_privileges():
    findings = []
    current_user = get_current_user()
    privs = run_cmd("whoami /priv")

    for line in privs.splitlines():
        if "SeImpersonatePrivilege" in line and "Enabled" in line:
            findings.append({
                "id": "high_risk_user_permission",
                "title": "High-Risk User Permission Found",
                "severity": "High",
                "category": "Privilege Escalation",
                "details": {
                    "User": current_user,
                    "Permission": "SeImpersonatePrivilege"
                },
                "problem": "This user can act as another user on the system.",
                "fix": "Remove this permission from non-administrator accounts."
            })

    return findings


# -------------------------------
# CHECK 3: Writable SYSTEM Tasks
# -------------------------------
def parse_icacls(acl_output):
    results = []
    seen = set()  # prevents duplicates

    for line in acl_output.splitlines():
        for identity in RISKY_IDENTITIES:
            if identity.lower() in line.lower():
                perms = re.findall(r"\([A-Z]+\)", line)

                for p in perms:
                    if p in PERMISSION_LABELS:
                        key = (identity.lower(), p)
                        if key not in seen:
                            results.append({
                                "user": identity,
                                "access": normalize_permission(p)
                            })
                            seen.add(key)
                        break
    return results


def task_runs_as_system(task_name):
    output = run_cmd(f'schtasks /query /tn "{task_name}" /fo list /v')

    if not output:
        return False

    for line in output.splitlines():
        if "Run As User" in line:
            user = line.split(":", 1)[-1].strip()
            return user.upper() in ["SYSTEM", "NT AUTHORITY\\SYSTEM"]

    return False


def check_writable_system_tasks():
    findings = []
    base = r"C:\Windows\System32\Tasks"

    for root, _, files in os.walk(base):
        for f in files:
            full_path = os.path.join(root, f)
            task_name = "\\" + os.path.relpath(full_path, base).replace("/", "\\")

            if not task_runs_as_system(task_name):
                continue

            acl = run_cmd(f'icacls "{full_path}"')
            risky = parse_icacls(acl)

            for r in risky:
                findings.append({
                    "id": "writable_system_task",
                    "title": "Writable System Task Found",
                    "severity": "High",
                    "category": "Privilege Escalation",
                    "details": {
                        "Task": f,
                        "Path": full_path,
                        "User": r["user"],
                        "Access": r["access"]
                    },
                    "problem": "A normal user can change this system task.",
                    "fix": "Only administrators should have access."
                })

    return findings


# -------------------------------
# MAIN SCAN FUNCTION
# -------------------------------
def run_security_audit():
    findings = []
    findings += check_always_install_elevated()
    findings += check_user_privileges()
    findings += check_writable_system_tasks()
    return findings


# -------------------------------
# TERMINAL OUTPUT
# -------------------------------
def print_console(findings):
    if not findings:
        print("No issues found.")
        return

    for item in findings:
        print(f"\n[!] {item['title']} ({item['severity']})\n")

        for k, v in item["details"].items():
            print(f"{k}: {v}")

        print(f"\nProblem: {item['problem']}")
        print(f"Fix: {item['fix']}")
        print("-" * 45)



# -----------------------------------------------Firewall Script Begin-------------------------------------------------

RISKY_PORTS = {
    "21": ("FTP", "FTP can expose files and credentials if left open unnecessarily."),
    "23": ("Telnet", "Telnet is insecure because it does not protect login details."),
    "135": ("RPC", "RPC exposure can increase the attack surface of the system."),
    "139": ("NetBIOS", "NetBIOS should not be exposed unless it is truly needed."),
    "445": ("SMB", "SMB exposure can allow file-sharing related attacks or unauthorized access attempts."),
    "1433": ("SQL Server", "SQL Server should not be exposed unless required and properly restricted."),
    "3389": ("Remote Desktop", "Remote Desktop exposure can allow remote login attempts."),
    "5900": ("VNC", "VNC exposure can allow remote control attempts if not restricted."),
}


def run_ps_json(command):
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return []

        output = result.stdout.strip()
        if not output:
            return []

        return json.loads(output)

    except Exception:
        return []


def ensure_list(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    return []


def safe_str(value):
    if value is None:
        return "Unknown"
    return str(value).strip()


def parse_profiles_field(value):
    if value is None:
        return []

    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]

    value = str(value).strip()
    if not value:
        return []

    parts = [p.strip() for p in value.split(",")]
    return [p for p in parts if p]


def is_any_remote_address(remote_address):
    if remote_address is None:
        return False

    if isinstance(remote_address, list):
        values = [str(v).strip().lower() for v in remote_address]
        return any(v in ["any", "*", "0.0.0.0/0", "::/0", "internet"] for v in values)

    value = str(remote_address).strip().lower()
    return value in ["any", "*", "0.0.0.0/0", "::/0", "internet"]


def normalize_action(value):
    value = str(value).strip().lower()

    if value in ["2", "allow"]:
        return "Allow"
    if value in ["4", "block"]:
        return "Block"
    if value == "notconfigured":
        return "NotConfigured"
    return str(value)


def normalize_enabled(value):
    value = str(value).strip().lower()
    return value in ["1", "true"]


def normalize_service_status(value):
    value = str(value).strip().lower()

    if value in ["4", "running"]:
        return "Running"
    if value in ["1", "stopped"]:
        return "Stopped"
    return str(value)


def normalize_start_type(value):
    value = str(value).strip().lower()

    if value in ["2", "automatic"]:
        return "Automatic"
    if value in ["3", "manual"]:
        return "Manual"
    if value in ["4", "disabled"]:
        return "Disabled"
    return str(value)


def normalize_inbound_action(value):
    value = str(value).strip().lower()

    if value in ["2", "block"]:
        return "Block"
    if value in ["4", "allow"]:
        return "Allow"
    return str(value)


def get_firewall_profiles():
    data = run_ps_json(r"""
    Get-NetFirewallProfile |
    Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
    ConvertTo-Json -Depth 3
    """)
    return ensure_list(data)


def get_firewall_service():
    data = run_ps_json(r"""
    Get-Service -Name mpssvc |
    Select-Object Name, Status, StartType |
    ConvertTo-Json -Depth 3
    """)
    return data if isinstance(data, dict) else {}


def get_inbound_rules():
    data = run_ps_json(r"""
    Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
    ForEach-Object {
        $rule = $_
        $portFilter = $rule | Get-NetFirewallPortFilter
        $addressFilter = $rule | Get-NetFirewallAddressFilter

        [PSCustomObject]@{
            DisplayName   = $rule.DisplayName
            Enabled       = $rule.Enabled
            Action        = $rule.Action
            Profile       = $rule.Profile
            Protocol      = $portFilter.Protocol
            LocalPort     = $portFilter.LocalPort
            RemoteAddress = $addressFilter.RemoteAddress
        }
    } | ConvertTo-Json -Depth 5
    """)
    return ensure_list(data)


def add_finding(findings, title, severity, details, problem, fix):
    findings.append({
        "title": title,
        "severity": severity,
        "details": details,
        "problem": problem,
        "fix": fix
    })


def analyze_profiles(profiles, findings):
    for profile in profiles:
        name = safe_str(profile.get("Name"))
        enabled = normalize_enabled(profile.get("Enabled"))
        inbound_action = normalize_inbound_action(profile.get("DefaultInboundAction"))

        if not enabled:
            add_finding(
                findings,
                "Firewall Profile Disabled",
                "High",
                {
                    "Profile": name
                },
                f"The {name} firewall profile is turned off. This reduces protection for that network type.",
                "Turn this firewall profile on unless there is a very specific reason to keep it disabled."
            )

        if inbound_action == "Allow":
            add_finding(
                findings,
                "Default Inbound Traffic Allowed",
                "High",
                {
                    "Profile": name,
                    "Default Inbound Action": inbound_action
                },
                f"The {name} firewall profile allows incoming traffic by default, which can expose the system to unwanted connections.",
                "Change the default inbound action to Block."
            )


def analyze_service(service, findings):
    if not service:
        add_finding(
            findings,
            "Firewall Service Status Unknown",
            "Medium",
            {},
            "The firewall service status could not be checked.",
            "Verify that the Windows Defender Firewall service is present and running."
        )
        return

    name = safe_str(service.get("Name"))
    status = normalize_service_status(service.get("Status"))
    start_type = normalize_start_type(service.get("StartType"))

    if status != "Running":
        add_finding(
            findings,
            "Firewall Service Not Running",
            "High",
            {
                "Service": name,
                "Status": status,
                "Start Type": start_type
            },
            "The Windows firewall service is not running, so firewall protection may not be working properly.",
            "Start the firewall service and set it to Automatic."
        )

    elif start_type == "Disabled":
        add_finding(
            findings,
            "Firewall Service Disabled",
            "High",
            {
                "Service": name,
                "Status": status,
                "Start Type": start_type
            },
            "The Windows firewall service is disabled and may not start after reboot.",
            "Set the firewall service startup type to Automatic."
        )


def analyze_rules(rules, findings):
    for rule in rules:
        rule_name = safe_str(rule.get("DisplayName"))
        protocol = safe_str(rule.get("Protocol"))
        local_port = safe_str(rule.get("LocalPort"))
        remote_address = rule.get("RemoteAddress")
        remote_address_text = safe_str(remote_address)
        profiles = parse_profiles_field(rule.get("Profile"))

        any_address = is_any_remote_address(remote_address)
        is_public = any(p.lower() == "public" for p in profiles)

        ports = [p.strip() for p in local_port.split(",") if p.strip()]
        if not ports:
            ports = [local_port]

        for port in ports:
            if port in RISKY_PORTS and any_address:
                service_name, port_problem = RISKY_PORTS[port]
                severity = "High" if is_public else "Medium"

                profile_text = ", ".join(profiles) if profiles else "Unknown"

                if is_public:
                    problem = (
                        f"This rule allows {service_name} access from any remote address on the Public profile. "
                        f"{port_problem}"
                    )
                else:
                    problem = (
                        f"This rule allows {service_name} access from any remote address. "
                        f"{port_problem}"
                    )

                add_finding(
                    findings,
                    f"Open {service_name} Port Detected",
                    severity,
                    {
                        "Rule": rule_name,
                        "Port": port,
                        "Protocol": protocol,
                        "Profile": profile_text,
                        "Remote Address": remote_address_text
                    },
                    problem,
                    "Disable this rule if it is not needed, or restrict access to trusted IP addresses only."
                )

            elif any_address and is_public:
                profile_text = ", ".join(profiles) if profiles else "Unknown"

                add_finding(
                    findings,
                    "Broad Public Firewall Rule Found",
                    "Medium",
                    {
                        "Rule": rule_name,
                        "Port": port,
                        "Protocol": protocol,
                        "Profile": profile_text,
                        "Remote Address": remote_address_text
                    },
                    "This rule allows inbound access from any remote address on a public network profile.",
                    "Restrict this rule to trusted IP addresses or disable it if it is not needed."
                )


def print_finding(finding):
    print(f"[!] {finding['title']} ({finding['severity']})\n")

    for key, value in finding["details"].items():
        print(f"{key}: {value}")

    if finding["details"]:
        print()

    print(f"Problem: {finding['problem']}")
    print(f"Fix: {finding['fix']}")
    print("---------------------------------------------\n")


def print_summary(findings):
    high_count = sum(1 for f in findings if f["severity"] == "High")
    medium_count = sum(1 for f in findings if f["severity"] == "Medium")
    low_count = sum(1 for f in findings if f["severity"] == "Low")

    if high_count > 0:
        overall = "High"
    elif medium_count > 0:
        overall = "Medium"
    elif low_count > 0:
        overall = "Low"
    else:
        overall = "Low"

    print("=== Firewall Security Check ===")
    print(f"Overall Risk: {overall}")
    print(f"High Findings: {high_count}")
    print(f"Medium Findings: {medium_count}")
    print(f"Low Findings: {low_count}")
    print("================================\n")

def firewall_check():
    print("\n                                   ===== Firewall Reporting =====\n")
    findings = []

    profiles = get_firewall_profiles()
    service = get_firewall_service()
    rules = get_inbound_rules()

    analyze_profiles(profiles, findings)
    analyze_service(service, findings)
    analyze_rules(rules, findings)

    if not findings:
        findings.append({
            "title": "No Major Firewall Issues Found",
            "severity": "Low",
            "details": {},
            "problem": "The firewall checks did not find any major risky conditions.",
            "fix": "Keep the firewall enabled and review new rules before allowing remote access."
        })

    print_summary(findings)

    for finding in findings:
        print_finding(finding)

    return findings
    
# ------------------------------------------------Trivy Script Begin-------------------------------------------------

def get_trivy_path():
    """
    Return the Trivy executable path if found, otherwise None.
    """
    possible_paths = [
        "trivy",
        os.path.join(os.getcwd(), "trivy_local", "trivy.exe"),
        os.path.join(os.getcwd(), "trivy_local", "trivy"),
    ]

    for path in possible_paths:
        try:
            result = subprocess.run(
                [path, "--version"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if result.returncode == 0:
                return path
        except Exception:
            continue

    return None


def is_trivy_installed():
    return get_trivy_path() is not None


def get_latest_trivy_url():
    try:
        api_url = "https://api.github.com/repos/aquasecurity/trivy/releases/latest"

        with urllib.request.urlopen(api_url) as response:
            data = json.loads(response.read().decode())

        for asset in data["assets"]:
            name = asset["name"].lower()
            if "windows" in name and "64bit" in name and name.endswith(".zip"):
                return asset["browser_download_url"]

    except Exception as e:
        print("[!] Error getting latest Trivy version:", e)

    return None


def install_trivy():
    """
    Install Trivy locally into trivy_local folder.
    """
    try:
        print("\n[*] Installing Trivy...\n")

        url = get_latest_trivy_url()
        if not url:
            print("[!] Could not find Trivy download link.")
            return False

        zip_path = os.path.join(tempfile.gettempdir(), "trivy.zip")
        extract_folder = os.path.join(os.getcwd(), "trivy_local")

        print("[*] Downloading Trivy...")
        urllib.request.urlretrieve(url, zip_path)

        print("[*] Extracting files...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_folder)

        time.sleep(2)

        if is_trivy_installed():
            print("[✓] Trivy installed successfully\n")
            return True

        print("[!] Trivy installation completed, but executable was not detected.")
        return False

    except Exception as e:
        print("[!] Trivy installation failed:", e)
        return False


def run_trivy(args):
    """
    Run Trivy safely using detected executable path.
    """
    trivy_path = get_trivy_path()
    if not trivy_path:
        print("[!] Trivy is not installed or not found.")
        return None

    try:
        result = subprocess.run(
            [trivy_path] + args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=600
        )
        return result
    except subprocess.TimeoutExpired:
        print("[!] Trivy scan timed out.")
        return None
    except Exception as e:
        print(f"[!] Failed to run Trivy: {e}")
        return None


def download_scan_target(url):
    """
    Download a file from a direct link into TEMP folder.
    Returns downloaded file path or None.
    """
    try:
        file_name = os.path.basename(url.split("?")[0].strip())
        if not file_name:
            file_name = "trivy_download_target"

        download_path = os.path.join(tempfile.gettempdir(), file_name)

        print("[*] Downloading file...")
        urllib.request.urlretrieve(url, download_path)

        if os.path.exists(download_path) and os.path.getsize(download_path) > 0:
            print("[✓] File downloaded successfully")
            return download_path

        print("[!] Downloaded file is empty or invalid.")
        return None

    except Exception as e:
        print(f"[!] Failed to download file: {e}")
        return None


def add_trivy_finding(findings, title, severity, details, problem, fix):
    findings.append({
        "title": title,
        "severity": severity,
        "details": details,
        "problem": problem,
        "fix": fix
    })


def normalize_trivy_severity(severity):
    value = str(severity).strip().upper()

    if value == "CRITICAL":
        return "High"
    if value == "HIGH":
        return "High"
    if value == "MEDIUM":
        return "Medium"
    if value == "LOW":
        return "Low"
    return "Low"


def parse_trivy_results(data, findings):
    """
    Parse Trivy JSON results into human-readable findings.
    """
    results = data.get("Results", [])
    found_any = False

    for result in results:
        target = result.get("Target", "Unknown")
        vuln_list = result.get("Vulnerabilities", [])
        secret_list = result.get("Secrets", [])
        misconfig_list = result.get("Misconfigurations", [])

        for vuln in vuln_list:
            found_any = True

            pkg_name = vuln.get("PkgName", "Unknown")
            installed_version = vuln.get("InstalledVersion", "Unknown")
            vuln_id = vuln.get("VulnerabilityID", "Unknown")
            severity = normalize_trivy_severity(vuln.get("Severity", "Low"))
            title = f"Vulnerable Package Found ({vuln_id})"

            add_trivy_finding(
                findings,
                title,
                severity,
                {
                    "Target": target,
                    "Package": pkg_name,
                    "Installed Version": installed_version,
                    "Vulnerability ID": vuln_id
                },
                "A package with a known security vulnerability was found.",
                "Update the affected package to a safer version or remove it if it is not needed."
            )

        for secret in secret_list:
            found_any = True

            rule_id = secret.get("RuleID", "Secret")
            category = secret.get("Category", "Secret")
            severity = normalize_trivy_severity(secret.get("Severity", "High"))

            add_trivy_finding(
                findings,
                "Possible Secret Found",
                severity,
                {
                    "Target": target,
                    "Rule": rule_id,
                    "Category": category
                },
                "Sensitive information may be exposed in this file.",
                "Remove the secret from the file and store it securely using a safe secret-management method."
            )

        for misconfig in misconfig_list:
            found_any = True

            misconfig_id = misconfig.get("ID", "Unknown")
            title_text = misconfig.get("Title", "Misconfiguration")
            severity = normalize_trivy_severity(misconfig.get("Severity", "Medium"))

            add_trivy_finding(
                findings,
                f"Misconfiguration Found ({misconfig_id})",
                severity,
                {
                    "Target": target,
                    "Issue": title_text,
                    "Check ID": misconfig_id
                },
                "A security-related configuration issue was found.",
                "Review the affected configuration and apply the recommended secure setting."
            )

    if not found_any:
        add_trivy_finding(
            findings,
            "No Major Trivy Issues Found",
            "Low",
            {},
            "The advanced Trivy scan did not find major vulnerabilities, secrets, or misconfigurations in the selected target.",
            "Continue using secure files and keep dependencies and configurations updated."
        )


def print_trivy_summary(findings):
    high_count = sum(1 for f in findings if f["severity"] == "High")
    medium_count = sum(1 for f in findings if f["severity"] == "Medium")
    low_count = sum(1 for f in findings if f["severity"] == "Low")

    if high_count > 0:
        overall = "High"
    elif medium_count > 0:
        overall = "Medium"
    else:
        overall = "Low"

    print("=== Trivy Advanced Scan Report ===")
    print(f"Overall Risk: {overall}")
    print(f"High Findings: {high_count}")
    print(f"Medium Findings: {medium_count}")
    print(f"Low Findings: {low_count}")
    print("==================================\n")


def print_trivy_finding(finding):
    print(f"[!] {finding['title']} ({finding['severity']})\n")

    for key, value in finding["details"].items():
        print(f"{key}: {value}")

    if finding["details"]:
        print()

    print(f"Problem: {finding['problem']}")
    print(f"Fix: {finding['fix']}")
    print("---------------------------------------------\n")


def scan_folder_with_trivy(folder_path):
    print(f"\n[*] Running Trivy scan on folder:\n{folder_path}\n")
    return run_trivy(["fs", "--format", "json", folder_path])


def scan_file_with_trivy(file_path):
    print(f"\n[*] Running Trivy scan on file:\n{file_path}\n")
    return run_trivy(["fs", "--format", "json", file_path])


def trivy_check():
    print("\n                                   ===== Trivy Advanced Scan =====\n")

    choice = input("Do you want to run advanced Trivy scanning? (yes/no): ").strip().lower()
    if choice not in ["yes", "y"]:
        print("[*] Skipping Trivy advanced scan.\n")
        return [{
            "title": "Trivy Scan Skipped",
            "severity": "Low",
            "details": {},
            "problem": "Advanced Trivy scanning was skipped by the user.",
            "fix": "Run Trivy scanning later if you want to inspect project files, archives, or configuration-related targets."
        }]

    print("\nTrivy is an advanced scan for project files, archives, and configuration-related targets.")
    print("If you are unsure, you can skip this step.\n")

    print("Choose an option:")
    print("1. Scan a folder")
    print("2. Scan a local file")
    print("3. Download a file from a link and scan it\n")

    option = input("Enter your choice (1/2/3): ").strip()

    scan_result = None
    target_path = None

    if option == "1":
        folder_path = input("Enter folder path: ").strip().strip('"')

        if not os.path.isdir(folder_path):
            print("[!] Invalid folder path.\n")
            return [{
                "title": "Trivy Scan Failed",
                "severity": "Medium",
                "details": {},
                "problem": "Invalid folder path was provided.",
                "fix": "Provide a valid folder path and try again."
            }]

        target_path = folder_path
        scan_result = scan_folder_with_trivy(folder_path)

    elif option == "2":
        file_path = input("Enter file path: ").strip().strip('"')

        if not os.path.isfile(file_path):
            print("[!] File not found.\n")
            return [{
                "title": "Trivy Scan Failed",
                "severity": "Medium",
                "details": {},
                "problem": "Selected file was not found.",
                "fix": "Provide a valid file path and try again."
            }]

        target_path = file_path
        scan_result = scan_file_with_trivy(file_path)

    elif option == "3":
        print("\nPlease provide a direct download link to the file you want to scan.")
        print("Example: a .tar archive or another file that can be downloaded directly.")
        print("Note: This must be a direct file download link, not a webpage or repository link.\n")

        url = input("Enter direct file link: ").strip()

        downloaded_file = download_scan_target(url)
        if not downloaded_file:
            return [{
                "title": "Trivy Download Failed",
                "severity": "Medium",
                "details": {},
                "problem": "The file could not be downloaded from the provided link.",
                "fix": "Provide a valid direct download link and try again."
            }]

        target_path = downloaded_file
        scan_result = scan_file_with_trivy(downloaded_file)

    else:
        print("[!] Invalid option selected.\n")
        return [{
            "title": "Trivy Scan Failed",
            "severity": "Medium",
            "details": {},
            "problem": "Invalid Trivy option was selected.",
            "fix": "Choose option 1, 2, or 3."
        }]

    if not scan_result:
        print("[!] Trivy scan could not be started.\n")
        return [{
            "title": "Trivy Scan Failed",
            "severity": "Medium",
            "details": {},
            "problem": "Trivy scan could not be started.",
            "fix": "Verify Trivy installation and try again."
        }]

    if scan_result.returncode not in [0, 5] and not scan_result.stdout.strip():
        print("[!] Trivy scan failed.")
        if scan_result.stderr.strip():
            print(scan_result.stderr.strip())
        print()

        return [{
            "title": "Trivy Scan Failed",
            "severity": "Medium",
            "details": {},
            "problem": "Trivy scan returned an error.",
            "fix": "Review the scan target and Trivy installation, then try again."
        }]

    try:
        data = json.loads(scan_result.stdout)
    except Exception:
        print("[!] Could not read Trivy scan results properly.\n")
        return [{
            "title": "Trivy Result Parsing Failed",
            "severity": "Medium",
            "details": {},
            "problem": "Trivy output could not be parsed properly.",
            "fix": "Run the scan again and verify the selected target."
        }]

    findings = []
    parse_trivy_results(data, findings)

    print(f"[*] Trivy scan target: {target_path}\n")
    print_trivy_summary(findings)

    for finding in findings:
        print_trivy_finding(finding)

    return findings


# ------------------------------------------------Autorun Script Begin-------------------------------------------------

def get_value(elem, tag):
    for child in elem:
        if child.tag.lower() == tag.lower():
            return (child.text or "").strip()
    return ""

def autorun_check():
    print("\n                                   ===== Autorun Reporting =====\n")

    findings = []

    autorun = os.path.join(os.getenv("TEMP"), "Autoruns", "Autorunsc.exe")

    autorun_processes = subprocess.run(
        [autorun, "-accepteula", "-a", "ls", "-x", "-h", "-s", "-nobanner"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )

    if not autorun_processes.stdout.strip():
        finding = {
            "title": f"Suspicious Autorun Entry #{count}",
            "severity": "Medium",
            "details": {
                "Entry": entry,
                "Path": path,
                "SHA256": sha256,
                "VirusTotal": f"https://www.virustotal.com/gui/file/{sha256}"
            },
            "problem": ", ".join(reasons),
            "fix": "Review this file carefully and verify whether it is safe."
        }

    root = ET.fromstring(autorun_processes.stdout)

    print("[*] Checking for vulnerable autorun entries...\n")

    count = 0

    for item in root:
        entry = get_value(item, "itemname")
        path = get_value(item, "imagepath")
        publisher = get_value(item, "signer")
        sha256 = get_value(item, "sha256hash")

        reasons = []

        if publisher == "" or "not verified" in publisher.lower():
            if sha256 != "":
                reasons.append("This file is unsigned or not verified. Review it on VirusTotal.")

        if reasons:
            count += 1
            finding = {
                "title": f"Suspicious Autorun Entry #{count}",
                "severity": "Medium",
                "details": {
                    "Entry": entry,
                    "Path": path,
                    "SHA256": sha256
                },
                "problem": ", ".join(reasons),
                "fix": f"Review this file carefully. VirusTotal link: https://www.virustotal.com/gui/file/{sha256}"
            }
            findings.append(finding)

            print(f"[!] Suspicious Entry #{count}")
            print("Entry     :", entry)
            print("Path      :", path)
            print("SHA256    :", sha256)
            print("Reason    :", ", ".join(reasons))
            print("-" * 40)

    if count == 0:
        print("[✓] No vulnerable autorun entries found")
        findings.append({
            "title": "No Suspicious Autorun Entries Found",
            "severity": "Low",
            "details": {},
            "problem": "No suspicious autorun entries were found in the scan.",
            "fix": "Continue monitoring startup entries and verify new unknown items carefully."
        })

    return findings


# ------------------------------------------------HTML Script Begin-------------------------------------------------


def severity_badge_class(severity):
    severity = str(severity).strip().lower()
    if severity == "high":
        return "sev-high"
    if severity == "medium":
        return "sev-medium"
    return "sev-low"


def count_all_findings(report_data):
    all_findings = []
    for key in ["nmap", "privilege", "firewall", "trivy", "autorun"]:
        all_findings.extend(report_data.get(key, []))
    return all_findings


def overall_risk(findings):
    if any(f.get("severity") == "High" for f in findings):
        return "High"
    if any(f.get("severity") == "Medium" for f in findings):
        return "Medium"
    return "Low"


def render_details_html(details):
    if not details:
        return "<p class='muted'>No extra details.</p>"

    rows = []
    for key, value in details.items():
        value_str = str(value)

        if value_str.startswith("http://") or value_str.startswith("https://"):
            value_html = f'<a href="{html.escape(value_str)}" target="_blank" class="detail-link">{html.escape(value_str)}</a>'
        else:
            value_html = html.escape(value_str)

        rows.append(f"""
            <div class="detail-row">
                <span class="detail-key">{html.escape(str(key))}</span>
                <span class="detail-value">{value_html}</span>
            </div>
        """)
    return "".join(rows)


def render_finding_cards(findings):
    if not findings:
        return '<div class="empty-card">No findings in this section.</div>'

    cards = []
    for finding in findings:
        sev = finding.get("severity", "Low")

        problem_text = html.escape(finding.get("problem", ""))
        fix_text_raw = str(finding.get("fix", ""))
        fix_text = html.escape(fix_text_raw)

        import re
        url_pattern = r'(https?://[^\s]+)'
        fix_text = re.sub(
            url_pattern,
            r'<a href="\1" target="_blank" class="detail-link">\1</a>',
            fix_text
        )

        cards.append(f"""
            <div class="finding-card">
                <div class="finding-header">
                    <h3>{html.escape(finding.get("title", "Untitled Finding"))}</h3>
                    <span class="severity-badge {severity_badge_class(sev)}">{html.escape(sev)}</span>
                </div>
                <div class="details-box">
                    {render_details_html(finding.get("details", {}))}
                </div>
                <div class="text-block">
                    <strong>Problem:</strong>
                    <p>{problem_text}</p>
                </div>
                <div class="text-block">
                    <strong>Fix:</strong>
                    <p>{fix_text}</p>
                </div>
            </div>
        """)
    return "".join(cards)


def html_reporting(report_data):
    findings = count_all_findings(report_data)

    high_count = sum(1 for f in findings if f.get("severity") == "High")
    medium_count = sum(1 for f in findings if f.get("severity") == "Medium")
    low_count = sum(1 for f in findings if f.get("severity") == "Low")
    risk = overall_risk(findings)

    system_info_html = ""
    for key, value in report_data.get("system_info", {}).items():
        if isinstance(value, list):
            value_html = "<br>".join(html.escape(str(v)) for v in value) if value else "N/A"
        else:
            value_html = html.escape(str(value))
        system_info_html += f"""
            <div class="info-item">
                <span class="info-label">{html.escape(str(key))}</span>
                <span class="info-value">{value_html}</span>
            </div>
        """

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report</title>
    <style>
        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #0f172a, #111827);
            color: #e5e7eb;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 30px;
        }}

        .hero {{
            background: linear-gradient(135deg, #1e293b, #0f172a);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 20px;
            padding: 30px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.35);
            margin-bottom: 25px;
        }}

        .hero h1 {{
            margin: 0 0 10px;
            font-size: 36px;
            color: #ffffff;
        }}

        .hero p {{
            margin: 6px 0;
            color: #cbd5e1;
        }}

        .top-actions {{
            margin-top: 20px;
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }}

        .btn {{
            background: #2563eb;
            color: white;
            border: none;
            padding: 12px 18px;
            border-radius: 12px;
            cursor: pointer;
            font-size: 14px;
            text-decoration: none;
            display: inline-block;
        }}

        .btn:hover {{
            background: #1d4ed8;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }}

        .summary-card {{
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 18px;
            padding: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }}

        .summary-card h2 {{
            margin: 0 0 8px;
            font-size: 16px;
            color: #cbd5e1;
        }}

        .summary-card .big {{
            font-size: 28px;
            font-weight: bold;
            color: #ffffff;
        }}

        .section {{
            margin-bottom: 28px;
        }}

        .section-title {{
            font-size: 24px;
            margin-bottom: 14px;
            color: #ffffff;
        }}

        .system-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 14px;
        }}

        .info-item, .finding-card, .empty-card {{
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 18px;
            padding: 18px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.18);
        }}

        .info-label {{
            display: block;
            font-size: 13px;
            color: #94a3b8;
            margin-bottom: 8px;
        }}

        .info-value {{
            font-size: 15px;
            color: #f8fafc;
            word-break: break-word;
            overflow-wrap: anywhere;
        }}

        .findings-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 16px;
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: start;
            gap: 12px;
            margin-bottom: 14px;
        }}

        .finding-header h3 {{
            margin: 0;
            font-size: 18px;
            color: #ffffff;
        }}

        .severity-badge {{
            padding: 6px 12px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: bold;
            min-width: 72px;
            text-align: center;
        }}

        .sev-high {{
            background: rgba(239,68,68,0.18);
            color: #fca5a5;
            border: 1px solid rgba(239,68,68,0.35);
        }}

        .sev-medium {{
            background: rgba(245,158,11,0.18);
            color: #fcd34d;
            border: 1px solid rgba(245,158,11,0.35);
        }}

        .sev-low {{
            background: rgba(34,197,94,0.18);
            color: #86efac;
            border: 1px solid rgba(34,197,94,0.35);
        }}

        .details-box {{
            margin-bottom: 14px;
        }}

        .detail-row {{
            display: flex;
            justify-content: space-between;
            gap: 12px;
            padding: 8px 0;
            border-bottom: 1px solid rgba(255,255,255,0.06);
        }}

        .detail-key {{
            color: #93c5fd;
            font-size: 14px;
        }}

        .detail-value {{
            color: #f8fafc;
            font-size: 14px;
            text-align: right;
            word-break: break-word;
            overflow-wrap: anywhere;
            max-width: 100%;
        }}

        /* 🔥 CLICKABLE LINK STYLE */
        .detail-link {{
            color: #93c5fd;
            text-decoration: none;
            word-break: break-word;
            overflow-wrap: anywhere;
        }}

        .detail-link:hover {{
            color: #bfdbfe;
            text-decoration: underline;
        }}

        .text-block strong {{
            color: #bfdbfe;
        }}

        .text-block p {{
            margin: 6px 0 0;
            color: #e5e7eb;
            line-height: 1.55;
            word-break: break-word;
            overflow-wrap: anywhere;
        }}

        .muted {{
            color: #94a3b8;
        }}

        .footer {{
            text-align: center;
            color: #94a3b8;
            margin-top: 35px;
            font-size: 13px;
        }}

        @media print {{
            body {{
                background: white;
                color: black;
            }}

            .hero, .summary-card, .info-item, .finding-card, .empty-card {{
                box-shadow: none;
                background: white;
                color: black;
                border: 1px solid #ccc;
            }}

            .top-actions {{
                display: none;
            }}

            .section-title, .hero h1, .finding-header h3, .big, 
            .info-value, .detail-value, .text-block p {{
                color: black !important;
            }}
        }}
    </style>
    <script>
        function saveAsPDF() {{
            window.print();
        }}
    </script>
</head>
<body>
    <div class="container">
        <div class="hero">
            <h1>Client Vulnerability Scan Report</h1>
            <p><strong>Scan Time:</strong> {html.escape(report_data.get("scan_time", ""))}</p>
            <p><strong>Overall Risk:</strong> {html.escape(risk)}</p>
            <div class="top-actions">
                <button class="btn" onclick="saveAsPDF()">Save as PDF</button>
            </div>
        </div>

        <div class="summary-grid">
            <div class="summary-card">
                <h2>Overall Risk</h2>
                <div class="big">{html.escape(risk)}</div>
            </div>
            <div class="summary-card">
                <h2>High Findings</h2>
                <div class="big">{high_count}</div>
            </div>
            <div class="summary-card">
                <h2>Medium Findings</h2>
                <div class="big">{medium_count}</div>
            </div>
            <div class="summary-card">
                <h2>Low Findings</h2>
                <div class="big">{low_count}</div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">System Information</div>
            <div class="system-grid">
                {system_info_html}
            </div>
        </div>

        <div class="section">
            <div class="section-title">Nmap Findings</div>
            <div class="findings-grid">
                {render_finding_cards(report_data.get("nmap", []))}
            </div>
        </div>

        <div class="section">
            <div class="section-title">Privilege Escalation Findings</div>
            <div class="findings-grid">
                {render_finding_cards(report_data.get("privilege", []))}
            </div>
        </div>

        <div class="section">
            <div class="section-title">Firewall Findings</div>
            <div class="findings-grid">
                {render_finding_cards(report_data.get("firewall", []))}
            </div>
        </div>

        <div class="section">
            <div class="section-title">Trivy Findings</div>
            <div class="findings-grid">
                {render_finding_cards(report_data.get("trivy", []))}
            </div>
        </div>

        <div class="section">
            <div class="section-title">Autorun Findings</div>
            <div class="findings-grid">
                {render_finding_cards(report_data.get("autorun", []))}
            </div>
        </div>

    </div>
</body>
</html>
"""

    report_path = Path(__file__).resolve().parent / "vulnerability_report.html"

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"\n[✓] HTML report created: {report_path}")
    print("[*] Opening report in your default browser...\n")

    webbrowser.open(report_path.as_uri())

if __name__ == "__main__":
    main()
