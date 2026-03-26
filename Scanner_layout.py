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
from short_script import get_firewall_scan_results
from privilege_escalation import get_privilege_escalation_results 

def main():
    # 1) Ensure we're running inside an elevated console first
    if not is_admin():
        request_admin_privileges()
        return  # stop the non-admin instance immediately

    # 2) Now we're admin (in the admin PowerShell window) — show UX
    display_welcome()
    display_preparing_system()

    if not system_preflight_check():
        display_setup_failed()
        exit_program()


    scan_results = run_vulnerability_scan()
    if scan_results is None:
        display_scan_failed()
        exit_program()

    # Step 5: Generate report
    if not generate_report(scan_results):
        print("[!] Failed to generate report.")
        exit_program()

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

def run_vulnerability_scan():
    """
    Orchestrates the entire scan:
    - Windows security checks
    - Network scanning
    - Data aggregation
    """
    """
    Run all team vulnerability modules and collect their results.
    Each module should return a structured dictionary.
    """
    all_results = {
        "scan_title": "Client Vulnerability Scan Report",
        "modules": []
    }

    try:
        firewall_results = get_firewall_scan_results()
        all_results["modules"].append(firewall_results)
    except Exception as e:
        all_results["modules"].append({
            "module_name": "Firewall Security Check",
            "status": "Failed",
            "findings": [{
                "title": "Firewall scan could not be completed",
                "severity": "High",
                "message": f"The firewall scan module failed to run. Error: {str(e)}"
            }]
        })

    # Privilege escalation module
    try:
        privilege_results = get_privilege_escalation_results()
        all_results["modules"].append(privilege_results)
    except Exception as e:
        all_results["modules"].append({
            "module_name": "Privilege Escalation Check",
            "status": "Failed",
            "findings": [{
                "title": "Privilege escalation scan could not be completed",
                "severity": "High",
                "message": f"The privilege escalation module failed to run. Error: {str(e)}"
            }]
        })

    # Add your other 2 teammates later in the same way
    # from script3 import get_scan_results as get_script3_results
    
    return all_results



# -------- WINDOWS SECURITY CHECKS --------

def collect_os_information():
    """Collect OS version, hostname, build"""
    pass

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
    
    pass


# -------- NETWORK SCANNING --------

def run_port_scan():
    """Run Nmap port scan on local system"""
    pass

def run_vulnerability_scripts():
    """Run Nmap vulnerability scripts"""
    pass


# -------- DATA PROCESSING --------

def process_scan_results():
    """
    Normalize Windows + Nmap data
    Assign severity (High / Medium / Low)
    """
    pass


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
    """
    Generate one non-technical HTML report for all modules.
    """
    try:
        html = []
        html.append("""
        <html>
        <head>
            <title>Vulnerability Scan Report</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 30px;
                    background: #f7f9fc;
                    color: #222;
                }
                h1, h2 {
                    color: #1f4e79;
                }
                .card {
                    background: white;
                    border: 1px solid #ddd;
                    border-radius: 10px;
                    padding: 16px;
                    margin-bottom: 20px;
                    box-shadow: 0 2px 6px rgba(0,0,0,0.08);
                }
                .severity-High {
                    color: #b00020;
                    font-weight: bold;
                }
                .severity-Medium {
                    color: #d97706;
                    font-weight: bold;
                }
                .severity-Low {
                    color: #2563eb;
                    font-weight: bold;
                }
                .severity-Info {
                    color: #4b5563;
                    font-weight: bold;
                }
                ul {
                    padding-left: 20px;
                }
            </style>
        </head>
        <body>
        """)

        html.append(f"<h1>{scan_data.get('scan_title', 'Security Report')}</h1>")
        html.append("<p>This report gives a simple overview of the security checks completed on this device.</p>")

        for module in scan_data.get("modules", []):
            html.append("<div class='card'>")
            html.append(f"<h2>{module.get('module_name', 'Unknown Module')}</h2>")
            html.append(f"<p><strong>Status:</strong> {module.get('status', 'Unknown')}</p>")

            findings = module.get("findings", [])
            if findings:
                html.append("<ul>")
                for item in findings:
                    sev = item.get("severity", "Info")
                    title = item.get("title", "Finding")
                    msg = item.get("message", "")
                    html.append(
                        f"<li><span class='severity-{sev}'>{sev}</span> - "
                        f"<strong>{title}</strong><br>{msg}</li><br>"
                    )
                html.append("</ul>")
            else:
                html.append("<p>No issues were reported in this section.</p>")

            html.append("</div>")

        html.append("</body></html>")

        report_path = os.path.join(os.getcwd(), "vulnerability_report.html")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("".join(html))

        print(f"[✓] Report generated: {report_path}")
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
    """
    pass


def exit_program():
    """
    Safely terminate the program.
    In an elevated PowerShell with -NoExit, the window will stay open anyway.
    """
    sys.exit(0)


# ==========================================
# SCRIPT ENTRY POINT
# ==========================================

if __name__ == "__main__":
    main()
