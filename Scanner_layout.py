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

    if not authentication_menu():
        exit_program()

    scan_results = run_vulnerability_scan()
    if scan_results is None:
        display_scan_failed()
        exit_program()

    if not upload_results(scan_results):
        display_upload_failed()
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
    pass


def collect_os_information():
    """
    Use PowerShell to collect OS version, hostname, and system info.
    """
    pass


def run_port_scan():
    """
    Run Nmap port scan against the local system.
    """
    pass


def run_vulnerability_scripts():
    """
    Execute basic Nmap vulnerability detection scripts.
    """
    pass


def process_scan_results():
    """
    Normalize scan output and assign risk levels.
    Convert data into JSON-ready format.
    """
    pass


# ==========================================
# SERVER COMMUNICATION
# ==========================================

def upload_results(scan_data):
    """
    Upload scan results to the web server using HTTPS.
    Uses authentication token for authorization.
    Returns True on success, False otherwise.
    """
    pass


def send_https_request():
    """
    Generic helper for sending authenticated HTTPS requests to server.
    """
    pass


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
