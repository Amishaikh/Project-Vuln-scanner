# privilege_escalation.py
import subprocess
import os
import json
import platform
from datetime import datetime


def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return ""


def check_writable(path):
    cmd = f'icacls "{path}"'
    output = run_cmd(cmd)
    risky_acls = ["(F)", "(M)", "(W)"]
    for line in output.splitlines():
        if any(acl in line for acl in risky_acls):
            return True
    return False


def run_security_audit():
    results = {
        "System Info": {},
        "Installer Policies": [],
        "User Privileges": [],
        "Scheduled Tasks": [],
        "File Permissions": [],
        "Service Paths": []
    }

    results["System Info"] = {
        "Hostname": platform.node(),
        "OS": platform.platform(),
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    hklm = run_cmd(r'reg query HKLM\Software\Policies\Microsoft\Windows\Installer')
    hkcu = run_cmd(r'reg query HKCU\Software\Policies\Microsoft\Windows\Installer')

    if "AlwaysInstallElevated" in hklm and "AlwaysInstallElevated" in hkcu:
        results["Installer Policies"].append({
            "title": "AlwaysInstallElevated Enabled",
            "risk": "Allows MSI packages to install with elevated privileges.",
            "recommendation": "Disable AlwaysInstallElevated in HKLM and HKCU."
        })

    privs = run_cmd("whoami /priv")

    if "SeDebugPrivilege" in privs:
        results["User Privileges"].append({
            "title": "SeDebugPrivilege Enabled",
            "risk": "Allows interaction with system processes.",
            "recommendation": "Restrict SeDebugPrivilege to administrators only."
        })

    if "SeImpersonatePrivilege" in privs:
        results["User Privileges"].append({
            "title": "SeImpersonatePrivilege Enabled",
            "risk": "Allows impersonation of other users.",
            "recommendation": "Restrict impersonation rights to essential accounts."
        })

    task_dir = r"C:\Windows\System32\Tasks"
    if os.path.exists(task_dir):
        for root, dirs, files in os.walk(task_dir):
            for f in files:
                full_path = os.path.join(root, f)
                acl = run_cmd(f'icacls "{full_path}"')
                if "SYSTEM" in acl and any(x in acl for x in ["(M)", "(W)", "(F)"]):
                    results["Scheduled Tasks"].append({
                        "title": f"Potentially Modifiable SYSTEM Task: {f}",
                        "risk": "Writable scheduled task running as SYSTEM.",
                        "recommendation": "Restrict ACLs on scheduled task files."
                    })

    if check_writable(r"C:\Program Files"):
        results["File Permissions"].append({
            "title": "Writable Program Files Directory",
            "risk": "Writable application directories can allow unauthorized file replacement.",
            "recommendation": "Review and restrict ACLs on Program Files."
        })

    ps_cmd = (
        'powershell -NoProfile -Command "'
        'Get-WmiObject Win32_Service | '
        'Select-Object Name,PathName | ConvertTo-Json -Depth 3"'
    )
    svc_json = run_cmd(ps_cmd)

    try:
        services = json.loads(svc_json) if svc_json.strip() else []
        if isinstance(services, dict):
            services = [services]

        for svc in services:
            raw_path = svc.get("PathName", "")
            if not raw_path:
                continue

            raw_path = raw_path.strip()

            if raw_path.startswith('"'):
                end_quote = raw_path.find('"', 1)
                exe_path = raw_path[1:end_quote] if end_quote != -1 else raw_path
            else:
                exe_path = raw_path.split(" ")[0]

            if " " in exe_path and not raw_path.startswith('"'):
                results["Service Paths"].append({
                    "title": f"Unquoted Service Path: {svc.get('Name')}",
                    "risk": "Executable path contains spaces but is not quoted.",
                    "recommendation": "Quote the ImagePath registry value."
                })

    except Exception:
        pass

    return results


def get_privilege_escalation_results():
    raw = run_security_audit()

    findings = []

    # Installer policies
    if raw["Installer Policies"]:
        findings.append({
            "title": "Software installation settings may allow elevated installation",
            "severity": "High",
            "message": "This device may allow certain software packages to run with more power than expected."
        })

    # User privileges
    if raw["User Privileges"]:
        findings.append({
            "title": "Some powerful user rights were detected",
            "severity": "High",
            "message": f"The scan found {len(raw['User Privileges'])} privilege setting(s) that may allow stronger control over the system."
        })

    # Scheduled tasks
    if raw["Scheduled Tasks"]:
        findings.append({
            "title": "Some scheduled tasks may be easier to change than expected",
            "severity": "High",
            "message": f"The scan found {len(raw['Scheduled Tasks'])} task(s) that may be modified in a risky way."
        })

    # File permissions
    if raw["File Permissions"]:
        findings.append({
            "title": "A system application folder may be writable",
            "severity": "High",
            "message": "A sensitive application folder appears to allow changes that should normally be restricted."
        })

    # Service paths
    if raw["Service Paths"]:
        findings.append({
            "title": "Some service program paths are not safely quoted",
            "severity": "Medium",
            "message": f"The scan found {len(raw['Service Paths'])} service path issue(s) that may create security weakness."
        })

    if not findings:
        findings.append({
            "title": "No major privilege escalation issues were found",
            "severity": "Low",
            "message": "Basic privilege escalation checks did not show any major concerns."
        })

    return {
        "module_name": "Privilege Escalation Check",
        "status": "Completed",
        "system_info": raw.get("System Info", {}),
        "raw_results": raw,
        "findings": findings
    }


if __name__ == "__main__":
    import pprint
    pprint.pprint(get_privilege_escalation_results())