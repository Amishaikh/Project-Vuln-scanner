import subprocess
import os
import json
import platform
from datetime import datetime

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
    except:
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

    hklm = run_cmd('reg query HKLM\\Software\\Policies\\Microsoft\\Windows\\Installer')
    hkcu = run_cmd('reg query HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer')

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
        "powershell -command \"Get-WmiObject Win32_Service | "
        "Select-Object Name,PathName | ConvertTo-Json -Depth 3\""
    )
    svc_json = run_cmd(ps_cmd)

    try:
        services = json.loads(svc_json)
        if isinstance(services, dict):
            services = [services]

        for svc in services:
            raw_path = svc.get("PathName", "")
            if not raw_path:
                continue

            raw_path = raw_path.strip()

            exe_path = ""
            if raw_path.startswith('"'):
                end_quote = raw_path.find('"', 1)
                exe_path = raw_path[1:end_quote] if end_quote != -1 else raw_path
            else:
                parts = raw_path.split(" ")
                exe_path = parts[0]

            if " " in exe_path and not raw_path.startswith('"'):
                results["Service Paths"].append({
                    "title": f"Unquoted Service Path: {svc.get('Name')}",
                    "risk": "Executable path contains spaces but is not quoted.",
                    "recommendation": "Quote the ImagePath registry value."
                })

    except:
        pass

    return results

def print_console(results):
    print("\n==============================")
    print(" Windows Security Audit Report")
    print("==============================\n")

    for category, findings in results.items():
        print(f"[{category}]")

        if isinstance(findings, dict):
            for k, v in findings.items():
                print(f"  {k}: {v}")
            print()
            continue

        if not findings:
            print("  No issues found.\n")
            continue

        for f in findings:
            print(f" ⚠ {f['title']}")
            print(f"   Risk: {f['risk']}")
            print(f"   Recommendation: {f['recommendation']}\n")

def generate_html(results):
    html = """
    <html>
    <head>
        <title>Windows Security Audit</title>
        <style>
            body { font-family: Arial; margin: 40px; }
            h1 { color: #2c3e50; }
            h2 { color: #34495e; }
            .finding { margin-bottom: 15px; }
            .risk { color: #c0392b; }
            .rec { color: #27ae60; }
        </style>
    </head>
    <body>
    <h1>Windows Security Audit Report</h1>
    """

    for category, findings in results.items():
        html += f"<h2>{category}</h2>"

        if isinstance(findings, dict):
            html += "<ul>"
            for k, v in findings.items():
                html += f"<li><b>{k}:</b> {v}</li>"
            html += "</ul>"
            continue

        if not findings:
            html += "<p>No issues found.</p>"
            continue

        for f in findings:
            html += f"""
            <div class='finding'>
                <b>{f['title']}</b><br>
                <span class='risk'>Risk:</span> {f['risk']}<br>
                <span class='rec'>Recommendation:</span> {f['recommendation']}
            </div>
            """

    html += "</body></html>"

    with open("security_audit_report.html", "w") as file:
        file.write(html)

if __name__ == "__main__":
    results = run_security_audit()
    print_console(results)
    generate_html(results)
    print("HTML report saved as: security_audit_report.html")
