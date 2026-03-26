# firewall_scan.py
import subprocess
import json


def run_ps_json(command):
    result = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True,
        text=True
    )

    if result.stdout.strip() == "":
        return []

    return json.loads(result.stdout)


def ensure_list(data):
    if isinstance(data, dict):
        return [data]
    if data is None:
        return []
    return data


def get_firewall_scan_results():
    # 1. Profile check
    profiles = run_ps_json("""
    Get-NetFirewallProfile |
    Select Name,Enabled,DefaultInboundAction,DefaultOutboundAction |
    ConvertTo-Json
    """)
    profiles = ensure_list(profiles)

    # 2. Port exposure check
    ports = run_ps_json("""
    Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
    Get-NetFirewallPortFilter |
    Select Protocol,LocalPort |
    ConvertTo-Json
    """)
    ports = ensure_list(ports)

    # 3. Address scope check
    addresses = run_ps_json("""
    Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
    Get-NetFirewallAddressFilter |
    Select RemoteAddress |
    ConvertTo-Json
    """)
    addresses = ensure_list(addresses)

    # 4. Firewall service check
    service = run_ps_json("""
    Get-Service mpssvc |
    Select Name,Status,StartType |
    ConvertTo-Json
    """)

    # 5. Event log check
    events = run_ps_json("""
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5152,5154,5157} -MaxEvents 20 |
    Select Id,TimeCreated |
    ConvertTo-Json
    """)
    events = ensure_list(events)

    any_count = sum(1 for a in addresses if a.get("RemoteAddress") == "Any")
    blocked = sum(1 for e in events if e.get("Id") == 5157)
    listen = sum(1 for e in events if e.get("Id") == 5154)

    # User-friendly findings
    findings = []

    for p in profiles:
        if not p.get("Enabled", True):
            findings.append({
                "title": f"{p.get('Name', 'Unknown')} firewall protection is turned off",
                "severity": "High",
                "message": "One network protection area is disabled, which may leave the device less protected."
            })

        if str(p.get("DefaultInboundAction", "")).lower() == "allow":
            findings.append({
                "title": f"{p.get('Name', 'Unknown')} profile allows incoming traffic by default",
                "severity": "High",
                "message": "This device may accept outside connections more easily than expected."
            })

    if len(ports) > 0:
        findings.append({
            "title": "Incoming network access rules were found",
            "severity": "Medium",
            "message": f"The scan found {len(ports)} firewall port rules allowing inbound access."
        })

    if any_count > 0:
        findings.append({
            "title": "Some rules accept connections from any address",
            "severity": "Medium",
            "message": f"{any_count} rule(s) allow access from any remote address."
        })

    if service and str(service.get("Status")) not in ["Running", "4"]:
        findings.append({
            "title": "Firewall service is not running properly",
            "severity": "High",
            "message": "The firewall background service does not appear to be active."
        })

    if blocked > 0 or listen > 0:
        findings.append({
            "title": "Recent firewall activity was detected",
            "severity": "Low",
            "message": f"Recent events found: {blocked} blocked connection event(s), {listen} listening event(s)."
        })

    if not findings:
        findings.append({
            "title": "No major firewall issues were found",
            "severity": "Low",
            "message": "Basic firewall checks did not show any major concerns."
        })

    return {
        "module_name": "Firewall Security Check",
        "status": "Completed",
        "profiles": profiles,
        "port_rules_found": len(ports),
        "rules_from_any_address": any_count,
        "service": service,
        "blocked_events": blocked,
        "listening_events": listen,
        "findings": findings
    }


if __name__ == "__main__":
    # optional local test
    import pprint
    pprint.pprint(get_firewall_scan_results())