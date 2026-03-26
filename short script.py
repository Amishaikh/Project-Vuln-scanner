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

print("\n==============================")
print("WINDOWS FIREWALL SECURITY SCAN")
print("==============================\n")


# -------------------------------------------------
# 1. FIREWALL PROFILE CHECK
# -------------------------------------------------

profiles = run_ps_json("""
Get-NetFirewallProfile |
Select Name,Enabled,DefaultInboundAction,DefaultOutboundAction |
ConvertTo-Json
""")

print("1. FIREWALL PROFILE CHECK")
print("--------------------------")

for p in profiles:
    print(f"{p['Name']} Profile:")
    print(f"  Enabled: {p['Enabled']}")
    print(f"  Default Inbound Action: {p['DefaultInboundAction']}")
    print(f"  Default Outbound Action: {p['DefaultOutboundAction']}")
    print()

print()


# -------------------------------------------------
# 2. PORT EXPOSURE CHECK
# -------------------------------------------------

ports = run_ps_json("""
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
Get-NetFirewallPortFilter |
Select Protocol,LocalPort |
ConvertTo-Json
""")

print("2. PORT EXPOSURE CHECK")
print("----------------------")

if isinstance(ports, dict):
    ports = [ports]

for p in ports[:10]:  # limit output
    print(f"Protocol: {p['Protocol']} | Local Port: {p['LocalPort']}")

print(f"\nTotal exposed ports found: {len(ports)}")
print()


# -------------------------------------------------
# 3. ADDRESS SCOPE CHECK
# -------------------------------------------------

addresses = run_ps_json("""
Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow |
Get-NetFirewallAddressFilter |
Select RemoteAddress |
ConvertTo-Json
""")

print("3. ADDRESS SCOPE CHECK")
print("----------------------")

if isinstance(addresses, dict):
    addresses = [addresses]

any_count = sum(1 for a in addresses if a["RemoteAddress"] == "Any")

print(f"Rules allowing connections from ANY address: {any_count}")
print(f"Total inbound allow rules checked: {len(addresses)}")
print()


# -------------------------------------------------
# 4. FIREWALL SERVICE CHECK
# -------------------------------------------------

service = run_ps_json("""
Get-Service mpssvc |
Select Name,Status,StartType |
ConvertTo-Json
""")

print("4. FIREWALL SERVICE CHECK")
print("-------------------------")

print(f"Service Name: {service['Name']}")
print(f"Status: {service['Status']}")
print(f"Startup Type: {service['StartType']}")
print()


# -------------------------------------------------
# 5. FIREWALL EVENT LOG CHECK
# -------------------------------------------------

events = run_ps_json("""
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5152,5154,5157} -MaxEvents 20 |
Select Id,TimeCreated |
ConvertTo-Json
""")

print("5. FIREWALL EVENT LOG CHECK")
print("---------------------------")

if isinstance(events, dict):
    events = [events]

blocked = sum(1 for e in events if e["Id"] == 5157)
listen = sum(1 for e in events if e["Id"] == 5154)

print(f"Blocked connection events: {blocked}")
print(f"Applications allowed to listen on port events: {listen}")
print(f"Total recent firewall events checked: {len(events)}")

print("\nScan Complete.\n")