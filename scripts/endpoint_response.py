#!/usr/bin/env python3
"""
Day 25 Endpoint Response Integration
------------------------------------
- Reads Suricata eve.json alerts
- Cross-checks with osquery results
- If match found -> trigger auto_block.py
- Logs to reports/
"""

import json
import subprocess
from pathlib import Path
from datetime import datetime

# Paths
EVE_LOG = "/var/log/suricata/eve.json"  # adjust if needed
OSQ_LOG = Path("NIDS/osquery/logs/osqueryd.results.log")
REPORT_DIR = Path("NIDS/reports")
AUTO_BLOCK = "NIDS/scripts/auto_block.py"

REPORT_DIR.mkdir(parents=True, exist_ok=True)

def read_suricata_alerts():
    """Extract IPs from Suricata alerts."""
    ips = set()
    try:
        with open(EVE_LOG, "r") as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    if event.get("event_type") == "alert":
                        if "src_ip" in event: ips.add(event["src_ip"])
                        if "dest_ip" in event: ips.add(event["dest_ip"])
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"[!] Suricata log not found: {EVE_LOG}")
    return ips

def read_osquery_results():
    """Extract suspicious processes from osquery logs."""
    matches = []
    try:
        with open(OSQ_LOG, "r") as f:
            for line in f:
                event = json.loads(line.strip())
                if event.get("name") in ["reverse_shells", "suspicious_parents", "persistence"]:
                    matches.append(event)
    except FileNotFoundError:
        print(f"[!] Osquery log not found: {OSQ_LOG}")
    return matches

def block_ip(ip):
    """Call auto_block.py"""
    try:
        subprocess.run(["python3", AUTO_BLOCK, ip], check=True)
        print(f"[+] Blocked {ip}")
    except Exception as e:
        print(f"[!] Failed to block {ip}: {e}")

def main():
    alerts = read_suricata_alerts()
    threats = read_osquery_results()

    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "suricata_alerts": list(alerts),
        "osquery_threats": threats,
        "actions_taken": []
    }

    # Auto-block if Suricata IP matches osquery detection
    for ip in alerts:
        for threat in threats:
            if ip in json.dumps(threat):  # crude matching
                block_ip(ip)
                report["actions_taken"].append({"blocked_ip": ip, "reason": threat})

    # Save report
    out_file = REPORT_DIR / f"endpoint_response_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[✔] Report saved: {out_file}")

if __name__ == "__main__":
    main()
