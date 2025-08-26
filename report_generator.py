#!/usr/bin/env python3

import json
from collections import Counter
from datetime import datetime

ALERT_FILE = "/var/log/suricata/eve.json"
signatures = []
severities = []
src_ips = []

try:
    with open(ALERT_FILE, "r") as f:
        for line in f:
            try:
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    alert = event.get("alert", {})
                    sig = alert.get("signature")
                    sev = alert.get("severity")
                    src_ip = event.get("src_ip")

                    if sig:
                        signatures.append(sig)
                    if sev is not None:
                        severities.append(sev)
                    if src_ip:
                        src_ips.append(src_ip)

            except json.JSONDecodeError:
                continue
except FileNotFoundError:
    print("❌ Error: eve.json file not found.")
    exit(1)

print("\n📊 Suricata Daily Alert Summary")
print("🕒 Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

print("\n🔁 Alert Signatures:")
for sig, count in Counter(signatures).most_common(10):
    print(f" - {sig}: {count} hits")

print("\n⚠️ Severity Breakdown:")
for sev, count in Counter(severities).most_common():
    print(f" - Severity {sev}: {count} alerts")

print("\n🌐 Top Offending Source IPs:")
for ip, count in Counter(src_ips).most_common(5):
    print(f" - {ip}: {count} times")

print("\n✅ Report generation complete.\n")

