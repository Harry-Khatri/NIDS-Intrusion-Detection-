import json
import subprocess
import os
import datetime
import time
# Custom keyword mapping for known test rules
keyword_mapping = {
    "icmp": {
        "ATT&CK ID": "T1046",
        "Technique": "Network Service Scanning",
        "Tactic": "Discovery"
    },
    "ping": {
        "ATT&CK ID": "T1046",
        "Technique": "Network Service Scanning",
        "Tactic": "Discovery"
    },
    "http": {
        "ATT&CK ID": "T1071",
        "Technique": "Application Layer Protocol",
        "Tactic": "Command and Control"
    },
    "tcp": {
        "ATT&CK ID": "T1046",
        "Technique": "Network Service Scanning",
        "Tactic": "Discovery"
    },
    "malicious ip": {
        "ATT&CK ID": "T1568",
        "Technique": "Dynamic Resolution",
        "Tactic": "Command and Control"
    }
}

# Paths
EVE_LOG = "/var/log/suricata/eve.json"
MITRE_FILE = "enterprise_attack.json"

# Step 1: Download MITRE dataset if missing
if not os.path.exists(MITRE_FILE):
    print("⬇ Downloading MITRE ATT&CK dataset...")
    subprocess.run(
        f"wget https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json -O {MITRE_FILE}",
        shell=True,
        check=True
    )

print("🔍 Extracting unique Suricata alert signatures in Python...")



EVE_LOG = "/var/log/suricata/eve.json"
MAPPING_FILE = "mitre_mapping.json"

# Load mapping
with open(MAPPING_FILE, "r") as f:
    mitre_mapping = json.load(f)

# Make reports dir
os.makedirs("reports", exist_ok=True)

# Write to a new timestamped NDJSON file so Filebeat always re-harvests from start
ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
NDJSON_FILE = f"reports/mitre_mapping-{ts}.ndjson"

print("🔍 Extracting & enriching Suricata alerts → NDJSON...")
unique_sigs = set()
count = 0

with open(EVE_LOG, "r", errors="ignore") as log_file, open(NDJSON_FILE, "w") as out:
    for line in log_file:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") != "alert":
            continue

        sig = event.get("alert", {}).get("signature")
        if not sig:
            continue

        doc = {
            "@timestamp": event.get("timestamp"),          # keep original event time
            "signature": sig,
            "src_ip": event.get("src_ip"),
            "dest_ip": event.get("dest_ip"),
            "log_type": "mitre_mapping"                    # helps filtering in Kibana
        }

        # attach MITRE mapping when available
        m = mitre_mapping.get(sig)
        if m:
            doc.update(m)

        out.write(json.dumps(doc) + "\n")
        count += 1

print(f"✅ Wrote {count} enriched events to {NDJSON_FILE}")

