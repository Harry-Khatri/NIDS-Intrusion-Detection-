#!/usr/bin/env python3
import json
import os
import smtplib
from email.mime.text import MIMEText

EVE_LOG = "/var/log/suricata/eve.json"
ALERT_FILE = "/tmp/last_suricata_alert.line"
EMAIL_TO = "harmankhatri248@gmail.com"   # <-- change this
EMAIL_FROM = "suricata@localhost"
SUBJECT = "🚨 Suricata Alert Triggered"

def send_email(body):
    msg = MIMEText(body)
    msg['Subject'] = SUBJECT
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO
    with smtplib.SMTP('localhost') as server:
        server.send_message(msg)

def get_last_line():
    if os.path.exists(ALERT_FILE):
        with open(ALERT_FILE, 'r') as f:
            return int(f.read())
    return 0

def save_last_line(line_num):
    with open(ALERT_FILE, 'w') as f:
        f.write(str(line_num))

last_line = get_last_line()
with open(EVE_LOG, 'r') as f:
    lines = f.readlines()

for i, line in enumerate(lines[last_line:], start=last_line):
    try:
        entry = json.loads(line)
        if entry.get("event_type") == "alert":
            alert = entry["alert"]
            if alert["severity"] <= 2 or "Dummy Rule" in alert["signature"]:
                body = f"Signature: {alert['signature']}\nSeverity: {alert['severity']}\n{json.dumps(entry, indent=2)}"
                send_email(body)
    except Exception:
        continue

save_last_line(len(lines))
