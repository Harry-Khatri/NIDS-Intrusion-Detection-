#!/usr/bin/env python3

import json
from collections import Counter
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

ALERT_FILE = "/var/log/suricata/eve.json"
PDF_OUTPUT = f"/home/kali/Desktop/NIDS/reports/suricata_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"

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
    print("❌ eve.json not found.")
    exit(1)

# Create reports folder if it doesn't exist
import os
os.makedirs(os.path.dirname(PDF_OUTPUT), exist_ok=True)

# Start PDF generation
c = canvas.Canvas(PDF_OUTPUT, pagesize=A4)
c.setTitle("Suricata Daily Alert Report")
width, height = A4
y = height - 50

c.setFont("Helvetica-Bold", 16)
c.drawString(40, y, "Suricata Daily Alert Report")
y -= 30

c.setFont("Helvetica", 10)
c.drawString(40, y, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
y -= 30

def draw_section(title, data):
    global y
    c.setFont("Helvetica-Bold", 12)
    c.drawString(40, y, title)
    y -= 20
    c.setFont("Helvetica", 10)
    for item, count in data:
        if y < 50:
            c.showPage()
            y = height - 50
        c.drawString(50, y, f"- {item}: {count}")
        y -= 15
    y -= 10

draw_section("🔁 Alert Signatures", Counter(signatures).most_common(10))
draw_section("⚠️ Severity Breakdown", Counter(severities).most_common())
draw_section("🌐 Top Offending Source IPs", Counter(src_ips).most_common(5))

c.save()
print(f"✅ PDF Report saved to: {PDF_OUTPUT}")

