from elasticsearch import Elasticsearch
import smtplib
from email.mime.text import MIMEText

# Connect to Elasticsearch
es = Elasticsearch(
    ["https://localhost:9200"],
    basic_auth=("elastic", "HcGyzd829l5CsH4UZRzw"),
    verify_certs=False
)

# Suspicious patterns to look for
queries = {
    "Failed SSH login": {"match": {"message": "Failed password"}},
    "Sudo command used": {"match": {"message": "sudo"}},
    "Authentication failure": {"match": {"message": "authentication failure"}},
    "Error logs": {"match": {"log.level": "error"}},
}

# Get list of indices
indices = es.cat.indices(format="json")
index_names = [idx["index"] for idx in indices]

alerts = []

# Run queries
for alert_name, query in queries.items():
    for index in index_names:
        try:
            results = es.search(index=index, query=query, size=3)
            if results["hits"]["total"]["value"] > 0:
                alerts.append(f"[{alert_name}] found in index {index}")
        except Exception as e:
            print(f"Skipping {index} due to error: {e}")

# Gmail SMTP settings
SENDER_EMAIL = "harmankhatri248@gmail.com"
SENDER_PASSWORD = "nyfuppdatnfhrtbl"  # ⚠️ Use Gmail App Password, not real password
RECEIVER_EMAIL = "harmankhatri248@gmail.com"

def send_email(subject, body):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        print("✅ Email alert sent successfully!")
    except Exception as e:
        print(f"⚠️ Could not send email: {e}")

# Send alert or print status
if alerts:
    message = "\n".join(alerts)
    print("🚨 ALERTS 🚨\n", message)
    send_email("Elasticsearch Security Alert", message)
else:
    print("✅ No suspicious activity detected.")
