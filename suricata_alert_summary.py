import json
from collections import Counter
from datetime import datetime

LOG_PATH = "/var/log/suricata/eve.json"

def summarize_alerts(log_path):
    alert_counts = Counter()
    try:
        with open(log_path, "r") as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        signature = event["alert"]["signature"]
                        alert_counts[signature] += 1
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"File not found: {log_path}")
        return

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"Suricata Alert Summary - {now}")
    print("-" * 50)
    for sig, count in alert_counts.most_common():
        print(f"{count:>5}  {sig}")

if __name__ == "__main__":
    summarize_alerts(LOG_PATH)
