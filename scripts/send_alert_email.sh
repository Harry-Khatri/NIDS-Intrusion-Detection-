
#!/bin/bash

LOG_FILE="/var/log/suricata/eve.json"
EMAIL="harmankhatri248@gmail.com"
KEYWORDS=("🔥 Dummy Rule Triggered" "ICMP Ping Detected" "Nmap Scan Detected" "DNS Tunnel Detected")
SUBJECT="🚨 Suricata Alert Triggered"

ALERTS_FOUND=()

# Check for each keyword
for keyword in "${KEYWORDS[@]}"; do
  if tail -n 50 "$LOG_FILE" | grep -q "$keyword"; then
    ALERTS_FOUND+=("$keyword")
  fi
done

# Send email if any keyword matched
if [ ${#ALERTS_FOUND[@]} -gt 0 ]; then
  echo -e "Suricata has detected the following alert(s):\n\n${ALERTS_FOUND[@]}" | mail -s "$SUBJECT" "$EMAIL"
fi
