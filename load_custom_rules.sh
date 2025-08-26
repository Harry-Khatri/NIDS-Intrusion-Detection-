#!/bin/bash

CUSTOM_DIR="$HOME/Desktop/NIDS/custom-rules"
SURICATA_DIR="/etc/suricata/rules"
BACKUP_DIR="/etc/suricata/rules/backup"

# Create backup
mkdir -p "$BACKUP_DIR"
cp "$SURICATA_DIR"/custom.rules "$BACKUP_DIR"/custom.rules.$(date +%F-%H%M%S) 2>/dev/null

# Combine all custom .rules into one
cat $CUSTOM_DIR/*.rules > "$SURICATA_DIR/custom.rules"

# Validate
suricata -T -c /etc/suricata/suricata.yaml -v
if [ $? -eq 0 ]; then
    echo "[+] Custom rules loaded successfully."
else
    echo "[!] Error loading custom rules. Reverting..."
    cp "$BACKUP_DIR"/custom.rules.* "$SURICATA_DIR/custom.rules"
fi
