import json
import subprocess
import time

EVE_LOG = "/var/log/suricata/eve.json"
BLOCKED_IPS = set()

def block_ip(ip):
    if ip not in BLOCKED_IPS:
        print(f"[+] Blocking IP via UFW: {ip}")
        try:
            subprocess.run(["sudo", "ufw", "deny", "from", ip], check=True)
            BLOCKED_IPS.add(ip)
        except subprocess.CalledProcessError:
            print(f"[!] Failed to block IP: {ip}")

def monitor_eve():
    print("[*] Monitoring eve.json for alerts...")
    with open(EVE_LOG, "r", encoding="utf-8") as f:
        # Jump to end of file
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            try:
                data = json.loads(line)
                if "alert" in data and "src_ip" in data:
                    ip = data["src_ip"]
                    block_ip(ip)
            except json.JSONDecodeError:
                continue

if __name__ == "__main__":
    try:
        monitor_eve()
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
