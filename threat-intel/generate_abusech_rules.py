feed = "abusech_ips.txt"
output = "abusech.rules"

with open(feed) as f, open(output, "w") as out:
    for i, ip in enumerate(f):
        ip = ip.strip()
        if ip and not ip.startswith("#"):
            out.write(f'alert ip any any -> {ip} any (msg:"[ABUSE.CH] Malicious IP {ip}"; sid:1001{i}; rev:1;)\n')
