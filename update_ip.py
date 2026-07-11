import sys, re
if len(sys.argv) != 2:
    print("Usage: python update_ip.py NEW_IP")
    sys.exit(1)
new_ip = sys.argv[1]
files_to_update = [".env"]   # add other files if needed (e.g., ossec.conf, etc.)
for f in files_to_update:
    try:
        with open(f, "r") as file:
            content = file.read()
    except FileNotFoundError:
        print(f"File {f} not found, skipping.")
        continue
    # Replace only the first occurrence of an IP in common patterns (WAZUH_URL, INDEXER_URL, TARGET_IP)
    # Safer: match lines that look like URL or IP assignments
    lines = content.splitlines()
    new_lines = []
    for line in lines:
        if "WAZUH_URL" in line or "INDEXER_URL" in line or "TARGET_IP" in line:
            # Replace the IP part (preserve port and protocol)
            line = re.sub(r'(\d{1,3}\.){3}\d{1,3}', new_ip, line)
        new_lines.append(line)
    with open(f, "w") as file:
        file.write("\n".join(new_lines))
    print(f"✅ Updated {f} to use {new_ip}")