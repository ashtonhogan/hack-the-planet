import re

# Open the full_scan_results.gnmap file
with open('full_scan_results.gnmap', 'r') as file:
    data = file.readlines()

# Define a dictionary to hold IP:Port combinations
ip_ports = {}

# Iterate through each line in the file
for line in data:
    # Extract IP address
    ip_match = re.match(r'Host: (\d+\.\d+\.\d+\.\d+)', line)
    if ip_match:
        ip = ip_match.group(1)
    # Extract port information
    port_matches = re.findall(r'(\d+)/open/tcp', line)
    for port in port_matches:
        ip_ports[ip] = ip_ports.get(ip, []) + [port]

# Write the IP:Port combinations to a new text file
with open('ip_port_list.txt', 'w') as file:
    for ip, ports in ip_ports.items():
        for port in ports:
            file.write(f"{ip}:{port}\n")

print("IP:Port combinations written to ip_port_list.txt")
