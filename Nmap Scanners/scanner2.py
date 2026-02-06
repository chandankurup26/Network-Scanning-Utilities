import nmap
scanner = nmap.PortScanner()

# Define the target network range (e.g., 192.168.0.0/24)
target = ('10.66.19.224/24')

# Perform a ping scan with host discovery and include MAC addresses
scanner.scan(target, arguments='-sn')

# Display the results
hosts = []
for host in scanner.all_hosts():
    addresses = scanner[host]['addresses']
    if 'mac' in addresses:
        hosts.append(addresses)
    else:
        # If no MAC address is available, still include the IP
        hosts.append({'ipv4': addresses.get('ipv4')})

print(hosts)