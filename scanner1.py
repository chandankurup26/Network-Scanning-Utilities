import nmap
import socket
scanner = nmap.PortScanner()
ip_address = socket.gethostbyname(socket.gethostname())

print("NMAP Automation Tool")
print("<----------------------------------------------------->")
print("Provided IP Address: ", ip_address)
type(ip_address)
response = input(""" \nEnter the type of scan to run:  
                     1. SYN ACK Scan
                     2. UDP Scan
                     3. Comprehensive Scan \n""")
print("Selected Option: ", response)

if response == "1":
    print("NMAP Version: ", scanner.nmap_version())
    scanner.scan(ip_address, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_address].state())
    print(scanner[ip_address].all_protocols())
    print("Open Ports: ", scanner[ip_address]['tcp'].keys())

elif response == "2":
    print("NMAP Version: ", scanner.nmap_version())
    scanner.scan(ip_address, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_address].state())
    print(scanner[ip_address].all_protocols())
    print("Open Ports: ", scanner[ip_address]['udp'].keys())

elif response == "3":
    print("NMAP Version: ", scanner.nmap_version())
    scanner.scan(ip_address, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_address].state())
    print(scanner[ip_address].all_protocols())
    print("Open Ports: ", scanner[ip_address]['tcp'].keys())

elif response <= "4":

    print("ERROR: Enter a valid option")
