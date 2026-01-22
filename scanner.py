from scapy.all import ARP, Ether, srp
from scrapli import Scrapli
import re, netifaces
import networkx as nx

SCRAPLI_BASE = {
    "auth_username": "admin",
    "auth_password": "password",
    "auth_strict_key": False,
    "platform": "cisco_iosxe",
    "timeout_socket": 10
}

visited = set()
to_visit = set()
topology = nx.Graph() #Create Graph

def network_scan(network):
    arp_request = ARP(pdst=network) #ARP
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff") #Ethernet
    packet = broadcast/arp_request #Combining ARP & Ethernet
    #Send Packet & Recieve Information
    answered, _ = srp(packet, timeout = 10, verbose = False)
    
    devices = []
    for sent, received in answered:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })
    return [received.psrc for _, received in answered]

def discover_neighbors(ip):
    device = SCRAPLI_BASE.copy()
    device["host"] = ip
    neighbors = set()

    with Scrapli(**device) as conn:
        neighbors.update(
            re.findall(r"IP address: (\S+)",
            conn.send_command("show cdp neighbors detail").result)
        )
        neighbors.update(
            re.findall(r"Management Address: (\S+)",
            conn.send_command("show lldp neighbors detail").result)
        )
    return neighbors

if __name__ == "__main__":
    #Netifaces To Find Gateway IP
    gws = netifaces.gateways()
    gateway_ip = gws['default'][netifaces.AF_INET][0]
    subnet = gateway_ip+'/16'
    
    # Step 1: ARP Scan
    live_ips = network_scan(subnet)
    to_visit.update(live_ips)
    print(f"Discovered {len(live_ips)} Live Hosts\n")

    #Adding ARP Nodes To Graph
    for ip in live_ips:
        topology.add_node(ip, discovered_by="arp")

    # Step 2: Scrapli Discovery
    while to_visit:
        ip = to_visit.pop()
        if ip in visited:
            continue

        visited.add(ip)
        topology.add_node(ip, discovered_by="ssh")
        print(f"Trying {ip}")

        try:
            neighbors = discover_neighbors(ip)
            print(f"Neighbors found on {ip}: {neighbors}")
            for neighbor in neighbors:
                topology.add_node(neighbor, discovered_by="cdp/lldp")
                topology.add_edge(ip, neighbor)
            to_visit.update(neighbors - visited)

        except Exception as e:
            print(f"Failed to discover neighbors on {ip}: {e}")
    
    # Output Topology
    print("\nDiscovered Network Topology:")
    print(f"Nodes: {topology.number_of_nodes()}")
    print(f"Edges: {topology.number_of_edges()}")
    for edge in topology.edges():
        print(f"{edge[0]} <--> {edge[1]}\n")