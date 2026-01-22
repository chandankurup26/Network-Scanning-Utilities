from scapy.all import ARP, Ether, srp
from scrapli import Scrapli
import re, netifaces, ipaddress
import networkx as nx
import json
from networkx.readwrite import json_graph
import socket

ROUTER_MODE = False   #True - Router Based | False - Non-Router Based

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

def is_router_present(devices):
    """
    Attempt to detect presence of a Router / Managed Device.
    Tries SSH connection and CDP/LLDP command execution.
    """
    for ip in devices:
        # Quick TCP/22 check (fast fail)
        try:
            sock = socket.create_connection((ip, 22), timeout=2)
            sock.close()
        except Exception:
            continue

        # Try CDP/LLDP via Scrapli
        try:
            device = SCRAPLI_BASE.copy()
            device["host"] = ip

            with Scrapli(**device) as conn:
                output = conn.send_command(
                    "show cdp neighbors detail"
                ).result

                if "Device ID" in output or "IP address" in output:
                    print(f"[Auto-Detect] Router detected at {ip}")
                    return True

        except Exception:
            continue

    print("[Auto-Detect] No router detected")
    return False

def save_topology(graph, filename="topology.json"):
    data = json_graph.node_link_data(graph)
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"\nTopology saved to {filename}")

if __name__ == "__main__":
    try:
        gws = netifaces.gateways()
        gateway_info = gws['default'][netifaces.AF_INET]
        gateway_ip = gateway_info[0]
        interface = gateway_info[1]
        
        iface_data = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
        netmask = iface_data['netmask']
        
        network = ipaddress.IPv4Interface(f"{gateway_ip}/{netmask}").network
        subnet = str(network)
        print(f"Targeting Subnet: {subnet} on interface {interface}")

    except Exception as e:
        print(f"Error determining network: {e}")
        exit(1)
    
    # Step 1: ARP Scan
    live_ips = network_scan(subnet)
    to_visit.update(live_ips)
    print(f"Discovered {len(live_ips)} Live Hosts\n")

    if not live_ips:
        print("No devices discovered. Exiting.")
        exit(0)

    #Adding ARP Nodes To Graph
    for ip in live_ips:
        topology.add_node(ip, discovered_by="arp")

    ROUTER_MODE = is_router_present(live_ips)
    if ROUTER_MODE:
        print("\n[MODE] Router-based Discovery Enabled\n")

        while to_visit:
            ip = to_visit.pop()
            if ip in visited:
                continue

            visited.add(ip)
            print(f"Connecting to {ip}")

            try:
                neighbors = discover_neighbors(ip)
                print(f"Neighbors on {ip}: {neighbors}")

                for neighbor in neighbors:
                    topology.add_node(
                        neighbor,
                        discovered_by="cdp/lldp"
                    )
                    topology.add_edge(ip, neighbor, relation="L3/L2")
                    to_visit.add(neighbor)

            except Exception as e:
                print(f"Failed on {ip}: {e}")

    else:
        print("\n[MODE] Router-less Logical Topology Enabled\n")
        ips = live_ips
        neighbors_map = {ip: set() for ip in live_ips}

        for src_ip in live_ips:
            # Send ARP request from this host to all other hosts
            for dst_ip in live_ips:
                if src_ip == dst_ip:
                    continue
                try:
                    # Quick ARP request check: if dst_ip responds, they are neighbors
                    arp_request = ARP(pdst=dst_ip)
                    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                    packet = broadcast/arp_request
                    answered, _ = srp(packet, timeout=2, verbose=False)
                    if answered:
                        neighbors_map[src_ip].add(dst_ip)
                except Exception:
                    pass  # ignore unreachable hosts

        # Add edges based on actual detected neighbors
        for ip, neighbors in neighbors_map.items():
            for neighbor_ip in neighbors:
                if not topology.has_edge(ip, neighbor_ip):
                    topology.add_edge(ip, neighbor_ip, relation="logical-L2")
    
    # Output Topology
    print("\nDiscovered Network Topology:")
    print(f"Nodes: {topology.number_of_nodes()}")
    print(f"Edges: {topology.number_of_edges()}")
    for edge in topology.edges():
        print(f"{edge[0]} <--> {edge[1]}\n")

    save_topology(topology)
