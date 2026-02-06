from scapy.all import ARP, Ether, srp
from scrapli import Scrapli
import re, netifaces, ipaddress
import networkx as nx
import json, socket, manuf
from networkx.readwrite import json_graph

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
    return devices

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

def get_interface_type(interface):
    if interface.startswith(("wl", "wlan", "wifi")):
        return "wifi"
    elif interface.startswith(("en", "eth", "eno", "ens")):
        return "ethernet"
    return "unknown"


def guess_remote_link_type(mac):
    if not mac:
        return "unknown"

    mobile_ouis = (
        "Apple", "Samsung", "Xiaomi", "Huawei",
        "OnePlus", "Motorola", "Realtek"
    )
    try:
        parser = manuf.MacParser()
        vendor = parser.get_manuf(mac)
        if vendor and any(v in vendor for v in mobile_ouis):
            return "wifi"
    except Exception:
        pass

    return "ethernet"

def add_implicit_l2_device(topology, devices, gateway_ip=None):
    l2_node_id = "L2_SWITCH_AP"
    topology.add_node(
        l2_node_id,
        role="implicit-l2",
        discovered_by="inference"
    )

    for ip in devices:  # devices is a list of IP strings
        topology.add_edge(
            l2_node_id,
            ip,
            relation="logical-L2"
        )

    # Optionally link gateway if provided
    if gateway_ip:
        topology.add_edge(
            l2_node_id,
            gateway_ip,
            relation="uplink"
        )
    return l2_node_id

def save_topology(graph, filename="topology.json"):
    data = json_graph.node_link_data(graph)
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"\nTopology saved to {filename}")

def detect_real_loops(graph):
    """
    Detects loops only if cycles involve more than one L2/L3 device.
    Host-only cycles are ignored.
    """
    cycles = nx.cycle_basis(graph)
    real_loops = []

    for cycle in cycles:
        infra_nodes = [
            n for n in cycle
            if graph.nodes[n].get("role") in ("router", "implicit-l2")
        ]

        if len(infra_nodes) > 1:
            real_loops.append(cycle)

    return real_loops

if __name__ == "__main__":
    try:
        gws = netifaces.gateways()
        gateway_info = gws['default'][netifaces.AF_INET]
        gateway_ip = gateway_info[0]
        interface = gateway_info[1]
        
        iface_data = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
        netmask = iface_data['netmask']
        local_iface_type = get_interface_type(interface)
        
        network = ipaddress.IPv4Interface(f"{gateway_ip}/{netmask}").network
        subnet = str(network)
        print(f"Targeting Subnet: {subnet} on interface {interface}")

    except Exception as e:
        print(f"Error determining network: {e}")
        exit(1)
    
    # Step 1: ARP Scan
    devices = network_scan(subnet)
    live_ips = [d["ip"] for d in devices]
    mac_map = {d["ip"]: d["mac"] for d in devices}
    to_visit.update(live_ips)

    print(f"Discovered {len(live_ips)} Live Hosts\n")

    if not live_ips:
        print("No devices discovered. Exiting.")
        exit(0)

    #Adding ARP Nodes To Graph
    for ip in live_ips:
        topology.add_node(
            ip,
            discovered_by="arp",
            connection_type=guess_remote_link_type(mac_map.get(ip)),
            mac_address=mac_map.get(ip)
        )

    topology.add_node(
        gateway_ip,
        role="gateway",
        connection_type=local_iface_type
    )

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

        # Create One implicit L2 Switch/AP
        l2_node = add_implicit_l2_device(
            topology=topology,
            devices=live_ips,
            gateway_ip=gateway_ip
        )
        print(f"[INFO] Implicit L2 device created: {l2_node}")
    
    # Output Topology
    print("\nDiscovered Network Topology:")
    print(f"Nodes: {topology.number_of_nodes()}")
    print(f"Edges: {topology.number_of_edges()}")

    #Loop Detection
    real_loops = detect_real_loops(topology)
    if real_loops:
        print("\n[WARNING] Real Network Loops Detected:")
        for loop in real_loops:
            print(" -> ".join(loop))
    else:
        print("\n[OK] No real network loops detected")

    topology.graph["real_loops"] = real_loops
    save_topology(topology)
