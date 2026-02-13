import time
from scapy.all import ARP, Ether, srp
from scrapli import Scrapli
import re, netifaces, ipaddress
import networkx as nx
import json, socket, manuf
from networkx.readwrite import json_graph

ROUTER_MODE = False
SCRAPLI_BASE = {
    "auth_username": "admin",
    "auth_password": "password",
    "auth_strict_key": False,
    "platform": "cisco_iosxe",
    "timeout_socket": 10
}

visited = set()
to_visit = set()
topology = nx.Graph()

def network_scan(network):
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast/arp_request
    answered, _ = srp(packet, timeout=5, verbose=False) # Reduced timeout for faster loops
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
    try:
        with Scrapli(**device) as conn:
            neighbors.update(re.findall(r"IP address: (\S+)", conn.send_command("show cdp neighbors detail").result))
            neighbors.update(re.findall(r"Management Address: (\S+)", conn.send_command("show lldp neighbors detail").result))
    except:
        pass
    return neighbors

def is_router_present(devices):
    for ip in devices:
        try:
            sock = socket.create_connection((ip, 22), timeout=1)
            sock.close()
            device = SCRAPLI_BASE.copy()
            device["host"] = ip
            with Scrapli(**device) as conn:
                output = conn.send_command("show cdp neighbors detail").result
                if "Device ID" in output or "IP address" in output:
                    return True
        except:
            continue
    return False

def get_interface_type(interface):
    if interface.startswith(("wl", "wlan", "wifi")): return "wifi"
    elif interface.startswith(("en", "eth", "eno", "ens")): return "ethernet"
    return "unknown"

def guess_remote_link_type(mac):
    if not mac: return "unknown"
    mobile_ouis = ("Apple", "Samsung", "Xiaomi", "Huawei", "OnePlus", "Motorola", "Realtek")
    try:
        parser = manuf.MacParser()
        vendor = parser.get_manuf(mac)
        if vendor and any(v in vendor for v in mobile_ouis): return "wifi"
    except: pass
    return "ethernet"

def add_implicit_l2_device(topology, devices, gateway_ip=None):
    l2_node_id = "L2_SWITCH_AP"
    topology.add_node(l2_node_id, role="implicit-l2", discovered_by="inference", status="online")
    for ip in devices:
        topology.add_edge(l2_node_id, ip, relation="logical-L2")
    if gateway_ip:
        topology.add_edge(l2_node_id, gateway_ip, relation="uplink")
    return l2_node_id

def save_topology(graph, filename="topology.json"):
    data = json_graph.node_link_data(graph)
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

def detect_real_loops(graph):
    try:
        cycles = nx.cycle_basis(graph)
        real_loops = []
        for cycle in cycles:
            infra_nodes = [n for n in cycle if graph.nodes[n].get("role") in ("router", "implicit-l2")]
            if len(infra_nodes) > 1: real_loops.append(cycle)
        return real_loops
    except: return []

if __name__ == "__main__":
    print("Starting continuous network scan... (Ctrl+C to stop)")
    while True:
        try:
            gws = netifaces.gateways()
            gateway_info = gws['default'][netifaces.AF_INET]
            gateway_ip, interface = gateway_info[0], gateway_info[1]
            iface_data = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
            network = ipaddress.IPv4Interface(f"{gateway_ip}/{iface_data['netmask']}").network
            subnet = str(network)
            local_iface_type = get_interface_type(interface)

            # Step 1: Current Scan
            current_devices = network_scan(subnet)
            live_ips = [d["ip"] for d in current_devices]
            mac_map = {d["ip"]: d["mac"] for d in current_devices}

            # Update status for existing nodes
            for node in topology.nodes:
                topology.nodes[node]["status"] = "offline"

            # Always ensure gateway is marked correctly
            topology.add_node(gateway_ip, role="gateway", connection_type=local_iface_type, status="online")

            for ip in live_ips:
                topology.add_node(
                    ip, 
                    discovered_by="arp",
                    connection_type=guess_remote_link_type(mac_map.get(ip)),
                    mac_address=mac_map.get(ip),
                    status="online"
                )

            ROUTER_MODE = is_router_present(live_ips)
            if ROUTER_MODE:
                to_visit.update(live_ips)
                while to_visit:
                    ip = to_visit.pop()
                    if ip in visited: continue
                    visited.add(ip)
                    neighbors = discover_neighbors(ip)
                    for neighbor in neighbors:
                        topology.add_node(neighbor, discovered_by="cdp/lldp", status="online")
                        topology.add_edge(ip, neighbor, relation="L3/L2")
            else:
                l2_node = add_implicit_l2_device(topology, live_ips, gateway_ip)

            topology.graph["real_loops"] = detect_real_loops(topology)
            save_topology(topology)
            print(f"Scan complete. Found {len(live_ips)} online devices. Sleeping 30s...")
            time.sleep(30)

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Loop Error: {e}")
            time.sleep(10)