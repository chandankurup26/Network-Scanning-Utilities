# Topology-Scanning-Utilities

This project provides a Python-based implementation (`scanner.py`) for discovering network topology in environments that include routers or managed network devices. The script performs automated host discovery and builds a network topology graph by identifying reachable devices and their logical relationships within the network.

It is intended for use in controlled lab or enterprise environments where routing devices are present and accessible, enabling a structured representation of network connectivity for analysis, visualization, or academic study.

## Notes

- This code is currently under development and is recommended to be executed **only on Linux-based environments**. Compatibility with other operating systems has not yet been tested or validated.
- The `topology.json` file included in this repository is a **sample output file** provided for reference and testing purposes.
- The `index.html` file renders a web-based visualization of the discovered network topology. To view it correctly, it must be served via a local HTTP server.
- The `Continous Scanner` directory is a variation of the `scanner.py` file and the corresponding `index.html` that supports continous scanning and a live view of active and inactive devices on a network.

## Viewing the Topology Visualization

To serve the visualization locally, run the following command in the project directory:

```bash
python -m http.server
```

# Nmap-Scanners
A collection of Python-based tools for network scanning, host discovery, port mapping, and service detection.

**scanner1.py** — Python CLI that automates Nmap SYN-ACK, UDP, and comprehensive scans, reporting open ports, protocols, and host status (requires Nmap and python-nmap).

**scanner2.py** — Python script that runs an Nmap ping sweep over a CIDR to discover hosts and collect IPs + MAC addresses (requires Nmap and python-nmap).
