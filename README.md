# Network Scanner 🛡️

A command-line tool for analyzing hosts on a network using multiple scanning techniques: ICMP echo requests, TCP connect port scanning, and ARP discovery. Built with Python and Scapy for network administrators and security professionals to assess network configurations on networks they are authorized to test.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-41c350)
![License](https://img.shields.io/badge/License-MIT-blue)

## Features

- **ICMP Echo Request (Ping) Scanning** — check host availability with round-trip time measurement
- **TCP Connect Port Scanning** — multithreaded scan that identifies open ports and resolves service names
- **Service Detection (`-sV`)** — banner grabbing on open ports to identify services and versions (SSH, FTP, SMTP, POP3, IMAP, MySQL, …)
- **Web Service Enumeration** — detects HTTP/HTTPS services and extracts the URL, page title, server software and links found on the landing page
- **ARP Network Scanning** — discover live devices and their MAC addresses on a local subnet
- **Configurable scan types and timeouts** — run all scans or pick one with `-t`
- **Port ranges and lists** — `80,443`, `1-1000`, or mixed `22,80,8000-8010`
- **Clean, detailed output** — per-port state, service and banner, RTT, host/MAC tables

## Requirements

- Python 3.10 or higher
- [Scapy](https://scapy.net/) 2.5.0 or higher (packet crafting for ICMP/ARP)
- Root/administrator privileges for ICMP and ARP scans (raw sockets); the TCP scan runs unprivileged

## Installation

```bash
git clone https://github.com/anusshyk/network-scanner.git
cd network-scanner
pip install -r requirements.txt
```

## Usage

```bash
python src/main.py <target> [options]
```

### Examples

```bash
# Scan a single host with all scan types
sudo python src/main.py 192.168.1.1

# ICMP ping only
sudo python src/main.py 192.168.1.1 -t icmp

# Scan specific ports
python src/main.py 192.168.1.1 -t tcp -p 80,443,8080

# Scan a port range
python src/main.py 192.168.1.1 -t tcp -p 1-1000

# Scan with service detection: banners, web titles and links
python src/main.py 192.168.1.1 -t tcp -p 1-1000 -sV

# Discover devices on a subnet via ARP
sudo python src/main.py 192.168.1.0/24 -t arp
```

### Command-line options

| Option | Description |
|---|---|
| `target` | Target IP address or network in CIDR notation (required) |
| `-t, --type` | Scan type: `all`, `icmp`, `tcp`, `arp` (default: `all`) |
| `-p, --ports` | Ports to scan, e.g. `80,443` or `1-1000` (default: common ports) |
| `-T, --timeout` | Timeout in seconds per probe (default: `2`) |
| `-sV, --service-detection` | Grab banners on open ports and enumerate web services (title, server, links) |

### Sample output

```
[*] TCP connect scan on 192.168.1.1: 21 port(s) ...
       PORT  STATE  SERVICE    BANNER
       22/tcp  open   ssh        SSH-2.0-OpenSSH_9.6
       80/tcp  open   http       HTTP/1.1 200 OK (nginx/1.24.0)
[+] scanned 21 port(s) in 1.84s

[*] web service on port 80: http://192.168.1.1/
    title : Router Admin
    server: nginx/1.24.0
    links (3):
      - /login
      - /status
      - /help
```

## Project structure

```
network-scanner/
├── src/
│   ├── main.py         # Command-line interface
│   ├── scanner.py      # Core scanning functionality
│   └── probes.py       # Service detection: banners + web enumeration
├── tests/
│   └── test_scanner.py # Unit tests (run: python -m unittest discover -s tests)
├── requirements.txt    # Project dependencies
├── LICENSE
└── README.md
```

## Running the tests

```bash
python -m unittest discover -s tests -v
```

## Security considerations

- **Authorization required** — scanning is intrusive; use this tool only on networks you own or have explicit written permission to test
- **Network restrictions** — some networks filter ICMP or ARP, so a silent host is not necessarily down
- **Privileges** — ICMP and ARP scans need elevated privileges for raw socket operations
- **Responsible use** — unauthorized scanning may violate laws such as the Computer Fraud and Abuse Act or equivalent legislation in your country

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

Built by [Muhammad Anas Shaikh](https://github.com/anusshyk) — Cybersecurity & IT Infrastructure Specialist
