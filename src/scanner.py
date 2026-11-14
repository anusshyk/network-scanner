"""Core scanning functionality for the network scanner.

Provides three scan techniques:
  - ICMP echo request (ping) to check host availability
  - TCP connect scan to find open ports and guess services
  - ARP scan to discover live devices on a local subnet

ICMP and ARP scans craft raw packets with Scapy and therefore need
root/administrator privileges. The TCP scan uses ordinary sockets and
works without elevated privileges.
"""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Iterable

from scapy.all import ARP, ICMP, IP, Ether, sr1, srp  # type: ignore

import probes


@dataclass
class PortResult:
    """Result of probing a single TCP port."""

    port: int
    open: bool
    service: str = ""
    info: "probes.ServiceInfo | None" = None


@dataclass
class HostResult:
    """Aggregated scan results for a single host."""

    address: str
    alive: bool | None = None          # None = ICMP scan not performed
    rtt_ms: float | None = None        # ICMP round-trip time
    mac: str | None = None             # From ARP scan
    ports: list[PortResult] = field(default_factory=list)

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.open]


def icmp_ping(host: str, timeout: float = 2.0) -> HostResult:
    """Send one ICMP echo request and report availability and RTT."""
    result = HostResult(address=host)
    packet = IP(dst=host) / ICMP()
    reply = sr1(packet, timeout=timeout, verbose=0)
    if reply is not None:
        result.alive = True
        result.rtt_ms = round((reply.time - packet.sent_time) * 1000, 2)
    else:
        result.alive = False
    return result


def _probe_port(host: str, port: int, timeout: float) -> PortResult:
    """Attempt a TCP connection to a single port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        is_open = sock.connect_ex((host, port)) == 0
    service = ""
    if is_open:
        try:
            service = socket.getservbyport(port, "tcp")
        except OSError:
            service = "unknown"
    return PortResult(port=port, open=is_open, service=service)


def tcp_scan(
    host: str,
    ports: Iterable[int],
    timeout: float = 2.0,
    max_workers: int = 100,
    detect: bool = False,
) -> HostResult:
    """Scan the given TCP ports concurrently with a connect scan.

    With ``detect=True``, every open port also gets a service-detection
    pass: banner grabbing, and HTTP enumeration (title, server, links)
    for web services.
    """
    result = HostResult(address=host)
    ports = list(ports)
    with ThreadPoolExecutor(max_workers=min(max_workers, max(len(ports), 1))) as pool:
        futures = {pool.submit(_probe_port, host, p, timeout): p for p in ports}
        for future in as_completed(futures):
            result.ports.append(future.result())
    result.ports.sort(key=lambda p: p.port)

    if detect and result.open_ports:
        with ThreadPoolExecutor(max_workers=min(16, len(result.open_ports))) as pool:
            futures = {
                pool.submit(probes.detect_service, host, p.port, timeout): p
                for p in result.open_ports
            }
            for future in as_completed(futures):
                port_result = futures[future]
                port_result.info = future.result()
                if port_result.info.protocol:
                    port_result.service = port_result.info.protocol
    return result


def arp_scan(network: str, timeout: float = 2.0) -> list[HostResult]:
    """Discover live hosts on a local subnet via ARP who-has requests."""
    # Validate the target network before putting it on the wire.
    ipaddress.ip_network(network, strict=False)
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    answered, _ = srp(packet, timeout=timeout, verbose=0)
    hosts = [
        HostResult(address=reply.psrc, alive=True, mac=reply.hwsrc)
        for _, reply in answered
    ]
    hosts.sort(key=lambda h: ipaddress.ip_address(h.address))
    return hosts


def parse_ports(spec: str) -> list[int]:
    """Parse a port specification like '80,443' or '1-1000' into a list.

    Accepts comma-separated ports and inclusive ranges, mixed freely:
    '22,80,8000-8010'. Raises ValueError for malformed input.
    """
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_s, _, end_s = chunk.partition("-")
            start, end = int(start_s), int(end_s)
            if not (0 < start <= end <= 65535):
                raise ValueError(f"invalid port range: {chunk!r}")
            ports.update(range(start, end + 1))
        else:
            port = int(chunk)
            if not 0 < port <= 65535:
                raise ValueError(f"invalid port: {chunk!r}")
            ports.add(port)
    if not ports:
        raise ValueError("no ports given")
    return sorted(ports)


DEFAULT_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 1723, 3306, 3389, 5900, 8080, 8443,
]
