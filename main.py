#!/usr/bin/env python3
"""Command-line interface for the network scanner.

Examples:
    python src/main.py 192.168.1.1
    python src/main.py 192.168.1.1 -t icmp
    python src/main.py 192.168.1.1 -p 80,443,8080
    python src/main.py 192.168.1.1 -p 1-1000
    python src/main.py 192.168.1.0/24 -t arp
"""

from __future__ import annotations

import argparse
import os
import sys
import time

import scanner


BANNER = r"""
  _  _     _                  _     ___
 | \| |___| |___ __ _____ _ _| |__ / __| __ __ _ _ _  _ _  ___ _ _
 | .` / -_)  _\ V  V / _ \ '_| / / \__ \/ _/ _` | ' \| ' \/ -_) '_|
 |_|\_\___|\__|\_/\_/\___/_| |_\_\ |___/\__\__,_|_||_|_||_\___|_|
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network-scanner",
        description="Analyze hosts on a network with ICMP, TCP and ARP scans.",
        epilog="Use only on networks you own or have explicit permission to scan.",
    )
    parser.add_argument("target", help="target IP address or network (e.g. 192.168.1.1 or 192.168.1.0/24)")
    parser.add_argument(
        "-t", "--type",
        choices=["all", "icmp", "tcp", "arp"],
        default="all",
        help="type of scan to perform (default: all)",
    )
    parser.add_argument(
        "-p", "--ports",
        help="ports to scan, e.g. 80,443 or 1-1000 (default: common ports)",
    )
    parser.add_argument(
        "-T", "--timeout",
        type=float,
        default=2.0,
        help="timeout in seconds for each probe (default: 2)",
    )
    parser.add_argument(
        "-sV", "--service-detection",
        action="store_true",
        help="grab banners on open ports and enumerate web services (title, server, links)",
    )
    return parser


def require_root(scan_name: str) -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sys.exit(f"[!] {scan_name} scan needs raw sockets - run with sudo/administrator privileges.")


def run_icmp(target: str, timeout: float) -> None:
    require_root("ICMP")
    print(f"[*] ICMP ping {target} ...")
    result = scanner.icmp_ping(target, timeout=timeout)
    if result.alive:
        print(f"[+] {target} is up  (rtt {result.rtt_ms} ms)")
    else:
        print(f"[-] {target} did not reply (down or filtering ICMP)")


def run_tcp(target: str, ports_spec: str | None, timeout: float, detect: bool) -> None:
    ports = scanner.parse_ports(ports_spec) if ports_spec else scanner.DEFAULT_PORTS
    print(f"[*] TCP connect scan on {target}: {len(ports)} port(s) ...")
    started = time.perf_counter()
    result = scanner.tcp_scan(target, ports, timeout=timeout, detect=detect)
    elapsed = time.perf_counter() - started
    if result.open_ports:
        print(f"    {'PORT':>7}  {'STATE':<6} {'SERVICE':<10} BANNER")
        for port in result.open_ports:
            banner = port.info.banner if port.info else ""
            print(f"    {port.port:>5}/tcp  {'open':<6} {port.service:<10} {banner}")
    else:
        print("    no open ports found")
    print(f"[+] scanned {len(ports)} port(s) in {elapsed:.2f}s")

    if detect:
        for port in result.open_ports:
            info = port.info
            if info and info.url:
                print(f"\n[*] web service on port {port.port}: {info.url}")
                if info.title:
                    print(f"    title : {info.title}")
                if info.server:
                    print(f"    server: {info.server}")
                if info.links:
                    print(f"    links ({len(info.links)}):")
                    for link in info.links:
                        print(f"      - {link}")


def run_arp(target: str, timeout: float) -> None:
    require_root("ARP")
    print(f"[*] ARP scan on {target} ...")
    hosts = scanner.arp_scan(target, timeout=timeout)
    if hosts:
        print(f"    {'IP ADDRESS':<16} MAC ADDRESS")
        for host in hosts:
            print(f"    {host.address:<16} {host.mac}")
        print(f"[+] {len(hosts)} host(s) up")
    else:
        print("    no hosts responded")


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    print(BANNER)
    print(f"    target: {args.target}   scan: {args.type}   timeout: {args.timeout}s\n")

    try:
        if args.type in ("all", "icmp"):
            run_icmp(args.target, args.timeout)
        if args.type in ("all", "tcp"):
            run_tcp(args.target, args.ports, args.timeout, args.service_detection)
        if args.type == "arp":
            run_arp(args.target, args.timeout)
        elif args.type == "all" and "/" in args.target:
            run_arp(args.target, args.timeout)
    except ValueError as exc:
        sys.exit(f"[!] {exc}")
    except KeyboardInterrupt:
        sys.exit("\n[!] scan interrupted")


if __name__ == "__main__":
    main()
