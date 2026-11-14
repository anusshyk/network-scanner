"""Service-detection probes: banner grabbing and HTTP enumeration.

For an open TCP port this module tries, in order:
  1. Passive banner grab - many services (SSH, FTP, SMTP, POP3, IMAP,
     MySQL) announce themselves as soon as a client connects.
  2. HTTP probe - if no banner arrives, or the port is a known web port,
     send a GET request (TLS-wrapped for HTTPS ports) and extract the
     status line, Server header, page title and links on the page.

Everything uses only the Python standard library.
"""

from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass, field

# Ports that get the HTTP probe even when a passive banner shows up.
HTTP_PORTS = {80, 81, 591, 2082, 2086, 3000, 5000, 8000, 8008, 8080, 8081, 8888}
HTTPS_PORTS = {443, 2083, 2087, 8443, 9443}

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_HREF_RE = re.compile(rb"""href\s*=\s*["']([^"'#][^"']*)["']""", re.IGNORECASE)
_SERVER_RE = re.compile(rb"^server:\s*(.+?)\r?$", re.IGNORECASE | re.MULTILINE)
_STATUS_RE = re.compile(rb"^HTTP/[\d.]+\s+(\d{3}[^\r\n]*)")


@dataclass
class ServiceInfo:
    """Details learned about a service on an open port."""

    banner: str = ""          # Raw banner or HTTP status + server line
    protocol: str = ""        # e.g. "ssh", "http", "https", "ftp"
    url: str = ""             # For web services
    title: str = ""           # HTML <title> of the landing page
    server: str = ""          # HTTP Server header
    links: list[str] = field(default_factory=list)


def _clean(data: bytes, limit: int = 120) -> str:
    text = data.decode("utf-8", errors="replace")
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    return " ".join(text.split())[:limit]


def _guess_protocol(banner: str, port: int) -> str:
    low = banner.lower()
    if low.startswith("ssh-"):
        return "ssh"
    if low.startswith("220") and ("ftp" in low or port == 21):
        return "ftp"
    if low.startswith("220") and (port in (25, 587) or "smtp" in low or "esmtp" in low):
        return "smtp"
    if low.startswith("+ok"):
        return "pop3"
    if low.startswith("* ok"):
        return "imap"
    if port == 3306 or "mysql" in low or "mariadb" in low:
        return "mysql"
    return ""


def passive_banner(host: str, port: int, timeout: float) -> str:
    """Connect and wait briefly for the server to speak first."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(1024)
            except socket.timeout:
                return ""
            return _clean(data)
    except OSError:
        return ""


def http_probe(host: str, port: int, timeout: float, use_tls: bool, max_links: int = 10) -> ServiceInfo | None:
    """Send a GET request and extract status, server, title and links."""
    info = ServiceInfo(protocol="https" if use_tls else "http")
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return None
    try:
        sock = raw
        if use_tls:
            ctx = ssl.create_default_context()
            # Scanning by IP: certificate name checks would always fail.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=host)
        sock.settimeout(timeout)
        request = (
            f"GET / HTTP/1.1\r\nHost: {host}\r\n"
            "User-Agent: network-scanner\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        )
        sock.sendall(request.encode())
        chunks: list[bytes] = []
        total = 0
        while total < 65536:
            try:
                chunk = sock.recv(4096)
            except (socket.timeout, OSError):
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        response = b"".join(chunks)
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if not response.startswith(b"HTTP/"):
        return None

    status = _STATUS_RE.match(response)
    server = _SERVER_RE.search(response.split(b"\r\n\r\n", 1)[0])
    title = _TITLE_RE.search(response)

    default_port = 443 if use_tls else 80
    host_part = host if port == default_port else f"{host}:{port}"
    info.url = f"{info.protocol}://{host_part}/"
    if status:
        info.banner = _clean(status.group(0))
    if server:
        info.server = _clean(server.group(1))
        info.banner = f"{info.banner} ({info.server})" if info.banner else info.server
    if title:
        info.title = _clean(title.group(1), limit=80)

    seen: list[str] = []
    for match in _HREF_RE.finditer(response):
        link = _clean(match.group(1), limit=200)
        if link.startswith(("javascript:", "mailto:", "data:")):
            continue
        if link not in seen:
            seen.append(link)
        if len(seen) >= max_links:
            break
    info.links = seen
    return info


def detect_service(host: str, port: int, timeout: float) -> ServiceInfo:
    """Full detection for one open port: banner first, then HTTP."""
    if port in HTTPS_PORTS:
        web = http_probe(host, port, timeout, use_tls=True)
        if web:
            return web

    banner = "" if port in HTTP_PORTS else passive_banner(host, port, timeout)
    if banner:
        return ServiceInfo(banner=banner, protocol=_guess_protocol(banner, port))

    web = http_probe(host, port, timeout, use_tls=False)
    if web:
        return web
    if port in HTTPS_PORTS:
        return ServiceInfo()
    web = http_probe(host, port, timeout, use_tls=True)
    return web if web else ServiceInfo()
