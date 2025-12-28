import ipaddress
import socket
from urllib.parse import urlparse

# Block these schemes outright
ALLOWED_SCHEMES = {"http", "https"}

# Block obvious localhost hostnames even before DNS resolve
BLOCKED_HOSTS = {"localhost"}

def _is_private_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
    )

def _resolve_host_to_ips(host: str) -> list[str]:
    # Resolve A/AAAA records
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise ValueError("DNS resolution failed")

    ips = []
    for _, _, _, _, sockaddr in infos:
        ips.append(sockaddr[0])
    return list(set(ips))

def validate_outbound_url(raw_url: str) -> None:
    """
    Minimal, defensible SSRF protection for demo purposes:
    - allow only http/https
    - require hostname
    - block localhost hostname
    - DNS resolve host and block if any resolved IP is private/loopback/link-local/etc
    """
    parsed = urlparse(raw_url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError("Blocked scheme (only http/https allowed)")

    if not parsed.hostname:
        raise ValueError("Missing hostname")

    host = parsed.hostname.lower()
    if host in BLOCKED_HOSTS:
        raise ValueError("Blocked host")

    # Block direct IP targets if private
    try:
        ipaddress.ip_address(host)
        if _is_private_ip(host):
            raise ValueError("Blocked private IP")
        return
    except ValueError:
        # Not an IP literal, continue with DNS resolution
        pass

    ips = _resolve_host_to_ips(host)
    if not ips:
        raise ValueError("DNS resolution failed")

    for ip in ips:
        if _is_private_ip(ip):
            raise ValueError(f"Blocked private/reserved IP: {ip}")
