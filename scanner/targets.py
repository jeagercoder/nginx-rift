"""IP range parsing and target expansion."""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable

_LISTEN_HOST_RE = re.compile(
    r"^(?=.{1,253}$)"  # total length
    r"(?!-)"  # no leading hyphen on full string (single-label)
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


def parse_ip_range(spec: str) -> list[ipaddress.IPv4Address]:
    """
    Parse IPv4 range: CIDR (10.0.0.0/24), inclusive range (10.0.0.1-10.0.0.50),
    or single address (192.168.1.1).
    """
    spec = spec.strip()
    if not spec:
        raise ValueError("IP range must not be empty")

    if "-" in spec and "/" not in spec:
        start_s, end_s = spec.split("-", 1)
        start = ipaddress.IPv4Address(start_s.strip())
        end = ipaddress.IPv4Address(end_s.strip())
        if int(end) < int(start):
            raise ValueError(f"invalid range: end < start ({spec})")
        return [
            ipaddress.IPv4Address(addr)
            for addr in range(int(start), int(end) + 1)
        ]

    if "/" in spec:
        network = ipaddress.ip_network(spec, strict=False)
        if network.version != 4:
            raise ValueError(f"only IPv4 supported: {spec}")
        if network.num_addresses > 2:
            return list(network.hosts())
        return [ipaddress.IPv4Address(network.network_address)]

    return [ipaddress.IPv4Address(spec)]


def parse_ports(value: str) -> tuple[int, ...]:
    ports: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        port = int(part)
        if not 1 <= port <= 65535:
            raise ValueError(f"port out of range: {port}")
        ports.append(port)
    if not ports:
        raise ValueError("no ports specified")
    return tuple(ports)


def expand_targets(
    addresses: Iterable[ipaddress.IPv4Address],
    ports: Iterable[int],
) -> list[tuple[str, int]]:
    return [(str(addr), port) for addr in addresses for port in ports]


def validate_listen_host(host: str) -> str:
    """
    Accept IPv4 or hostname for reverse-shell callback (e.g. host.docker.internal).
    """
    host = host.strip()
    if not host:
        raise ValueError("listen host must not be empty")
    try:
        ipaddress.IPv4Address(host)
        return host
    except ipaddress.AddressValueError:
        pass
    if _LISTEN_HOST_RE.match(host):
        return host
    raise ValueError(
        f"invalid --listen-ip: {host!r} (use IPv4 or hostname, e.g. host.docker.internal)"
    )
