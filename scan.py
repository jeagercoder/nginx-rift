#!/usr/bin/env python3
"""
CVE-2026-42945 (NGINX Rift) scanner.

  python3 scan.py <target> --listen-ip <host> --listen-port <port>

Target: single IP, CIDR, or range (10.0.0.1-10.0.0.50).
"""

import sys

from scanner.cli import main

if __name__ == "__main__":
    sys.exit(main())
