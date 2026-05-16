#!/usr/bin/env python3
"""
CVE-2026-42945 (NGINX Rift) scanner.

  python3 scan.py <target> -o report.json
  python3 scan.py <target> --listen-ip <host> --listen-port <port>
  python3 scan.py <target> --shell --listen-ip <host> --listen-port <port>
"""

import sys

from scanner.cli import main

if __name__ == "__main__":
    sys.exit(main())
