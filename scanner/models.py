"""Data models for scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from scanner.constants import CVE_ID, DEFAULT_CONNECT_TIMEOUT


class VulnStatus(str, Enum):
    DOWN = "down"
    NOT_VULNERABLE = "not_vulnerable"
    VULNERABLE_VERSION = "vulnerable_version"
    POSSIBLY_VULNERABLE = "possibly_vulnerable"
    LIKELY_VULNERABLE = "likely_vulnerable"
    CONFIRMED_VULNERABLE = "confirmed_vulnerable"
    ERROR = "error"


VULNERABLE_STATUSES = frozenset({
    VulnStatus.VULNERABLE_VERSION.value,
    VulnStatus.POSSIBLY_VULNERABLE.value,
    VulnStatus.LIKELY_VULNERABLE.value,
    VulnStatus.CONFIRMED_VULNERABLE.value,
})

STATUSES_ELIGIBLE_FOR_EXPLOIT = VULNERABLE_STATUSES


class ConfigRisk(str, Enum):
    NONE = "none"
    UNKNOWN = "unknown"
    SUSPECTED = "suspected"
    LIKELY = "likely"


@dataclass(frozen=True)
class ParsedVersion:
    product: str
    major: int
    minor: int
    patch: int
    raw: str

    @property
    def tuple(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    def __str__(self) -> str:
        if self.patch:
            return f"{self.major}.{self.minor}.{self.patch}"
        return f"{self.major}.{self.minor}"


@dataclass
class ProbeResult:
    ok: bool = False
    status_code: int | None = None
    server_header: str | None = None
    location_header: str | None = None
    content_length: int | None = None
    request_path: str | None = None
    body_snippet: str | None = None
    detail: str | None = None


@dataclass
class Classification:
    status: VulnStatus
    nginx_detected: bool = False
    product: str | None = None
    version: str | None = None
    version_affected: bool | None = None
    config_risk: str = ConfigRisk.UNKNOWN.value
    exploit_surface: bool = False
    reasons: list[str] = field(default_factory=list)


@dataclass
class HostScanResult:
    ip: str
    port: int
    status: str
    open: bool = False
    latency_ms: float | None = None
    probes: dict[str, dict] = field(default_factory=dict)
    classification: dict = field(default_factory=dict)
    exploit: dict = field(default_factory=dict)
    error: str | None = None
    scanned_at: str = ""


@dataclass
class ScanConfig:
    ip_range: str
    ports: tuple[int, ...]
    threads: int = 50
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT
    read_timeout: float = 5.0
    probe_path: str | None = None
    output: str = "scan_report.json"
    quiet: bool = False
    verbose: bool = False
    log_file: str | None = None
    exploit_validate: bool = False
    shell: bool = False
    interactive_shell: bool = False
    listen_ip: str = ""
    listen_port: int = 0
    exploit_port: int | None = None
    exploit_tries: int = 5
    exploit_max_offsets: int = 5
    shell_wait: float = 12.0
    validate_all_open: bool = False

    @property
    def cve_id(self) -> str:
        return CVE_ID
