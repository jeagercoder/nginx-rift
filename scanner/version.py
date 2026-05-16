"""Nginx version parsing and CVE-2026-42945 classification."""

from __future__ import annotations

from urllib.parse import urlparse

from scanner.constants import (
    AFFECTED_FLOOR,
    NON_NGINX_SERVER_RE,
    PATCHED_1_30,
    PATCHED_1_31,
    SERVER_PRODUCT_RE,
)
from scanner.models import (
    Classification,
    ConfigRisk,
    ParsedVersion,
    ProbeResult,
    VulnStatus,
)


def parse_version_string(product: str, version: str) -> ParsedVersion:
    parts = version.split(".")
    major = int(parts[0])
    minor = int(parts[1]) if len(parts) > 1 else 0
    patch = int(parts[2]) if len(parts) > 2 else 0
    return ParsedVersion(
        product=product.lower(),
        major=major,
        minor=minor,
        patch=patch,
        raw=version,
    )


def parse_server_header(value: str | None) -> ParsedVersion | None:
    if not value:
        return None
    match = SERVER_PRODUCT_RE.search(value)
    if not match:
        return None
    return parse_version_string(match.group("product"), match.group("version"))


def is_nginx_fork(product: str) -> bool:
    return product.lower() in ("nginx", "openresty", "tengine")


def is_version_affected(ver: ParsedVersion) -> bool:
    if not is_nginx_fork(ver.product):
        return False
    t = ver.tuple
    if t < AFFECTED_FLOOR:
        return False
    if t >= PATCHED_1_31:
        return False
    if ver.major == 1 and ver.minor == 30 and ver.patch >= PATCHED_1_30[2]:
        return False
    return True


def is_definitely_not_nginx(server_headers: list[str]) -> bool:
    for header in server_headers:
        if not header:
            continue
        if SERVER_PRODUCT_RE.search(header):
            return False
        if NON_NGINX_SERVER_RE.search(header):
            return True
    return False


def pick_best_nginx_version(probes: dict[str, ProbeResult]) -> ParsedVersion | None:
    candidates: list[ParsedVersion] = []
    for probe in probes.values():
        parsed = parse_server_header(probe.server_header)
        if parsed and is_nginx_fork(parsed.product):
            candidates.append(parsed)
    if not candidates:
        return None
    return max(candidates, key=lambda v: v.tuple)


def location_adds_query_vs_request(request_path: str, location: str) -> bool:
    if not location:
        return False
    req = urlparse(request_path)
    loc = urlparse(location)
    if loc.query and not req.query:
        return True
    if "?" in location and "?" not in request_path:
        return True
    return False


def _body_has_backend_ok(probe: ProbeResult | None) -> bool:
    if not probe or not probe.ok:
        return False
    return "backend ok" in (probe.body_snippet or "").lower()


def detect_rift_exploit_surface(probes: dict[str, ProbeResult]) -> tuple[bool, list[str]]:
    """
    Detect nginx.conf layout used by the NGINX Rift PoC:
      location ~ ^/api/(.*)$ { rewrite ...?...; set $var $1; }
      location /spray { proxy_pass ...; }
    """
    reasons: list[str] = []
    api = probes.get("api_rewrite")
    spray = probes.get("spray_post")
    api_ok = _body_has_backend_ok(api)
    spray_ok = _body_has_backend_ok(spray)

    if api_ok:
        reasons.append(
            "GET /api/ reaches internal proxy (rewrite+set location from PoC / advisory)"
        )
    if spray_ok:
        reasons.append("POST /spray reaches backend (heap spray location from PoC)")

    if api_ok and spray_ok:
        return True, reasons

    if api_ok:
        reasons.append("spray endpoint not confirmed (partial PoC layout)")
        return True, reasons

    return False, reasons


def assess_config_risk(
    probes: dict[str, ProbeResult],
    probe_path: str | None,
) -> tuple[ConfigRisk, list[str]]:
    reasons: list[str] = []
    risk = ConfigRisk.NONE

    rift_ok, rift_reasons = detect_rift_exploit_surface(probes)
    if rift_ok:
        reasons.extend(rift_reasons)
        risk = ConfigRisk.LIKELY

    for name, probe in probes.items():
        if not probe.ok or not probe.location_header or probe.status_code not in (
            301, 302, 303, 307, 308,
        ):
            continue
        req_path = probe.request_path or "/"
        if location_adds_query_vs_request(req_path, probe.location_header):
            reasons.append(
                f"{name}: redirect Location adds query not in request path "
                f"(rewrite replacement with '?' / is_args pattern)"
            )
            risk = ConfigRisk.SUSPECTED

    if probe_path:
        plus = probes.get("config_path_plus")
        plain = probes.get("config_path_plain")
        if plus and plain and plus.ok and plain.ok:
            plus_len = plus.content_length or len(plus.body_snippet or "")
            plain_len = plain.content_length or len(plain.body_snippet or "")
            status_diff = plus.status_code != plain.status_code
            len_delta = abs(plus_len - plain_len)
            loc_diff = (plus.location_header or "") != (plain.location_header or "")

            if status_diff or loc_diff or len_delta >= 8:
                reasons.append(
                    f"config_path: '+' vs plain on {probe_path!r} diverged "
                    f"(NGX_ESCAPE_ARGS expansion in vulnerable set copy pass)"
                )
                risk = ConfigRisk.LIKELY if (status_diff or loc_diff) else ConfigRisk.SUSPECTED

    if risk == ConfigRisk.NONE:
        reasons.append(
            "no /api/+/spray PoC paths or rewrite+set redirect signal "
            "(version-only; custom configs may still be vulnerable)"
        )

    return risk, reasons


def classify_vulnerability(
    probes: dict[str, ProbeResult],
    probe_path: str | None,
) -> Classification:
    if not any(p.ok for p in probes.values()):
        details = [p.detail for p in probes.values() if p.detail]
        return Classification(
            status=VulnStatus.DOWN,
            config_risk=ConfigRisk.NONE.value,
            reasons=(["no HTTP response"] + details[:3]) if details else ["host:port unreachable"],
        )

    server_headers = [p.server_header for p in probes.values() if p.server_header]
    nginx_ver = pick_best_nginx_version(probes)
    config_risk, config_reasons = assess_config_risk(probes, probe_path)
    rift_surface, rift_reasons = detect_rift_exploit_surface(probes)
    reasons = list(config_reasons)

    if is_definitely_not_nginx(server_headers):
        return Classification(
            status=VulnStatus.NOT_VULNERABLE,
            nginx_detected=False,
            config_risk=ConfigRisk.NONE.value,
            reasons=["Server header indicates non-nginx stack", *reasons],
        )

    if nginx_ver is None:
        if server_headers:
            reasons.insert(0, "HTTP responds but nginx version not disclosed")
        else:
            reasons.insert(0, "HTTP open without Server header")
        return Classification(
            status=VulnStatus.POSSIBLY_VULNERABLE,
            nginx_detected=False,
            config_risk=config_risk.value,
            reasons=reasons,
        )

    version_str = str(nginx_ver)
    banner_affected = is_version_affected(nginx_ver)

    if rift_surface:
        if not banner_affected:
            reasons.insert(
                0,
                f"{nginx_ver.product}/{version_str} banner looks patched, but "
                f"/api/+/spray PoC layout is present (vulnerable rewrite+set config; "
                f"lab builds often report 1.31.0 while still exploitable)",
            )
        else:
            reasons.insert(
                0,
                f"{nginx_ver.product}/{version_str} in CVE range with confirmed "
                f"rewrite+set exploit surface",
            )
        return Classification(
            status=VulnStatus.LIKELY_VULNERABLE,
            nginx_detected=True,
            product=nginx_ver.product,
            version=version_str,
            version_affected=True,
            config_risk=ConfigRisk.LIKELY.value,
            exploit_surface=True,
            reasons=reasons,
        )

    if not banner_affected:
        reasons.insert(
            0,
            f"{nginx_ver.product}/{version_str} patched or outside CVE range "
            f"(fixed 1.30.1+ / 1.31.0+)",
        )
        return Classification(
            status=VulnStatus.NOT_VULNERABLE,
            nginx_detected=True,
            product=nginx_ver.product,
            version=version_str,
            version_affected=False,
            config_risk=config_risk.value,
            reasons=reasons,
        )

    reasons.insert(
        0,
        f"{nginx_ver.product}/{version_str} in CVE-affected range; "
        f"exploit needs rewrite '?'+set $var $capture in same location",
    )

    if config_risk == ConfigRisk.LIKELY:
        status = VulnStatus.LIKELY_VULNERABLE
    elif config_risk == ConfigRisk.SUSPECTED:
        status = VulnStatus.POSSIBLY_VULNERABLE
    else:
        status = VulnStatus.VULNERABLE_VERSION

    return Classification(
        status=status,
        nginx_detected=True,
        product=nginx_ver.product,
        version=version_str,
        version_affected=True,
        config_risk=config_risk.value,
        exploit_surface=False,
        reasons=reasons,
    )


def classification_to_dict(c: Classification) -> dict:
    return {
        "status": c.status.value,
        "nginx_detected": c.nginx_detected,
        "product": c.product,
        "version": c.version,
        "version_affected": c.version_affected,
        "config_risk": c.config_risk,
        "exploit_surface": c.exploit_surface,
        "reasons": c.reasons,
    }
