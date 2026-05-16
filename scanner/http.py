"""HTTP probing for passive fingerprinting."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from scanner.constants import MAX_RESPONSE_BYTES
from scanner.models import ProbeResult


def open_connection(host: str, port: int, connect_timeout: float) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=connect_timeout)
    if port == 443:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(sock, server_hostname=host)
    return sock


def recv_http_response(sock: socket.socket, timeout: float) -> bytes:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    total = 0
    while total < MAX_RESPONSE_BYTES:
        try:
            data = sock.recv(4096)
        except socket.timeout:
            break
        if not data:
            break
        chunks.append(data)
        total += len(data)
    return b"".join(chunks)


def http_probe(
    host: str,
    port: int,
    request: bytes,
    request_path: str,
    connect_timeout: float,
    read_timeout: float,
) -> tuple[bool, ProbeResult, float | None]:
    started = datetime.now(timezone.utc)
    result = ProbeResult(request_path=request_path)
    sock: socket.socket | None = None
    try:
        sock = open_connection(host, port, connect_timeout)
        sock.sendall(request)
        raw = recv_http_response(sock, read_timeout)
    except OSError as exc:
        result.detail = str(exc)
        return False, result, None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    elapsed_ms = (datetime.now(timezone.utc) - started).total_seconds() * 1000
    if not raw:
        result.detail = "empty response"
        return True, result, elapsed_ms

    head, _, body = raw.partition(b"\r\n\r\n")
    head_text = head.decode("latin-1", errors="replace")
    body_text = body.decode("latin-1", errors="replace")

    status_line = head_text.split("\r\n", 1)[0] if head_text else ""
    parts = status_line.split()
    if len(parts) >= 2 and parts[1].isdigit():
        result.status_code = int(parts[1])

    for line in head_text.split("\r\n")[1:]:
        lower = line.lower()
        if lower.startswith("server:"):
            result.server_header = line.split(":", 1)[1].strip()
        elif lower.startswith("location:"):
            result.location_header = line.split(":", 1)[1].strip()
        elif lower.startswith("content-length:"):
            try:
                result.content_length = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass

    result.body_snippet = body_text[:300] if body_text else ""
    result.ok = result.status_code is not None and 100 <= result.status_code < 600
    return True, result, elapsed_ms


def build_requests(host: str, probe_path: str | None) -> dict[str, tuple[bytes, str]]:
    nonce = "cve202642945"
    host_hdr = host if host.isascii() else "scan"

    out: dict[str, tuple[bytes, str]] = {
        "get_root": (
            (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host_hdr}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode(),
            "/",
        ),
        "get_404": (
            (
                f"GET /{nonce}-not-found HTTP/1.1\r\n"
                f"Host: {host_hdr}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode(),
            f"/{nonce}-not-found",
        ),
        "api_rewrite": (
            (
                f"GET /api/{nonce}-probe HTTP/1.1\r\n"
                f"Host: {host_hdr}\r\n"
                f"X-Delay: 0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode(),
            f"/api/{nonce}-probe",
        ),
        "spray_post": (
            (
                f"POST /spray HTTP/1.1\r\n"
                f"Host: {host_hdr}\r\n"
                f"Content-Length: 4\r\n"
                f"X-Delay: 0\r\n"
                f"Connection: close\r\n\r\n"
                f"ping"
            ).encode(),
            "/spray",
        ),
    }

    if probe_path:
        path_plus = probe_path.rstrip("/") + "/" + ("+" * 24)
        path_plain = probe_path.rstrip("/") + "/" + ("x" * 24)
        out["config_path_plus"] = (
            (
                f"GET {path_plus} HTTP/1.1\r\n"
                f"Host: {host_hdr}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode(),
            path_plus,
        )
        out["config_path_plain"] = (
            (
                f"GET {path_plain} HTTP/1.1\r\n"
                f"Host: {host_hdr}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode(),
            path_plain,
        )

    return out


def probe_to_dict(probe: ProbeResult) -> dict:
    return {
        "ok": probe.ok,
        "status_code": probe.status_code,
        "server_header": probe.server_header,
        "location_header": probe.location_header,
        "content_length": probe.content_length,
        "request_path": probe.request_path,
        "body_snippet": probe.body_snippet,
        "detail": probe.detail,
    }
