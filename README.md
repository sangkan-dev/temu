# Temu

*"Nggoleki oyoting masalah, nemokake celahe, ndandani saka dasar."*

Temu is an automated cybersecurity scanner written in Rust. It is built for internal red team and security assessment workflows where the goal is to find root causes, reduce false positives, and produce usable reports.

Temu runs as a CLI and writes all scan output locally. It does not send scan results to any external service.

## Features

- Single-target web scan pipeline: discovery, fingerprinting, fuzzing, vulnerability detection, verification, reporting.
- Multi-target scan from a file list.
- IPv4 CIDR scan with TCP port scanning and banner collection.
- CVE lookup from NVD/CISA KEV with SQLite cache.
- YAML vulnerability rules with read-only payloads.
- Advanced detections for time-based SQL injection, SSRF indicators, path traversal, open redirect, and missing security headers.
- JSON, HTML, and PDF reports.

## Install

Requirements:

- Rust stable with edition 2024 support.
- Cargo.

Build:

```bash
cargo build
cargo build --release
```

Run all checks:

```bash
cargo fmt --all --check
cargo clippy --all-targets
cargo test --workspace
cargo build
```

## Usage

Single target:

```bash
cargo run -p cli -- scan single --url https://target.example.com
```

Single target with options:

```bash
cargo run -p cli -- scan single \
  --url https://target.example.com \
  --mode hybrid \
  --rate 30 \
  --timeout 10 \
  --ports 80,443,8080 \
  --output ./results \
  --verbose
```

Scan from a file:

```bash
cargo run -p cli -- scan file --list targets.txt
```

`targets.txt` format:

```text
# one URL per line
https://app.example.com
https://api.example.com
```

Network scan:

```bash
cargo run -p cli -- scan network --cidr 192.168.1.0/24 --ports 80,443,8080
```

Generate a report from an existing JSON result:

```bash
cargo run -p cli -- report generate --format json --input ./results/2026-05-19_example_com.json
cargo run -p cli -- report generate --format html --input ./results/2026-05-19_example_com.json
cargo run -p cli -- report generate --format pdf --input ./results/2026-05-19_example_com.json
```

Update CVE cache:

```bash
cargo run -p cli -- cve update
cargo run -p cli -- cve update --cpe cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*
```

Discovery modes:

- `hybrid`: passive CT logs, DNS bruteforce, heuristic candidates, and zone transfer checks.
- `passive`: CT logs only.
- `bruteforce`: DNS wordlist mode.
- `heuristic`: generated candidate names only.

## Reports

Each completed scan writes:

- JSON: machine-readable source of truth.
- HTML: analyst-friendly report with summary, target table, findings, assets, and tech stack.
- PDF: executive report with cover page, risk overview, vulnerability detail, and recommendations.

Multi-target scans write one report set per target and one aggregate report. Aggregate reports include target summaries sorted by vulnerability count.

## Configuration

Default configuration lives in `config/default.toml`:

```toml
rate_limit = 50
timeout_secs = 10
concurrency = 100
user_agent = "Temu/0.1.0"
output_dir = "./results"
rules_dir = "./rules"
dictionaries_dir = "./dictionaries"
max_recursion_depth = 2
```

Environment overrides:

- `TEMU_RATE_LIMIT`
- `TEMU_TIMEOUT_SECS`
- `TEMU_CONCURRENCY`
- `TEMU_USER_AGENT`
- `TEMU_OUTPUT_DIR`
- `TEMU_RULES_DIR`
- `TEMU_DICTIONARIES_DIR`
- `TEMU_MAX_RECURSION_DEPTH`

## Rule Safety

Rules in `rules/` must use read-only payloads. Do not add payloads that modify data, execute commands, create files, start outbound callbacks, or intentionally deny service.

Allowed examples include:

- SQLi timing probes such as `SLEEP`, `pg_sleep`, or `WAITFOR DELAY`.
- Benign reflection markers.
- Safe path traversal reads for known static files.
- Header or status checks.

See [rules/SAFE_PAYLOAD_GUIDELINES.md](rules/SAFE_PAYLOAD_GUIDELINES.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## Project Layout

```text
crates/
  core/           shared types, config, errors, logging
  discovery/      DNS, CT logs, HTTP probe, TCP port scan
  fingerprint/    technology detection
  fuzzing/        path, parameter, recursive fuzzing
  vulnerability/  YAML rules and built-in checks
  cve_client/     NVD/CISA KEV cache
  verifier/       false-positive reduction
  reporter/       JSON, HTML, PDF reports
  cli/            CLI and orchestration
rules/            vulnerability and fingerprint rules
dictionaries/     wordlists
templates/        HTML report templates
results/          local output, gitignored
```

## Security Scope

Only scan systems you are authorized to assess. Temu has conservative defaults, but it still sends network traffic, probes paths, checks parameters, and may trigger application logging or security alerts.
