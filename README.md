# Temu

*"Nggoleki oyoting masalah, nemokake celahe, ndandani saka dasar."*

Temu is an automated cybersecurity scanner written in Rust. It is built for internal red team and security assessment workflows where the goal is to find root causes, reduce false positives, and produce usable reports.

Temu runs as a CLI and writes all scan output locally. It does not send scan results to any external service.

## Features

- Single-target web scan pipeline: discovery, fingerprinting, fuzzing, vulnerability detection, verification, reporting.
- Multi-target scan from a file list.
- IPv4 CIDR scan with TCP port scanning and banner collection.
- Distributed scanning with Redis-backed workers.
- CVE lookup from NVD/CISA KEV with SQLite cache.
- YAML vulnerability rules with explicit risk levels.
- Rules-as-code updates from a raw GitHub-compatible rules repository.
- Advanced detections for time-based SQL injection, SSRF indicators, path traversal, open redirect, and missing security headers.
- JSON, HTML, and PDF reports.

## Install

Download a release binary:

```bash
curl -L https://github.com/sangkan-dev/temu/releases/download/v1.2.1/temu-linux-x86_64-static \
  -o temu-linux-x86_64-static
chmod +x temu-linux-x86_64-static
./temu-linux-x86_64-static --help
```

Verify the checksum:

```bash
curl -L https://github.com/sangkan-dev/temu/releases/download/v1.2.1/SHA256SUMS \
  -o SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

Available release assets:

- `temu-linux-x86_64-static`
- `temu-macos-arm64`
- `SHA256SUMS`

Build from source:

- Rust stable with edition 2024 support.
- Cargo.

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

When using a downloaded binary, replace `cargo run -p cli --` with the downloaded executable path, for example `./temu-linux-x86_64-static`.

Single target:

```bash
cargo run -p cli -- scan single --url https://target.example.com
./temu-linux-x86_64-static scan single --url https://target.example.com
```

Rules marked as intrusive, destructive, DoS-prone, or requiring explicit confirmation are skipped by default. Enable them only when you accept the target and scanner-side risk:

```bash
./temu-linux-x86_64-static scan single \
  --url https://target.example.com \
  --allow-risky-rules
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

Distributed scan:

```bash
docker compose --profile distributed up -d redis
docker compose --profile distributed up -d --scale temu-worker=3 temu-worker
docker compose --profile distributed run --rm temu-coordinator
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

Update local detection rules and dictionaries from a rules-as-code repository:

```bash
cargo run -p cli -- rules update
cargo run -p cli -- rules update \
  --repo-url https://raw.githubusercontent.com/sangkan-dev/temu-rules/main
./temu-linux-x86_64-static rules update \
  --repo-url https://raw.githubusercontent.com/sangkan-dev/temu-rules/main
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
user_agent = "Temu/1.2.1"
output_dir = "./results"
rules_dir = "./rules"
dictionaries_dir = "./dictionaries"
max_recursion_depth = 2
allow_risky_rules = false
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
- `TEMU_ALLOW_RISKY_RULES`
- `TEMU_RULES_REPO_URL` for `temu rules update`

## Docker

Build the isolated scanner image:

```bash
docker compose build temu
docker compose run --rm temu --help
```

Run local benchmark targets:

```bash
docker compose --profile benchmark up -d juice-shop webgoat dvwa benchmark-nginx benchmark-httpbin
```

The benchmark profile exposes intentionally vulnerable apps on localhost only. See [docs/benchmark.md](docs/benchmark.md) for comparison commands against `nmap`, `ffuf`, and `nuclei`.

## Rules As Code

Temu can keep first-party rules in this repository and consume an external rules repository through `temu rules update`. The remote repository should expose a `rules-manifest.json` at its raw base URL:

```json
{
  "fingerprint": "fingerprint/fingerprint_rules.yaml",
  "vulnerability": ["vulnerability/sql-injection.yaml"],
  "network": ["network/ssh.yaml"],
  "dictionaries": ["dictionaries/paths-small.txt"]
}
```

The cron workflow should live in `sangkan-dev/temu-rules`, not in the engine repository. It refreshes upstream Wappalyzer, FingerprintHub, NVD snapshots, and dictionary sources, promotes low-risk fingerprint and dictionary updates into active files, validates the repository, and opens a pull request. Rules that are intrusive, destructive, or DoS-prone can still be published, but they must declare `risk_level` or `requires_confirmation` so Temu only executes them after explicit user opt-in.

See [docs/rules-repository.md](docs/rules-repository.md) for the recommended repository layout and workflow split.

## Rule Safety

Rules in `rules/` declare execution risk. `safe` rules run by default. Rules with `risk_level: intrusive`, `risk_level: destructive`, `risk_level: dos`, `requires_confirmation: true`, or payloads that look destructive are skipped unless the user enables `--allow-risky-rules` or `TEMU_ALLOW_RISKY_RULES=true`.

Rule authors can use:

```yaml
risk_level: intrusive
requires_confirmation: true
```

Risky rules may modify state, execute heavier probes, or stress a target. Use them only on systems you are authorized to test and when you accept all resulting risk.

Safe bundled rules should still prefer read-only payloads.

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

## Contributing

Use `cargo fmt --all --check`, `cargo clippy --all-targets`, `cargo test --workspace`, and `cargo build` before opening a pull request. New detection rules must be read-only and include references/remediation where applicable.
