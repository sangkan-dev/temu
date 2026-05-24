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
- OAST collaborator mode for opt-in blind SSRF, XXE, blind XSS, and log injection callback evidence.
- JSON, HTML, and PDF reports.

## Install

Download a release binary:

```bash
curl -L https://github.com/sangkan-dev/temu/releases/download/v1.3.0/temu-linux-x86_64-static \
  -o temu-linux-x86_64-static
chmod +x temu-linux-x86_64-static
./temu-linux-x86_64-static --help
```

Verify the checksum:

```bash
curl -L https://github.com/sangkan-dev/temu/releases/download/v1.3.0/SHA256SUMS \
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

For an authorized local audit, emit an additional unredacted evidence artifact:

```bash
cargo run -p cli -- scan single \
  --url https://target.example.com \
  --output ./results \
  --include-sensitive-evidence
```

The resulting `*_audit.json` can contain raw secrets or PII and is created with
owner-only permissions on Unix. Keep it local; the normal JSON, HTML, PDF,
SARIF, and Markdown artifacts remain redacted/shareable.

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
cargo run -p cli -- report generate --format sarif --input ./results/2026-05-19_example_com.json
cargo run -p cli -- report generate --format markdown --input ./results/2026-05-19_example_com.json
```

Compare current findings against an earlier baseline:

```bash
cargo run -p cli -- report diff \
  --baseline ./results/previous.json \
  --current ./results/current.json \
  --suppressions ./config/suppressions.example.toml
```

Run a cron-friendly target profile once, or omit `--once` for the local scheduler:

```bash
cargo run -p cli -- schedule run \
  --profile ./config/target-profile.example.toml \
  --once
```

Update CVE cache:

```bash
cargo run -p cli -- cve update
cargo run -p cli -- cve update --cpe cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*
```

CVE findings produced from NVD/CISA/FIRST EPSS are marked `[Metadata only]`.
They explain the fingerprint-to-CPE mapping and priority score, but do not claim
that a vulnerability was actively proven. Active confirmation comes from reviewed
detection rules.

Update local detection rules and dictionaries from a rules-as-code repository:

```bash
cargo run -p cli -- rules update
cargo run -p cli -- rules update \
  --repo-url https://raw.githubusercontent.com/sangkan-dev/temu-rules/main
./temu-linux-x86_64-static rules update \
  --repo-url https://raw.githubusercontent.com/sangkan-dev/temu-rules/main
```

Validate active rules or exercise them against an authorized fixture:

```bash
cargo run -p cli -- rules validate --rules-dir ./rules
cargo run -p cli -- rules checksum --rules-dir ./rules
cargo run -p cli -- rules simulate --rules-dir ./rules \
  --target-fixture http://127.0.0.1:3000/
```

`rules validate` reports effective risk and a confidence score, rejects duplicate
IDs, invalid regexes, excessive timing thresholds, and destructive payloads without
explicit risk/confirmation declarations. `rules simulate` executes only validated
rules; risky or time-based probes remain disabled unless `--allow-risky-rules` is
provided.

Rule authors should use schema v1 with marketplace metadata and compatibility
requirements. See [docs/rule-authoring.md](docs/rule-authoring.md) and
[docs/rule-schema.json](docs/rule-schema.json).

Run an OAST collaborator and scan with callback-aware rules:

```bash
cargo run -p cli -- collaborator serve \
  --bind 127.0.0.1:8788 \
  --public-url https://callback.example \
  --database ./results/.cache/callbacks.sqlite

cargo run -p cli -- scan single \
  --url https://target.example.com \
  --allow-risky-rules \
  --oast-callback-url https://callback.example \
  --oast-db ./results/.cache/callbacks.sqlite \
  --oast-wait-secs 5
```

OAST rules are skipped by default because they rely on out-of-band callbacks and
may be intrusive. Temu injects `{{callback_url}}` with a per-scan correlation ID,
loads matching evidence from SQLite, and records verified callback findings in
the JSON, HTML, and PDF reports.

Discovery modes:

- `hybrid`: passive CT logs, DNS bruteforce, heuristic candidates, and zone transfer checks.
- `passive`: CT logs only.
- `bruteforce`: DNS wordlist mode.
- `heuristic`: generated candidate names only.

## Stateful DAST

The normal scan pipeline also runs a read-only stateful pass after browser/API
discovery. It detects HTML forms, input names/types, CSRF token fields, reflected
GET form input, admin/debug endpoint exposure, IDOR/BOLA signals from bounded
numeric identifier mutation, verbose framework errors, and secrets/PII-like data
in HTML, JavaScript, or source-map responses.

Stateful probes stay same-origin, cap replay volume, reuse the configured session
headers, and avoid POST/write/delete requests. Shareable report evidence is
redacted before JSON, HTML, and PDF output are written. Use
`--include-sensitive-evidence` only when an authorized auditor needs the
additional local `*_audit.json` artifact with exact PoC evidence.

## Reports

Each completed scan writes:

- JSON: redacted machine-readable report suitable for sharing.
- Audit JSON (`--include-sensitive-evidence` only): local raw-evidence source for PoC validation; do not share or upload.
- HTML: analyst-friendly report with summary, target table, asset graph priorities, findings, OAST callback timeline, assets, and tech stack.
- PDF: executive report with cover page, risk overview, vulnerability detail, and recommendations.
- Asset graph JSON: relationship graph with deduplicated findings, attack path hints, and top remediation actions.
- Trend JSON: historical findings, assets, CVE findings, and duration for repeat scans.
- SARIF and Markdown: team-facing integration and remediation artifacts.

Multi-target scans write one report set per target and one aggregate report. Aggregate reports include target summaries sorted by vulnerability count.

## Configuration

Default configuration lives in `config/default.toml`:

```toml
rate_limit = 50
timeout_secs = 10
concurrency = 100
user_agent = "Temu/1.3.0"
output_dir = "./results"
rules_dir = "./rules"
dictionaries_dir = "./dictionaries"
max_recursion_depth = 2
allow_risky_rules = false
oast_wait_secs = 0
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
- `TEMU_OAST_CALLBACK_URL`
- `TEMU_OAST_CORRELATION_ID`
- `TEMU_OAST_DATABASE_PATH`
- `TEMU_OAST_WAIT_SECS`

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

The cron workflow should live in `sangkan-dev/temu-rules`, not in the engine repository. It refreshes upstream Wappalyzer, FingerprintHub, NVD/CISA/Exploit-DB snapshots, and dictionary sources; NVD records become non-executable candidate descriptors under `staging/candidates/` in the generated PR. Only reviewed rules are added to the active manifest. Rules that are intrusive, destructive, or DoS-prone can still be published, but they must declare `risk_level` or `requires_confirmation` so Temu only executes them after explicit user opt-in.

See [docs/rules-repository.md](docs/rules-repository.md) for the recommended repository layout and workflow split.
See [docs/enterprise-workflows.md](docs/enterprise-workflows.md) for profiles, baseline diff, suppressions, SARIF, Markdown, and webhook usage.

## Rule Safety

Rules in `rules/` declare execution risk. `safe` rules run by default. Rules with `risk_level: intrusive`, `risk_level: destructive`, `risk_level: dos`, `requires_confirmation: true`, payloads that look destructive, or OAST placeholders such as `{{callback_url}}` are skipped unless the user enables `--allow-risky-rules` or `TEMU_ALLOW_RISKY_RULES=true`.

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
