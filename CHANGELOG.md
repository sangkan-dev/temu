# Changelog

All notable changes to Temu will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.5.0] — 2026-05-25

Feature release expanding Temu into protocol-aware network service assessment.

### Added

- Protocol-aware TCP profiling for SSH, mail, database, broker, cache, remote-management, and HTTP-family services, including services observed on non-standard ports.
- Structured network service evidence with protocol, product/version, confidence, sanitized handshake, authentication signal, and TLS response metadata.
- Separate `rule_type: network` schema and safe evidence matchers for service checks, with bundled Redis unauthenticated-access and Memcached exposure rules.
- Per-host network connection and time budgets to bound protocol enumeration activity.

### Changed

- JSON, HTML, and PDF reports now include service evidence, with banner and handshake content redacted for shareable artifacts.
- Network scans can produce verified service findings without routing TCP checks through the HTTP vulnerability executor.

## [1.4.0] — 2026-05-24

Feature release for advanced discovery, rule extensibility, and repeatable audit workflows.

### Added

- Browser-aware SPA discovery with optional browser network capture, API surface discovery, authenticated session profiles, and a realtime WebSocket dashboard foundation.
- CVE intelligence rule candidate pipeline, read-only stateful DAST heuristics, OAST collaborator mode, and rule SDK/bundle metadata validation.
- Asset graph prioritization, scheduled target profiles, baseline diff with suppressions, scan trend history, SARIF output, Markdown remediation summaries, and optional webhook notifications.
- Opt-in `--include-sensitive-evidence` local audit JSON output for exact PoC validation while regular reports remain suitable for sharing.

### Changed

- Shareable JSON, HTML, and PDF reports retain sensitive evidence locators while redacting only secret/PII values, for example `Password="<REDACTED>"`.
- Stateful DAST stays within origin scope, reduces JavaScript numeric false positives, and distinguishes framework placeholders from hardcoded credential evidence.

### Notes

- Audit JSON artifacts may contain raw secrets or PII; Temu writes them with owner-only permissions on Unix and operators must keep them local.
- Version-based NVD findings still require an observed software version that can be mapped to a CPE.

## [1.3.0] — 2026-05-21

Feature release for CVE metadata integration in the scan pipeline.

### Added

- Scan runs now execute CVE metadata checks after fingerprinting, using detected versioned technologies, CPE mapping, the local SQLite CVE cache, and NVD fetches on cache miss.
- CVE cache/NVD matches are merged into scan vulnerabilities as version-related findings.

### Notes

- CVE metadata findings require a detected technology version that can be mapped to a CPE. Targets without exposed versions, such as OWASP Juice Shop in default mode, will not produce NVD findings from metadata alone.
- CVE-specific YAML probes remain separate active detection rules and still depend on matching technology fingerprints and risk policy.

## [1.2.1] — 2026-05-20

Patch release for vulnerability detection precision.

### Fixed

- `StatusCode` verification now honors optional body and header matchers, preventing SPA fallback pages from being reported as exposed files.
- Root-relative path probes such as `/.env` and `/metrics` now execute once against the origin root instead of being appended to every discovered path.
- Query-parameter rules now skip URLs without parameters unless the rule declares an explicit `injection_name`.
- Security-header findings are reported once for the root URL asset instead of repeated for every discovered path.
- Tightened Windows path traversal and SSRF regexes to avoid matching normal `security.txt` content.

## [1.2.0] — 2026-05-20

Feature release for risk-aware rules and expanded rules-as-code automation.

### Added

- Added `risk_level` and `requires_confirmation` metadata for vulnerability rules.
- Added `--allow-risky-rules` and `TEMU_ALLOW_RISKY_RULES=true` opt-in controls for intrusive, destructive, or DoS-prone rules.
- Added bundled OWASP Juice Shop, Angular Material, and exposed Prometheus metrics detection coverage.
- Expanded `temu-rules` automation to promote low-risk upstream fingerprint and dictionary updates into active rule files.

### Changed

- Risky rules are loaded but skipped by default unless the operator explicitly opts in.
- Rules-as-code documentation now distinguishes safe default rules from operator-accepted risky probes.

### Fixed

- Tightened the Django fingerprint rule to avoid matching generic `X-Frame-Options: SAMEORIGIN` headers as Django.

## [1.1.1] — 2026-05-20

Patch release for the Linux static binary scan pipeline.

### Fixed

- Replaced the remaining `tokio::net::lookup_host` call in domain port scanning with `hickory-resolver`, avoiding glibc NSS loading in the static Linux binary during `scan single`.
- Normalized fuzzing dictionary path entries that do not start with `/`, so external dictionary updates cannot produce malformed URLs such as `https://example.comadmin`.

## [1.1.0] — 2026-05-20

Rules-as-code update for dictionaries.

### Added

- `temu rules update` now supports a `dictionaries` manifest section and downloads reviewed dictionary files into the configured dictionaries directory.
- The release documentation now shows binary usage and dictionary-aware rules updates.

## [1.0.1] — 2026-05-20

Patch release for the Linux static binary.

### Fixed

- Enabled the Rust DNS resolver in `reqwest` so the static Linux binary does not enter glibc NSS DNS loading during HTTPS requests. This fixes a `SIGFPE` crash observed when running `temu rules update` from the release binary.

### Documentation

- Added release binary installation and usage examples.

## [1.0.0] — 2026-05-20

First complete release candidate for the Temu scanner.

### Added

- Distributed scanning with Redis-backed coordinator and workers.
- TCP port scanning, banner collection, multi-target file input, and CIDR scanning.
- CVE client with NVD/CISA KEV integration and SQLite cache.
- Verifier crate for false-positive reduction.
- JSON, HTML, and PDF reporting.
- Parameter fuzzing, recursive path fuzzing, adaptive rate limiting, and performance tuning.
- Dockerfile and Docker Compose benchmark environment with isolated vulnerable targets.
- `temu rules update` for rules-as-code updates from a raw GitHub-compatible rules repository.
- Scheduled GitHub Actions workflow to refresh upstream fingerprint/CVE rule sources through reviewed pull requests.
- Homebrew and AUR packaging templates.

### Changed

- Default user agent and crate versions are now `Temu/1.0.0`.
- Release workflow supports static Linux builds and macOS builds through GitHub Actions.

### Security

- Payload safety validation remains read-only by default.
- Scope enforcement, conservative rate limits, and local-only result storage were reviewed for final release.

## [0.1.0-alpha] — 2025-05-12

First functional MVP. All core pipeline stages are wired end-to-end.

### Added

**CLI (`crates/cli`)**
- `temu scan single --url <URL>` — full pipeline scan with JSON output
- Optional flags: `--mode`, `--rate`, `--timeout`, `--output`, `--config`, `--verbose`
- Placeholder subcommands: `scan file`, `scan network`, `cve update`
- `report generate --format json --input <FILE>` — re-serialize existing scan result
- Graceful shutdown on Ctrl+C (`tokio::signal::ctrl_c`)

**Reporter (`crates/reporter`)**
- `ScanResult` and `ScanStats` structs with full serde support
- `generate_json(result, output_dir)` — pretty-printed JSON, filename `{date}_{domain}.json`
- Auto-creates output directory

**Workspace**
- `clap = "4"` added as workspace dependency (derive feature)
- `chrono`, `serde_json` added to CLI dependencies

### Fixed

- `temu_core` config tests: env var race condition under parallel test execution — serialized via `static ENV_MUTEX`

### Sprint Coverage

| Sprint | Status |
|--------|--------|
| Sprint 1 — Core Foundation | ✅ Complete |
| Sprint 2 — Discovery (DNS + HTTP probe) | ✅ Complete |
| Sprint 2+ — Hybrid discovery, CT logs passive, heuristic | ✅ Complete |
| Sprint 3 — Fingerprint, Fuzzing, Vulnerability | ✅ Complete |
| Sprint 4 — CLI + Reporter + Integration Test | ✅ Complete |

### Not Yet Implemented (planned Sprint 5+)

- CT logs active query in CLI pipeline
- HTML / PDF report formats
- CVE database integration (NVD / CISA KEV)
- False positive verifier
- Parameter fuzzing
- Time-based SQLi detection
