# Changelog

All notable changes to Temu will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

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
