# Changelog

All notable changes to Temu will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

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
