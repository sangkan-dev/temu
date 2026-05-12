# AGENTS.md — Panduan untuk AI Coding Agents

> Dokumen ini berisi instruksi, konvensi, dan konteks yang **wajib** diikuti oleh setiap AI agent (Cascade, Copilot, Cursor, dsb.) saat bekerja di codebase Temu.

---

## 1. Gambaran Umum Project

**Temu** adalah automated cybersecurity scanner yang dibangun dengan **Rust (stable edition 2024)**. Filosofi project mengacu pada *Sangkan Paraning Dumadi* — mencari akar masalah, bukan hanya gejala.

- **Tipe project:** CLI tool (bukan web app, bukan library publik)
- **Target pengguna:** Internal red team, security assessor
- **Bahasa kode:** Rust — semua logic ditulis dalam Rust, tidak ada FFI atau bahasa lain
- **Bahasa dokumentasi:** Indonesia untuk PRD, TASK, AGENTS. Inggris untuk code comments, commit messages, dan rustdoc

---

## 2. Arsitektur & Struktur Workspace

Project menggunakan **Cargo workspace** dengan 9 crates. Pahami dependency graph ini sebelum menulis kode:

```
cli
 ├── core
 ├── discovery    → core
 ├── fingerprint  → core
 ├── fuzzing      → core
 ├── vulnerability → core, fingerprint
 ├── cve_client   → core, fingerprint
 ├── verifier     → core, vulnerability
 └── reporter     → core
```

### Struktur folder target:

```
temu/
├── Cargo.toml                 # Workspace root
├── crates/
│   ├── core/                  # Shared types, config, logging, errors
│   ├── discovery/             # Subdomain enumeration, DNS, CT logs
│   ├── fingerprint/           # Technology detection (Wappalyzer-style)
│   ├── fuzzing/               # Path & parameter fuzzing
│   ├── vulnerability/         # Rule-based vuln detection
│   ├── cve_client/            # NVD/CISA KEV integration, SQLite cache
│   ├── verifier/              # False positive reduction
│   ├── reporter/              # JSON, HTML, PDF output
│   └── cli/                   # Entrypoint, clap arg parsing, orchestration
├── rules/                     # YAML detection rules (vuln + fingerprint)
├── dictionaries/              # Wordlists (subdomain, path, parameter)
├── config/
│   └── default.toml           # Default configuration
├── templates/                 # Tera HTML templates untuk reporter
├── tests/                     # Integration tests
└── results/                   # Scan output (gitignored)
```

### Aturan dependency antar crate:

| Aturan | Penjelasan |
|--------|------------|
| `core` tidak boleh depend pada crate lain di workspace | Core adalah fondasi, harus independen |
| Semua crate boleh depend pada `core` | Shared types dan config ada di core |
| `cli` boleh depend pada semua crate | CLI adalah orchestrator |
| Crate selain `cli` tidak boleh depend satu sama lain kecuali diizinkan di graph di atas | Jaga modularitas |
| Hindari circular dependency | Rust compiler akan menolak, tapi tetap waspada saat refactor |

---

## 3. Konvensi Rust

### 3.1 Style & Formatting

- **Selalu** jalankan `cargo fmt` sebelum commit
- **Selalu** jalankan `cargo clippy` dan perbaiki semua warning
- Gunakan Rust edition **2024** (sudah diset di Cargo.toml)
- Tidak ada `unsafe` kecuali benar-benar diperlukan dan sudah didiskusikan
- Tidak ada `unwrap()` atau `expect()` di production code — gunakan `?` operator dengan proper error types
  - `unwrap()` hanya boleh di test code dan contoh
- Gunakan `thiserror` untuk error types, `anyhow` hanya di CLI/top-level

### 3.2 Naming Conventions

| Item | Convention | Contoh |
|------|-----------|--------|
| Crate name | `snake_case` | `cve_client` |
| Struct/Enum | `PascalCase` | `TechStack`, `AssetType` |
| Function/Method | `snake_case` | `run_discovery`, `load_rules` |
| Constants | `SCREAMING_SNAKE_CASE` | `MAX_RETRY_COUNT` |
| Module file | `snake_case` | `dns_resolver.rs` |
| Test function | `test_` prefix | `test_resolve_subdomain` |
| Builder pattern | `with_` prefix | `with_timeout`, `with_rate_limit` |

### 3.3 Import Ordering

Urutkan import dengan baris kosong antar kelompok:

```rust
// 1. Standard library
use std::collections::HashMap;
use std::net::IpAddr;

// 2. External crates
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

// 3. Workspace crates
use core::types::{Asset, Target};
use core::config::AppConfig;

// 4. Local modules
use crate::dns_resolver::resolve;
use crate::probe::HttpProber;
```

### 3.4 Async Runtime

- **Tokio** adalah satu-satunya async runtime. Jangan gunakan `async-std`.
- Gunakan `tokio::spawn` untuk concurrent tasks
- Gunakan `tokio::sync::Semaphore` untuk rate limiting / concurrency control
- Gunakan `tokio::time::timeout` untuk request timeouts
- Jangan block async context — gunakan `tokio::task::spawn_blocking` untuk CPU-bound work

### 3.5 Error Handling Pattern

```rust
// Di library crates — gunakan thiserror
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("DNS resolution failed for {domain}: {source}")]
    DnsResolution {
        domain: String,
        source: trust_dns_resolver::error::ResolveError,
    },

    #[error("HTTP probe failed: {0}")]
    HttpProbe(#[from] reqwest::Error),

    #[error("Wordlist not found: {path}")]
    WordlistNotFound { path: String },
}

// Di CLI — boleh gunakan anyhow untuk convenience
fn main() -> anyhow::Result<()> {
    // ...
}
```

### 3.6 Struct Design

- Derive `Debug` untuk semua struct
- Derive `Clone` jika struct perlu di-clone (kebanyakan iya)
- Derive `Serialize, Deserialize` untuk struct yang masuk/keluar JSON/YAML/TOML
- Gunakan `#[serde(rename_all = "snake_case")]` untuk enum serialization
- Prefer `&str` parameter daripada `String` di function signatures
- Return `String` (owned) dari functions, accept `&str` (borrowed) sebagai input

---

## 4. Konvensi Testing

### 4.1 Lokasi Test

| Jenis Test | Lokasi | Jalankan dengan |
|------------|--------|-----------------|
| Unit test | Di file yang sama (`#[cfg(test)] mod tests`) | `cargo test -p <crate>` |
| Integration test per crate | `crates/<crate>/tests/` | `cargo test -p <crate>` |
| Integration test end-to-end | `tests/` (root) | `cargo test --test <name>` |

### 4.2 Aturan Testing

- **Setiap fungsi publik harus punya minimal 1 unit test**
- Gunakan `#[tokio::test]` untuk async test functions
- Gunakan mock/stub untuk external services (HTTP, DNS):
  - `wiremock` untuk mock HTTP server
  - Jangan pernah test terhadap real external API di unit test
- Nama test deskriptif: `test_bruteforce_finds_www_subdomain`, bukan `test_1`
- Test harus bisa jalan offline (tanpa internet)
- Test harus idempotent (bisa dijalankan berulang kali tanpa side effect)

### 4.3 Contoh Test Pattern

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Critical.to_string(), "Critical");
    }

    #[tokio::test]
    async fn test_probe_returns_status_200() {
        // Setup mock server
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;

        let result = probe_http(&mock_server.uri(), Duration::from_secs(5)).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().status_code, 200);
    }
}
```

---

## 5. Konvensi File Konfigurasi

### 5.1 YAML Rules (Vulnerability Detection)

Semua file di `rules/` mengikuti format:

```yaml
id: "SQLI-MYSQL-TIME"                    # Unik, SCREAMING-KEBAB-CASE
name: "Time-based SQL injection (MySQL)"
tech_stack: ["mysql", "mariadb"]          # Harus match dengan nama di fingerprint
severity: Critical                        # Critical | High | Medium | Low | Info
cvss: 9.8
payload: "' OR SLEEP(5) -- "
request_method: GET                       # GET | POST | PUT | DELETE
request_headers: {}                       # Header tambahan (opsional)
request_body: null                        # Body untuk POST (opsional)
verify:
  match_type: TimeBased                   # BodyContains | BodyRegex | TimeBased | StatusCode | HeaderContains
  time_threshold_secs: 5
  response_codes: [200, 500]
  body_regex: null
cve_id: null                              # CVE ID jika terkait (opsional)
remediation: "Gunakan parameterized queries / prepared statements"
references:
  - "https://owasp.org/www-community/attacks/SQL_Injection"
```

**Aturan saat menulis rules:**

- Payload harus **read-only** — TIDAK BOLEH ada `DROP`, `DELETE`, `UPDATE`, `INSERT`
- Untuk SQL injection, gunakan `SLEEP`, `BENCHMARK`, atau `AND 1=1` / `AND 1=2`
- Untuk XSS, gunakan `<script>alert(1)</script>` atau tag benign
- `id` harus unik di seluruh folder `rules/`
- Satu file YAML = satu rule

### 5.2 YAML Rules (Fingerprint)

File `rules/fingerprint_rules.yaml`:

```yaml
- name: "nginx"
  category: WebServer
  headers:
    Server: "nginx(?:/([\\d.]+))?"
  version: "\\1"                   # Capture group dari regex
  confidence: 0.95

- name: "WordPress"
  category: CMS
  body:
    - "wp-content/"
    - "wp-includes/"
  meta:
    generator: "WordPress"
  implies: ["PHP", "MySQL"]        # Teknologi yang pasti ada jika ini terdeteksi
  confidence: 0.90
```

### 5.3 Wordlist (Dictionaries)

- Format: plain text, satu entry per baris
- Support komentar dengan `#`
- Baris kosong di-skip
- Encoding: UTF-8
- Penamaan: `<type>-<size>.txt` (contoh: `subdomains-small.txt`, `paths-medium.txt`)

### 5.4 Config TOML

File `config/default.toml` — semua field harus punya default yang aman:

```toml
rate_limit = 50          # Request per detik (jangan terlalu tinggi by default)
timeout_secs = 10
concurrency = 100
user_agent = "Temu/0.1.0"
output_dir = "./results"
rules_dir = "./rules"
dictionaries_dir = "./dictionaries"
```

---

## 6. Keamanan & Etika

Ini **sangat penting** karena Temu adalah tool keamanan siber.

### 6.1 Aturan Wajib

| Aturan | Alasan |
|--------|--------|
| Jangan hardcode API key di source code | Gunakan env var atau config file |
| Payload harus read-only | Temu bukan exploit tool — hanya scanner/verifier |
| Default rate limit harus rendah (50 rps) | Hindari DoS ke target |
| Scope enforcement | Jangan scan URL di luar scope yang didefinisikan user |
| Tidak ada data exfiltration | Hasil scan hanya disimpan lokal, tidak dikirim ke server manapun |
| Tidak ada reverse shell / RCE payload | Gunakan detection-only payload |
| Log semua request yang dikirim | Untuk audit trail |

### 6.2 Saat Menulis Payload / Rule Baru

Sebelum menambah rule, tanya:
1. Apakah payload ini bisa merusak data? → **Jangan gunakan**
2. Apakah payload ini bisa menyebabkan denial of service? → **Batasi / gunakan alternatif ringan**
3. Apakah payload ini mengeksekusi kode arbitrary? → **Jangan gunakan, deteksi via side-channel saja**

---

## 7. Dependency Management

### 7.1 Approved Dependencies

Gunakan dependency berikut. Jangan tambah dependency baru tanpa alasan kuat:

| Fungsi | Crate | Catatan |
|--------|-------|---------|
| HTTP client | `reqwest` | Dengan feature `rustls-tls`, bukan `native-tls` |
| Async runtime | `tokio` | Feature: `full` |
| DNS | `trust-dns-resolver` | — |
| CLI parsing | `clap` | Dengan feature `derive` |
| Serialization | `serde`, `serde_json`, `serde_yaml` | — |
| TOML parsing | `toml` | Untuk config |
| Error handling | `thiserror` (lib), `anyhow` (cli) | — |
| Logging | `tracing`, `tracing-subscriber` | — |
| Regex | `regex` | Compile sekali dengan `LazyLock` |
| HTML templating | `tera` | Untuk HTML report |
| PDF generation | `genpdf` atau `printpdf` | Untuk PDF report |
| SQLite | `rusqlite` | Untuk CVE cache |
| Time | `chrono` | Dengan feature `serde` |
| HTTP mock (test) | `wiremock` | Hanya di `[dev-dependencies]` |

### 7.2 Aturan Dependency

- Selalu pin versi mayor di `Cargo.toml` (contoh: `reqwest = "0.12"`)
- Jangan gunakan `*` wildcard untuk versi
- Gunakan `rustls` bukan `openssl` agar bisa static build
- Jalankan `cargo audit` secara berkala untuk cek vulnerability di dependencies
- Workspace-level dependencies: definisikan di root `Cargo.toml` `[workspace.dependencies]`, lalu inherit di member crates

---

## 8. Git & Commit Conventions

### 8.1 Branch Naming

```
feat/<sprint>-<deskripsi>     → feat/s1-core-structs
fix/<issue>-<deskripsi>       → fix/42-wildcard-detection
refactor/<scope>              → refactor/discovery-error-handling
test/<scope>                  → test/fingerprint-wappalyzer
docs/<scope>                  → docs/readme-update
```

### 8.2 Commit Message Format

```
<type>(<scope>): <deskripsi singkat>

<body opsional — jelaskan MENGAPA, bukan APA>
```

**Types:** `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `perf`
**Scope:** nama crate atau area (`core`, `discovery`, `cli`, `rules`, `ci`)

Contoh:
```
feat(discovery): add CT logs query via crt.sh API

Fetch subdomains from Certificate Transparency logs as
an additional discovery source beyond DNS bruteforce.
Cache results locally for 24 hours.
```

### 8.3 Aturan Git

- Commit harus atomic — satu commit = satu perubahan logis
- Jangan commit file `target/`, `results/`, atau file `.log`
- Jangan commit API keys atau secrets
- Setiap commit harus lulus `cargo build` dan `cargo test`

---

## 9. Panduan untuk AI Agent

### 9.1 Sebelum Menulis Kode

1. **Baca TASK.md** — cek sprint mana yang sedang aktif (ditandai `[~]`)
2. **Baca PRD.md** — pahami spesifikasi modul yang akan dikerjakan
3. **Cek existing code** — jangan duplikasi fungsi yang sudah ada
4. **Pahami dependency graph** — jangan buat circular dependency

### 9.2 Saat Menulis Kode

1. Ikuti konvensi di dokumen ini tanpa terkecuali
2. Tulis test bersamaan dengan implementasi, bukan setelahnya
3. Jangan tinggalkan `todo!()` atau `unimplemented!()` tanpa komentar alasan
4. Jika membuat struct baru di `core`, pastikan derive `Serialize`, `Deserialize`, `Debug`, `Clone`
5. Setiap fungsi publik harus punya rustdoc comment (dalam bahasa Inggris):
   ```rust
   /// Resolves a subdomain by performing a DNS A record lookup.
   ///
   /// Returns a list of IP addresses if the subdomain exists,
   /// or an error if the domain cannot be resolved.
   pub async fn resolve_subdomain(subdomain: &str) -> Result<Vec<IpAddr>, DiscoveryError> {
   ```

### 9.3 Setelah Menulis Kode

1. Pastikan `cargo build` sukses
2. Pastikan `cargo test` pass
3. Pastikan `cargo clippy` tidak ada warning
4. Update TASK.md — tandai task yang selesai (`[x]`)
5. Jika menambah dependency baru, dokumentasikan alasannya

### 9.4 Yang TIDAK Boleh Dilakukan

- ❌ Jangan ubah struct di `core` tanpa memastikan semua crate lain masih compile
- ❌ Jangan tambah `println!` untuk debugging — gunakan `tracing::debug!`
- ❌ Jangan buat file baru di root project kecuali diminta
- ❌ Jangan rename crate tanpa update seluruh workspace
- ❌ Jangan hapus test yang sudah ada kecuali diminta secara eksplisit
- ❌ Jangan gunakan `reqwest::blocking` — selalu async
- ❌ Jangan hardcode path — gunakan `AppConfig` atau `PathBuf` parameter
- ❌ Jangan panic di library code — return `Result<T, E>`

---

## 10. Referensi Cepat: Command Cheatsheet

```bash
# Tambah dependency
cargo add <crate_name>

# Build seluruh workspace
cargo build

# Build release (optimized)
cargo build --release

# Test seluruh workspace
cargo test

# Test satu crate
cargo test -p core
cargo test -p discovery

# Test satu fungsi
cargo test -p core test_severity_display

# Lint
cargo clippy --all-targets

# Format
cargo fmt --all

# Audit dependencies
cargo audit

# Run CLI
cargo run -p cli -- scan single --url https://example.com
cargo run -p cli -- scan single --url https://example.com --rate 100 --timeout 15
cargo run -p cli -- cve update
cargo run -p cli -- report generate --format html --input results/scan.json

# Static build (Linux)
RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --target x86_64-unknown-linux-gnu
```

---

## 11. Diagram Alur Scan Pipeline

```
User Input (CLI)
       │
       ▼
┌──────────────┐
│  Parse Args  │  cli crate
│  Load Config │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Discovery   │  Subdomain bruteforce, CT logs, zone transfer
│              │  HTTP/HTTPS probing
└──────┬───────┘
       │  Vec<Asset>
       ▼
┌──────────────┐
│ Fingerprint  │  Header analysis, Wappalyzer rules, WAF detection
└──────┬───────┘
       │  Vec<TechStack>
       ▼
┌──────────────┐
│   Fuzzing    │  Path fuzzing, parameter fuzzing, recursive
└──────┬───────┘
       │  Vec<Asset> (paths + params)
       ▼
┌──────────────────┐
│  Vulnerability   │  Load YAML rules, match tech_stack, send payload
│  + CVE Client    │  Query NVD/CISA KEV by CPE
└──────┬───────────┘
       │  Vec<Vulnerability>
       ▼
┌──────────────┐
│   Verifier   │  Re-send payload, compare baseline, confirm/deny
└──────┬───────┘
       │  Vec<Vulnerability> (verified)
       ▼
┌──────────────┐
│   Reporter   │  JSON + HTML + PDF
└──────────────┘
       │
       ▼
   Output files in results/
```

---

## 12. Checklist Review untuk Setiap PR/Perubahan

Sebelum menganggap perubahan selesai, pastikan:

- [ ] `cargo build` — no errors
- [ ] `cargo test` — all pass
- [ ] `cargo clippy --all-targets` — no warnings
- [ ] `cargo fmt --all --check` — formatted
- [ ] Tidak ada `unwrap()` di non-test code
- [ ] Tidak ada hardcoded paths atau secrets
- [ ] Semua fungsi publik punya rustdoc
- [ ] Semua struct baru punya derive yang sesuai
- [ ] Test baru ditambahkan untuk fungsionalitas baru
- [ ] TASK.md diupdate jika task selesai
- [ ] Commit message sesuai konvensi
