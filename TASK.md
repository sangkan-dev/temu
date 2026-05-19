# TASK.md — Sprint Planning
## Temu - Automated Cybersecurity Scanner

**Sprint Duration:** 1 minggu per sprint  
**Total Estimasi:** 20 sprint (~5 bulan)  
**Methodology:** Incremental delivery, setiap sprint menghasilkan artefak yang bisa di-test  

> **Legend:**
> - [ ] Belum dimulai
> - [~] Sedang dikerjakan
> - [x] Selesai
> - 🔴 **Critical** — Blocker jika tidak selesai
> - 🟡 **High** — Penting tapi bisa di-workaround
> - 🟢 **Normal** — Nice to have di sprint ini

---

# FASE 1 — MVP (Sprint 1–4)

Tujuan: Scanner bisa menerima 1 URL, menemukan subdomain, deteksi web server, fuzz path, deteksi kerentanan dasar (SQLi reflection), dan output JSON.

---

## Sprint 1 — Project Foundation & Core Crate

**Goal:** Setup workspace Cargo, implementasi semua struct dasar, config loader, dan logging.

### 1.1 Setup Cargo Workspace
- [x] 🔴 Ubah `Cargo.toml` root menjadi workspace manifest dengan members:
  ```
  members = ["crates/core", "crates/discovery", "crates/fingerprint",
             "crates/fuzzing", "crates/vulnerability", "crates/cve_client",
             "crates/verifier", "crates/reporter", "crates/cli"]
  ```
- [x] 🔴 Buat folder structure:
  ```
  temu/
  ├── Cargo.toml              (workspace root)
  ├── crates/
  │   ├── core/
  │   │   ├── Cargo.toml
  │   │   └── src/lib.rs
  │   ├── discovery/
  │   │   ├── Cargo.toml
  │   │   └── src/lib.rs
  │   ├── fingerprint/
  │   │   ├── Cargo.toml
  │   │   └── src/lib.rs
  │   ├── fuzzing/
  │   │   ├── Cargo.toml
  │   │   └── src/lib.rs
  │   ├── vulnerability/
  │   │   ├── Cargo.toml
  │   │   └── src/lib.rs
  │   ├── cve_client/
  │   │   ├── Cargo.toml
  │   │   └── src/lib.rs
  │   ├── verifier/
  │   │   ├── Cargo.toml
  │   │   └── src/lib.rs
  │   ├── reporter/
  │   │   ├── Cargo.toml
  │   │   └── src/lib.rs
  │   └── cli/
  │       ├── Cargo.toml
  │       └── src/main.rs
  ├── rules/                   (YAML detection rules)
  ├── dictionaries/            (wordlist subdomain, path)
  └── config/
      └── default.toml
  ```
- [x] 🔴 Pastikan `cargo build` sukses tanpa error pada workspace kosong
- [x] 🟢 Tambahkan `.gitignore` untuk `/target`, `*.log`, `/results`

### 1.2 Core Crate — Struct Dasar
- [x] 🔴 Definisikan `Target` struct:
  ```rust
  pub struct Target {
      pub domain: String,
      pub ip_list: Vec<IpAddr>,
      pub scope: Scope,
  }
  ```
- [x] 🔴 Definisikan `Scope` struct:
  ```rust
  pub struct Scope {
      pub include_patterns: Vec<String>,  // regex patterns
      pub exclude_patterns: Vec<String>,
  }
  ```
- [x] 🔴 Definisikan `Asset` struct + enum `AssetType`:
  ```rust
  pub enum AssetType {
      Subdomain,
      Path,
      Parameter,
      IP,
      URL,
  }

  pub struct Asset {
      pub url: String,
      pub asset_type: AssetType,
      pub discovered_by: String,       // nama modul yang menemukan
      pub discovered_at: DateTime<Utc>,
  }
  ```
- [x] 🔴 Definisikan `Severity` enum + `Vulnerability` struct:
  ```rust
  pub enum Severity {
      Critical,
      High,
      Medium,
      Low,
      Info,
  }

  pub struct Vulnerability {
      pub id: String,
      pub name: String,
      pub severity: Severity,
      pub cvss_score: f32,
      pub proof: String,
      pub url: String,
      pub parameter: Option<String>,
      pub verified: bool,
      pub detected_at: DateTime<Utc>,
      pub remediation: Option<String>,
  }
  ```
- [x] 🔴 Implementasi `Serialize`/`Deserialize` (derive serde) untuk semua struct
- [x] 🟡 Implementasi `Display` trait untuk `Severity` dan `AssetType`
- [x] 🟢 Unit test: serialisasi/deserialisasi semua struct ke JSON

### 1.3 Core Crate — Config Loader
- [x] 🔴 Definisikan `AppConfig` struct:
  ```rust
  pub struct AppConfig {
      pub rate_limit: u32,           // request per detik
      pub timeout_secs: u64,         // timeout per request
      pub concurrency: usize,        // max concurrent tasks
      pub user_agent: String,
      pub output_dir: PathBuf,
      pub rules_dir: PathBuf,
      pub dictionaries_dir: PathBuf,
  }
  ```
- [x] 🔴 Implementasi load config dari file TOML (`config/default.toml`)
- [x] 🔴 Buat `config/default.toml` dengan nilai default:
  ```toml
  rate_limit = 50
  timeout_secs = 10
  concurrency = 100
  user_agent = "Temu/0.1.0"
  output_dir = "./results"
  rules_dir = "./rules"
  dictionaries_dir = "./dictionaries"
  ```
- [x] 🟡 Support override config via environment variables (prefix `TEMU_`) ← selesai di Sprint 2+
- [x] 🟢 Unit test: load config default, override partial config

### 1.4 Core Crate — Logging
- [x] 🔴 Setup `tracing` + `tracing-subscriber` untuk structured logging
- [x] 🔴 Support log level dari config/CLI (trace, debug, info, warn, error)
- [x] 🟡 Output log ke file di samping stdout ← selesai di Sprint 2+
- [x] 🟢 Macro helper: `temu_info!`, `temu_warn!`, `temu_error!` ← selesai di Sprint 2+

### 1.5 Core Crate — Error Handling
- [x] 🔴 Definisikan `TemuError` enum menggunakan `thiserror`:
  ```rust
  pub enum TemuError {
      Config(String),
      Network(reqwest::Error),
      Dns(String),
      Io(std::io::Error),
      Parse(String),
      RuleLoad(String),
      Timeout,
  }
  ```
- [x] 🔴 Implementasi `From` conversions untuk error types umum
- [x] 🟢 Unit test: konversi error

### 🏁 Sprint 1 — Definition of Done
- `cargo build` sukses untuk seluruh workspace
- `cargo test -p core` pass semua test
- Semua struct bisa di-serialize ke JSON
- Config loader bisa baca `default.toml`
- Logger berjalan dengan output ke stdout

---

## Sprint 2 — Discovery Crate (Subdomain Enumeration)

**Goal:** Bisa menemukan subdomain dari sebuah domain target menggunakan bruteforce DNS dan HTTP probing.

### 2.1 Subdomain Wordlist Loader
- [x] 🔴 Buat file `dictionaries/subdomains-small.txt` (100 entry paling umum: www, mail, ftp, admin, api, staging, dev, test, dll)
- [x] 🔴 Fungsi `load_wordlist(path: &Path) -> Result<Vec<String>>` di discovery crate
- [x] 🟡 Support komentar (`#`) dan baris kosong di wordlist
- [x] 🟢 Unit test: load wordlist, validasi jumlah entry

### 2.2 DNS Resolution (Async)
- [x] 🔴 Setup dependency `hickory-resolver` (pengganti trust-dns-resolver) + `tokio` di discovery crate
- [x] 🔴 Fungsi `resolve_subdomain(subdomain: &str) -> Result<Vec<IpAddr>>`:
  - Kirim DNS A record query
  - Return list IP jika resolved, error jika NXDOMAIN
- [x] 🔴 Fungsi `bruteforce_subdomains(domain: &str, wordlist: &[String], concurrency: usize) -> Vec<Asset>`:
  - Untuk setiap kata di wordlist, bentuk `{word}.{domain}`
  - Resolve DNS secara async (gunakan `tokio::sync::Semaphore` untuk rate limit)
  - Kumpulkan yang berhasil resolve
- [x] 🟡 Wildcard detection:
  - Sebelum bruteforce, resolve `random-string-xyz123.{domain}`
  - Jika resolved, tandai domain sebagai wildcard
  - Filter hasil yang IP-nya sama dengan wildcard response
- [x] 🟢 Progress indicator: log setiap 100 subdomain yang dicek

### 2.3 HTTP/HTTPS Probing
- [x] 🔴 Setup dependency `reqwest` (dengan feature `rustls-tls`) di discovery crate
- [x] 🔴 Fungsi `probe_http(subdomain: &str, timeout: Duration) -> Option<ProbeResult>`:
  ```rust
  pub struct ProbeResult {
      pub url: String,           // http:// atau https://
      pub status_code: u16,
      pub redirect_url: Option<String>,
      pub content_length: Option<u64>,
      pub title: Option<String>,  // dari <title> tag
  }
  ```
  - Coba HTTPS dulu, fallback ke HTTP
  - Simpan status code, redirect location, content length
  - Parse `<title>` dari response body (regex sederhana)
- [x] 🔴 Fungsi `probe_all(subdomains: &[String], config: &AppConfig) -> Vec<ProbeResult>`:
  - Probe semua subdomain secara async
  - Gunakan semaphore sesuai `config.concurrency`
  - Timeout sesuai `config.timeout_secs`
- [x] 🟡 Deduplikasi: jika 2 subdomain redirect ke URL yang sama, tandai
- [x] 🟢 Unit test: mock HTTP server untuk test probing

### 2.4 Discovery Orchestrator
- [x] 🔴 Fungsi publik `run_discovery(target: &Target, config: &AppConfig) -> Vec<Asset>`:
  - Load wordlist
  - Jalankan bruteforce DNS
  - Probe HTTP untuk setiap subdomain ditemukan
  - Return list `Asset` dengan type `Subdomain` dan `URL`
- [x] 🟡 Log ringkasan: "Found X subdomains, Y are live"
- [x] 🟢 Integration test: discovery terhadap domain test (`crates/discovery/tests/integration_test.rs` — 2 tests, ActiveBruteforce + SmartHeuristic) ← selesai di Sprint 3

### 🏁 Sprint 2 — Definition of Done ✅
- `cargo test -p discovery` pass ✅
- Bisa resolve subdomain dari wordlist ✅
- Wildcard detection berfungsi ✅
- HTTP probing mengembalikan status code dan title ✅
- `run_discovery()` mengembalikan list `Asset` yang valid ✅

---

## Sprint 2+ Enhancement — Hutang Sprint 1 + Discovery Hybrid

**Goal:** Melunasi hutang Sprint 1 di temu_core dan upgrade discovery ke arsitektur hybrid.

### A.1 Core — Env Var Override
- [x] 🟡 `apply_env_overrides()` — override semua field AppConfig via `TEMU_*` env vars
- [x] 🟡 `load_with_env()` dan `load_or_default_with_env()` sebagai convenience methods
- [x] 🟢 Unit test: TEMU_RATE_LIMIT, TEMU_USER_AGENT, TEMU_OUTPUT_DIR, invalid value ignored

### A.2 Core — Log ke File
- [x] 🟡 Tambah dependency `tracing-appender` ke workspace
- [x] 🟡 `init_logging_with_file(level, log_dir)` — stdout + rolling daily file `temu.log`
- [x] 🟢 Unit test: no panic saat dipanggil dengan/tanpa log_dir

### A.3 Core — Macro Helper
- [x] 🟢 `temu_info!`, `temu_warn!`, `temu_error!` macro di `crates/core/src/macros.rs`
- [x] 🟢 Re-export dari `temu_core` root

### B.1 Discovery — DiscoveryMode Enum
- [x] 🔴 `DiscoveryMode { PassiveOnly, ActiveBruteforce, SmartHeuristic, Hybrid }`
- [x] 🔴 `run_discovery(target, config, mode)` — parameter mode wajib

### B.2 Discovery — Passive CT Logs
- [x] 🔴 `passive.rs` — `fetch_crtsh(domain)` via `https://crt.sh/?q=%.domain&output=json`
- [x] 🟡 `fetch_crtsh_with_base(domain, base_url)` untuk testability
- [x] 🟡 Wildcard strip (`*.example.com` → `example.com`), dedup, filter by domain
- [x] 🟢 wiremock tests: parse subdomains, dedup, HTTP error, invalid JSON

### B.3 Discovery — Heuristic Generator
- [x] 🔴 `heuristic.rs` — `generate_candidates(domain)` cross-kombinasi service/env/region/numeric tags
- [x] 🟢 Unit test: >= 200 kandidat, no duplicates, common patterns, all end with domain

### 🏁 Sprint 2+ — Definition of Done
- `cargo test -p temu_core` — 26 passed ✅
- `cargo test -p discovery` — 27 passed ✅
- `TEMU_RATE_LIMIT=999` → config.rate_limit berubah
- `init_logging_with_file` menulis file temu.log
- `generate_candidates("example.com")` menghasilkan > 200 kandidat
- `run_discovery(target, config, DiscoveryMode::Hybrid)` terkompilasi

---

## Sprint 3 — Fingerprint, Fuzzing, & Vulnerability (Dasar)

**Goal:** Deteksi web server dari header, fuzz path dasar, dan load aturan deteksi YAML.

### 3.1 Fingerprint — Header-based Detection
- [x] 🔴 Definisikan `TechStack` struct dan `TechCategory` enum di `types.rs`
- [x] 🔴 Fungsi `fingerprint_from_headers(headers: &HeaderMap) -> Vec<TechStack>`:
  - Parse header `Server` → deteksi nginx, Apache, IIS, dll + versi
  - Parse header `X-Powered-By` → deteksi PHP, ASP.NET, Express, dll
  - Parse header `X-AspNet-Version`, `cf-ray`, `X-Sucuri-ID`, `X-CDN`
- [x] 🟡 Fungsi `fingerprint_from_body(body: &str) -> Vec<TechStack>`:
  - Cari `<meta name="generator" content="WordPress 6.x">`
  - Cari pattern script `jquery-3.x.x.min.js`
  - Cari pattern CSS framework (Bootstrap)
- [x] 🟡 Fungsi `detect_waf(headers: &HeaderMap, status: u16, body: &str) -> Option<TechStack>`:
  - Cek header `X-Sucuri-ID`, `cf-ray` (Cloudflare), `X-CDN` (Incapsula)
  - Cek jika response 403 dengan body berisi "Access Denied" pattern
- [x] 🔴 Fungsi publik `run_fingerprint(url: &str, config: &AppConfig) -> Result<Vec<TechStack>, TemuError>`:
  - Kirim GET request ke URL
  - Gabungkan hasil dari headers, body, WAF detection
  - Deduplikasi dan sort by confidence
- [x] 🟢 Unit test: mock response dengan header nginx/1.18.0 → assert deteksi benar (22 tests)

### 3.2 Fuzzing — Path Fuzzing (Dasar)
- [x] 🔴 Buat file `dictionaries/paths-small.txt` (100 path umum)
- [x] 🔴 Definisikan `FuzzResult` struct di `types.rs`
- [x] 🔴 Fungsi `fuzz_paths(base_url, wordlist, config) -> Vec<FuzzResult>` di `fuzzer.rs`:
  - Async dengan semaphore sesuai concurrency
  - Filter status code interesting (200/301/302/403/401/500/dll)
- [x] 🟡 Baseline detection anti-false-positive (custom 404):
  - Request ke `/temu_baseline_zxqwvnm987` → baseline status + length
  - Filter paths yang identik dengan baseline
- [x] 🔴 Fungsi publik `run_fuzzing(base_url, config) -> Result<Vec<Asset>, TemuError>`
- [x] 🟢 Unit test: mock HTTP server, baseline filter, redirect URL (3 tests)

### 3.3 Vulnerability — Rule Loader
- [x] 🔴 Definisikan `Rule`, `VerifyConfig`, `MatchType` struct di `types.rs`
- [x] 🔴 Fungsi `load_rules(rules_dir: &Path) -> Result<Vec<Rule>, TemuError>` di `loader.rs`:
  - Baca semua file `.yaml` dari directory
  - Parse setiap file ke `Rule` struct via serde_yaml
  - Validasi: id unik, skip duplicate, skip invalid YAML
- [x] 🔴 Buat 3 file aturan awal di `rules/`:
  - `rules/sqli-reflection.yaml` — SQLi via body reflection
  - `rules/xss-reflection.yaml` — Reflected XSS
  - `rules/sensitive-files.yaml` — Exposed .env
- [x] 🟡 Fungsi `filter_rules_by_tech(rules, tech) -> Vec<&Rule>` di `filter.rs`
- [x] 🟢 Unit test: load valid rule, skip invalid YAML, skip duplicate ID (5 tests)

### 3.4 Vulnerability — Basic Executor
- [x] 🔴 Fungsi `execute_rule(rule, url, parameter, config) -> Option<Vulnerability>` di `executor.rs`:
  - Inject payload ke query string via `reqwest::Url::query_pairs_mut`
  - Cek response: `BodyContains`, `StatusCode`, `BodyRegex`, `HeaderContains`
  - `TimeBased` di-stub (Sprint 4+)
- [x] 🔴 Fungsi publik `run_vulnerability_scan(urls, tech, config) -> Result<Vec<Vulnerability>, TemuError>`
- [x] 🟢 Unit test: body_contains match, no-match, status_code match (3 tests)

### 🏁 Sprint 3 — Definition of Done ✅
- `cargo test -p fingerprint` — 22 passed ✅
- `cargo test -p fuzzing` — 3 passed ✅
- `cargo test -p vulnerability` — 13 passed ✅
- `cargo test -p discovery --test integration_test` — 2 passed ✅
- `cargo test --workspace` — semua pass ✅
- Fingerprinting mendeteksi nginx/Apache/IIS/PHP/WordPress dari header+body ✅
- Path fuzzing baseline anti-false-positive berfungsi ✅
- Rule loader baca 3 file YAML dari `rules/` ✅
- Vulnerability executor deteksi SQLi/XSS/sensitive-files ✅

---

## Sprint 4 — CLI + Reporter JSON + Integrasi End-to-End

**Goal:** Semua modul terhubung lewat CLI. User bisa jalankan `temu scan --url <target>` dan dapat output JSON.

### 4.1 CLI — Argument Parsing
- [x] 🔴 Setup `clap` dengan derive API di cli crate
- [x] 🔴 Implementasi command structure:
  ```
  temu scan single --url <URL> [--rate <N>] [--timeout <N>] [--output <DIR>]
  temu scan file --list <FILE>     (placeholder, belum implementasi)
  temu scan network --cidr <CIDR>  (placeholder, belum implementasi)
  temu report generate --format <json|html|pdf> --input <FILE>
  temu cve update                  (placeholder, belum implementasi)
  ```
- [x] 🔴 Parsing argumen ke `AppConfig` (merge dengan default.toml):
  - CLI args override config file
  - Validasi: URL harus valid, rate > 0, timeout > 0
- [x] 🟡 Help text yang informatif untuk setiap subcommand
- [x] 🟢 Tambahkan `--verbose` flag untuk debug logging

### 4.2 CLI — Scan Orchestrator
- [x] 🔴 Implementasi `async fn run_scan(url, config, mode) -> anyhow::Result<ScanResult>`:
  ```rust
  pub struct ScanResult {
      pub target: String,
      pub assets: Vec<Asset>,
      pub tech_stacks: HashMap<String, Vec<TechStack>>,  // url -> techs
      pub vulnerabilities: Vec<Vulnerability>,
      pub scan_started_at: DateTime<Utc>,
      pub scan_finished_at: DateTime<Utc>,
      pub stats: ScanStats,
  }

  pub struct ScanStats {
      pub subdomains_found: u32,
      pub paths_found: u32,
      pub vulns_found: u32,
      pub duration_secs: f64,
  }
  ```
- [x] 🔴 Implementasi alur pipeline MVP:
  ```
  1. Parse target URL → Target struct
  2. Discovery: bruteforce subdomain + HTTP probe
  3. Fingerprint: untuk setiap live URL
  4. Fuzzing: path fuzzing untuk setiap live URL
  5. Vulnerability: scan setiap path + parameter yang ditemukan
  6. Kumpulkan hasil → ScanResult
  ```
- [x] 🟡 Progress output ke terminal (stderr):
  ```
  [*] Starting scan for staging.company.com
  [+] Discovery: found 12 assets
  [+] Fingerprint: nginx/1.18.0, PHP/7.4
  [+] Fuzzing: found 23 paths
  [+] Vulnerability: found 3 issues
  [*] Scan completed in 45.2s
  ```
- [x] 🟢 Graceful shutdown: handle Ctrl+C dengan `tokio::signal`
- [x] 🟢 `cli/src/lib.rs` mengekspos `orchestrator` untuk integration test

### 4.3 Reporter — JSON Output
- [x] 🔴 Fungsi `generate_json(result: &ScanResult, output_dir: &Path) -> Result<PathBuf, TemuError>`:
  - Serialize `ScanResult` ke JSON pretty-printed
  - Nama file: `{date}_{domain}.json` (contoh: `2025-05-12_staging_company.json`)
  - Simpan ke `output_dir`
- [x] 🔴 JSON schema yang jelas:
  ```json
  {
    "target": "https://staging.company.com",
    "scan_started_at": "2025-05-12T10:00:00Z",
    "scan_finished_at": "2025-05-12T10:00:45Z",
    "stats": {
      "subdomains_found": 5,
      "paths_found": 12,
      "vulns_found": 2,
      "duration_secs": 45.2
    },
    "assets": [ ... ],
    "tech_stacks": { ... },
    "vulnerabilities": [ ... ]
  }
  ```
- [x] 🟡 Buat folder `results/` otomatis jika belum ada
- [x] 🟢 Unit test: generate JSON, parse kembali, validasi isi (4 tests)

### 4.4 Integration Test End-to-End
- [x] 🔴 Buat test binary yang menjalankan scan terhadap mock server:
  - Setup mock HTTP server menggunakan `wiremock`
  - nginx header + WordPress body di `/`, `/robots.txt` 200, `/.env` 200, lainnya 404
  - Jalankan full pipeline: discovery → fingerprint → fuzz → vuln scan
  - Assert: nginx fingerprint terdeteksi, `/robots.txt` ditemukan fuzz, JSON valid, file ditulis
- [x] 🟡 Test CLI argument parsing: semua kombinasi valid/invalid (11 tests di `args.rs`)
- [x] 🟢 Dokumentasi cara menjalankan: `cargo run -p cli -- scan single --url <URL>`

### 4.5 Dokumentasi MVP
- [x] 🟡 Update `README.md` dengan:
  - Cara build: `cargo build --release`
  - Cara pakai: contoh command
  - Struktur folder
- [x] 🟢 Tambahkan `CHANGELOG.md` entry untuk v0.1.0-alpha
- [x] 🟡 Bug fix: env var race condition di `temu_core` config tests — pakai `static ENV_MUTEX`

### 🏁 Sprint 4 — Definition of Done ✅
- `cargo run -p cli -- scan single --url <URL>` berjalan end-to-end ✅
- Output JSON valid dan berisi hasil scan ✅
- Seluruh pipeline: discovery → fingerprint → fuzzing → vulnerability → report berjalan ✅
- `cargo test -p cli --test integration_e2e` — 2 passed ✅
- `cargo test -p cli` — 11 args unit tests + 2 integration tests ✅
- `cargo test --workspace` — 0 FAILED ✅
- `cargo build --release` — sukses ✅
- Graceful shutdown Ctrl+C (`tokio::select!` + `ctrl_c()`) ✅
- **MVP tercapai ✅**

---

# FASE 2 — Enhancement (Sprint 5–10)

Tujuan: Memperkuat setiap modul, tambah CT logs, Wappalyzer rules, parameter fuzzing, CVE integration, verifier, dan laporan HTML.

---

## Sprint 5 — Discovery Enhancement (CT Logs & Zone Transfer)

**Goal:** Tambah sumber discovery selain bruteforce.

### 5.1 Certificate Transparency Logs
- [x] 🔴 Fungsi `query_crtsh(domain: &str) -> Result<Vec<String>>` (`fetch_crtsh_with_base`):
  - HTTP GET ke `https://crt.sh/?q=%25.{domain}&output=json`
  - Parse JSON response → extract `name_value` field
  - Deduplikasi dan filter wildcard entries (`*.domain.com` → skip)
  - Retry 3x dengan exponential backoff pada 5xx/timeout
- [x] 🔴 Integrasi ke `run_discovery()`: gabungkan hasil CT logs dengan bruteforce
- [x] 🟡 Cache hasil CT logs ke file lokal `{output_dir}/.cache/crtsh_{domain}.json` (expire 24 jam)
- [x] 🟢 Unit test: mock crt.sh response (8 tests: parse, dedup, HTTP error, invalid JSON, wildcard, retry-on-502, cache hit, no-cache-fetches-network)

### 5.2 DNS Zone Transfer
- [x] 🟡 Fungsi `attempt_zone_transfer(domain: &str) -> Result<Vec<String>>` (`crates/discovery/src/zone_transfer.rs`):
  - Resolve NS record untuk domain
  - Coba AXFR query ke setiap nameserver
  - Parse hasil → extract subdomain entries
- [x] 🟡 Handle error gracefully (kebanyakan server menolak AXFR → return `Ok(vec![])`)
- [x] 🟢 Log warning jika zone transfer berhasil (ini vulnerability)

### 5.3 Wordlist Besar
- [x] 🟡 Tambahkan `dictionaries/subdomains-medium.txt` (1000 entry)
- [x] 🟡 CLI flag `--wordlist-size small|medium|large` untuk pilih kamus
- [x] 🟢 Support custom wordlist path: `--wordlist /path/to/custom.txt`

### 🏁 Sprint 5 — Definition of Done ✅
- Discovery menggunakan 3 sumber: bruteforce + CT logs + zone transfer ✅
- Lebih banyak subdomain ditemukan dibanding Sprint 2 ✅
- Cache CT logs berfungsi ✅
- `cargo test -p discovery` — 32 passed ✅
- `cargo test --workspace` — 0 FAILED ✅

---

## Sprint 6 — Fingerprint Enhancement (Wappalyzer Rules)

**Goal:** Deteksi 200+ teknologi menggunakan Wappalyzer-style rules.

### 6.1 Wappalyzer Rule Format
- [x] 🔴 Buat file `rules/fingerprint_rules.yaml` (65+ rules):
  - Format: `name`, `category`, `confidence`, `headers`, `body`, `meta`, `cookies`, `version`, `implies`
  - Semua rules ada di `rules/fingerprint_rules.yaml`
- [x] 🔴 Parser: `load_fingerprint_rules(path) -> Vec<FingerprintRule>` di `crates/fingerprint/src/rules.rs`
- [x] 🔴 65+ rules untuk teknologi populer:
  - Web servers: nginx, Apache, IIS, LiteSpeed, Caddy, Gunicorn, Tomcat, OpenResty, Nginx Unit, HAProxy
  - Languages: PHP, Node.js, ASP.NET
  - CMS: WordPress, Drupal, Joomla, Magento, Ghost, Typo3, Shopify, Wix, Squarespace
  - Frameworks: Laravel, Django, Ruby on Rails, Express, Spring, Next.js, Nuxt.js
  - JS Libraries: jQuery, Bootstrap, React, Vue.js, Angular, Lodash, Moment.js, Axios, Webpack
  - CDN/WAF: Cloudflare, Akamai, Sucuri, AWS CloudFront, Fastly, Imperva, Netlify, Vercel, Heroku
  - Misc: Varnish, Envoy, Traefik, AWS ALB, Azure, Google Cloud

### 6.2 Matching Engine
- [x] 🔴 Fungsi `match_all_rules(rules, headers, body) -> Vec<TechStack>` di `rules.rs`:
  - Match headers via regex (capture group 1 = version)
  - Match body patterns (regex atau literal)
  - Match meta tags (`<meta name="..." content="...">`)
  - Match cookies via `Set-Cookie` header
  - Extract version dari capture group
  - Confidence score dari rule definition
- [x] 🟡 Support `implies`: WordPress terdeteksi → otomatis tambahkan PHP & MySQL
- [x] 🟢 9 unit tests: header match, body match, meta match, implies chain, no-match, dedup, load valid YAML, load missing file, missing rules returns empty

### 6.3 Integrasi
- [x] 🔴 `run_fingerprint()` di-refactor penuh — load rules dari `{rules_dir}/fingerprint_rules.yaml`
- [x] 🟡 Log detail: `"Detected: nginx/1.18.0 (confidence: 0.95)"` per teknologi via `tracing::info!`
- [x] 🟢 Output: list teknologi sorted by confidence descending
- [x] 🔴 Hapus `headers.rs`, `body.rs`, `waf.rs` — semua hardcode diganti YAML engine

### 🏁 Sprint 6 — Definition of Done ✅
- Deteksi 65+ teknologi dari fingerprint rules ✅
- Confidence score akurat (0.60–0.95) ✅
- Version extraction berfungsi (nginx/1.18.0, Apache/2.4.51, PHP/8.1, dll) ✅
- `implies` chain berfungsi (WordPress → PHP + MySQL) ✅
- `cargo test --workspace` — 0 FAILED ✅

---

## Sprint 7 — Parameter Fuzzing & Recursive Path

**Goal:** Fuzzer bisa menemukan parameter tersembunyi dan melakukan recursive path fuzzing.

### 7.1 Parameter Fuzzing
- [x] 🔴 Buat `dictionaries/parameters-small.txt` (100 parameter umum):
  ```
  id
  page
  search
  q
  user
  username
  password
  email
  token
  api_key
  redirect
  url
  next
  callback
  file
  path
  cmd
  exec
  ...
  ```
- [x] 🔴 Fungsi `fuzz_parameters(url: &str, wordlist: &[String], config: &AppConfig) -> Vec<Asset>`:
  - Kirim GET request dengan `?{param}=test123` untuk setiap parameter
  - Bandingkan response dengan baseline (tanpa parameter)
  - Jika response berbeda (status code, content length, body diff) → parameter valid
- [x] 🟡 Threshold untuk "response berbeda":
  - Status code berbeda → pasti valid
  - Content length berbeda > 10% → kemungkinan valid
  - Body contains `test123` → parameter reflected
- [x] 🟢 Unit test: mock server yang merespon beda untuk `?id=` vs unknown param

### 7.2 Recursive Path Fuzzing
- [x] 🟡 Jika path ditemukan (status 200/301/403), fuzz sub-path:
  - Contoh: `/api` ditemukan → fuzz `/api/v1`, `/api/users`, `/api/admin`
- [x] 🟡 Konfigurasi `max_recursion_depth` (default: 2)
- [x] 🟡 Hindari infinite loop: track visited paths
- [x] 🟢 Unit test: recursive fuzzing pada mock server

### 7.3 Integrasi ke Pipeline
- [x] 🔴 Update `run_fuzzing()` untuk include parameter fuzzing
- [x] 🔴 Pass parameter results ke vulnerability scanner
- [x] 🟢 Update CLI output: "Found X paths, Y parameters"

### 🏁 Sprint 7 — Definition of Done ✅
- Parameter fuzzing menemukan hidden params ✅
- Recursive path fuzzing berjalan dengan depth limit ✅
- Vulnerability scanner menerima parameter dari fuzzer ✅
- `cargo test --workspace` — 0 FAILED ✅
- `cargo clippy --all-targets` — no warnings ✅
- `cargo fmt --all --check` — formatted ✅

---

## Sprint 8 — CVE Client (NVD Integration + SQLite Cache)

**Goal:** Bisa query CVE berdasarkan teknologi yang terdeteksi, dengan cache lokal.

### 8.1 SQLite Setup
- [x] 🔴 Setup dependency `rusqlite` di cve_client crate
- [x] 🔴 Schema database:
  ```sql
  CREATE TABLE cve_entries (
      cve_id TEXT PRIMARY KEY,
      description TEXT,
      severity TEXT,
      cvss_score REAL,
      cpe_match TEXT,           -- JSON array of CPE strings
      published_date TEXT,
      last_modified TEXT,
      exploitability TEXT,      -- 'known_exploited' | 'poc_available' | 'theoretical'
      source TEXT,              -- 'nvd' | 'cisa_kev'
      cached_at TEXT
  );

  CREATE INDEX idx_cpe ON cve_entries(cpe_match);
  CREATE INDEX idx_severity ON cve_entries(severity);
  ```
- [x] 🔴 Fungsi `init_database(path: &Path) -> Result<Connection>`
- [x] 🟢 Unit test: create, insert, query

### 8.2 NVD API Client
- [x] 🔴 Fungsi `fetch_cves_from_nvd(cpe: &str, api_key: Option<&str>) -> Result<Vec<CveEntry>>`:
  - HTTP GET ke `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}`
  - Parse response JSON → `Vec<CveEntry>`
  - Handle pagination (NVD returns max 2000 per request)
  - Handle rate limit (tanpa API key: 5 req/30s, dengan key: 50 req/30s)
- [x] 🟡 Retry logic: exponential backoff untuk 503/429
- [x] 🟢 Unit test: mock NVD response

### 8.3 CPE Builder
- [x] 🔴 Fungsi `build_cpe(tech: &TechStack) -> Option<String>`:
  - Map nama teknologi ke CPE vendor/product
  - Contoh: `nginx` + `1.18.0` → `cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*`
  - Gunakan lookup table untuk mapping yang benar
- [x] 🟡 Lookup table untuk 50 teknologi paling umum
- [x] 🟢 Unit test: mapping benar untuk nginx, Apache, PHP, WordPress, dll

### 8.4 CISA KEV Integration
- [x] 🟡 Fungsi `fetch_cisa_kev() -> Result<Vec<String>>`:
  - Download `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  - Parse → list CVE IDs yang sedang actively exploited
- [x] 🟡 Tandai CVE di database yang ada di KEV list → `exploitability = 'known_exploited'`
- [x] 🟢 Cache KEV list (expire 24 jam)

### 8.5 CVE Query & Orchestrator
- [x] 🔴 Fungsi publik `check_cves(tech_stacks: &[TechStack], config: &AppConfig) -> Vec<Vulnerability>`:
  - Untuk setiap tech dengan version → build CPE → query cache → jika miss, fetch dari NVD
  - Simpan ke cache
  - Return sebagai `Vulnerability` (tanpa payload, hanya info versi)
  - Prioritas: KEV entries mendapat severity bump
- [x] 🔴 CLI subcommand `temu cve update`:
  - Force refresh cache dari NVD + CISA KEV
  - Progress: "Updating CVE database... X entries cached"
- [x] 🟢 Integration test: tech stack → CVE matches

### 🏁 Sprint 8 — Definition of Done ✅
- CVE lookup berdasarkan teknologi terdeteksi berfungsi ✅
- Cache SQLite menyimpan hasil query ✅
- CISA KEV memberikan prioritas lebih tinggi ✅
- `temu cve update` berjalan ✅
- `cargo test --workspace` — 0 FAILED ✅
- `cargo clippy --all-targets` — no warnings ✅
- `cargo fmt --all --check` — formatted ✅

---

## Sprint 9 — Verifier Crate

**Goal:** Verifikasi hasil vulnerability scan untuk mengurangi false positive.

### 9.1 Time-based Verification
- [x] 🔴 Fungsi `verify_time_based(vuln: &Vulnerability, config: &AppConfig) -> VerifyResult`:
  ```rust
  pub enum VerifyResult {
      Confirmed { confidence: f32, proof: String },
      FalsePositive { reason: String },
      Inconclusive { reason: String },
  }
  ```
  - Kirim baseline request (tanpa payload) → catat response time
  - Kirim payload request → catat response time
  - Ulangi 3 kali untuk konsistensi
  - Jika waktu payload - baseline > threshold → Confirmed
  - Jika fluktuasi besar → Inconclusive
- [x] 🟡 Support SLEEP payload adjustment: jika threshold 5s, coba 3s dan 7s juga

### 9.2 Reflection Verification
- [x] 🔴 Fungsi `verify_reflection(vuln: &Vulnerability, config: &AppConfig) -> VerifyResult`:
  - Kirim unique random string sebagai payload (contoh: `temu_verify_abc123`)
  - Cek apakah string muncul di response body
  - Jika ya → reflection confirmed
  - Cek apakah string di-encode (HTML entity, URL encode) → tetap count
- [x] 🟡 Cek konteks reflection: apakah di dalam `<script>`, attribute, atau text node

### 9.3 General Verification
- [x] 🔴 Fungsi `verify_status_code(vuln: &Vulnerability, config: &AppConfig) -> VerifyResult`:
  - Kirim ulang request yang sama → pastikan status code konsisten
- [x] 🟡 Fungsi `verify_header(vuln: &Vulnerability, config: &AppConfig) -> VerifyResult`:
  - Cek apakah header yang mengindikasikan kerentanan masih ada

### 9.4 Verifier Orchestrator
- [x] 🔴 Fungsi publik `run_verification(vulns: &[Vulnerability], config: &AppConfig) -> Vec<Vulnerability>`:
  - Untuk setiap vulnerability → pilih metode verifikasi berdasarkan `MatchType`
  - Update `verified` field
  - Hapus/tandai yang `FalsePositive`
  - Log: "Verified X/Y vulnerabilities, Z false positives removed"
- [x] 🔴 Integrasi ke scan pipeline (setelah vulnerability scan, sebelum report)
- [x] 🟢 Unit test: time-based vuln → verified, non-vuln → false positive

### 🏁 Sprint 9 — Definition of Done ✅
- Verifier mengurangi false positive secara signifikan ✅
- Time-based dan reflection verification berfungsi ✅
- Pipeline: vuln scan → verify → report ✅
- `cargo test --workspace` — 0 FAILED ✅
- `cargo clippy --all-targets` — no warnings ✅
- `cargo fmt --all --check` — formatted ✅

---

## Sprint 10 — HTML Reporter

**Goal:** Laporan HTML interaktif yang bisa diaudit.

### 10.1 Tera Template Setup
- [ ] 🔴 Setup dependency `tera` di reporter crate
- [ ] 🔴 Buat folder `templates/` dengan:
  - `templates/report.html` — main template
  - `templates/partials/header.html`
  - `templates/partials/summary.html`
  - `templates/partials/vulns_table.html`
  - `templates/partials/assets_table.html`
  - `templates/partials/tech_stack.html`
  - `templates/partials/footer.html`

### 10.2 HTML Template Design
- [ ] 🔴 Header section:
  - Logo/nama scanner, tanggal scan, target domain
  - Durasi scan, total requests
- [ ] 🔴 Executive summary:
  - Pie chart/bar (CSS-only) jumlah vuln per severity
  - Total: X Critical, Y High, Z Medium, W Low
  - Risk rating keseluruhan
- [ ] 🔴 Vulnerability table:
  - Sortable by severity, name, URL
  - Kolom: ID, Name, Severity (color-coded), URL, Parameter, CVSS, Verified, Proof
  - Detail expandable per vulnerability
- [ ] 🟡 Assets table:
  - List semua subdomain/path ditemukan
  - Status code, technology detected
- [ ] 🟡 Tech stack overview:
  - Group by category (Web Server, Framework, CMS, dll)
- [ ] 🟢 Remediation recommendations per vulnerability type
- [ ] 🔴 Self-contained HTML: semua CSS inline (tidak perlu external file)

### 10.3 Generate Function
- [ ] 🔴 Fungsi `generate_html(result: &ScanResult, output_dir: &Path) -> Result<PathBuf>`:
  - Render template dengan data dari `ScanResult`
  - Nama file: `{date}_{domain}.html`
- [ ] 🔴 Integrasi ke CLI: `temu report generate --format html --input results.json`
- [ ] 🔴 Otomatis generate HTML setelah scan selesai (selain JSON)
- [ ] 🟢 Unit test: generate HTML, validasi tidak ada template error

### 🏁 Sprint 10 — Definition of Done
- HTML report ter-generate otomatis setelah scan
- Report berisi semua informasi: summary, vulns, assets, tech stack
- Self-contained (bisa dibuka tanpa internet)
- **Fase 2 selesai ✅**

---

# FASE 3 — Advanced (Sprint 11–16)

Tujuan: Network scanning, aturan deteksi CVE spesifik, PDF output, input CIDR dan file list.

---

## Sprint 11 — Network Scanning (Port + Banner)

**Goal:** Support scanning port terbuka dan banner grabbing.

### 11.1 Port Scanner
- [ ] 🔴 Fungsi `scan_ports(ip: IpAddr, ports: &[u16], config: &AppConfig) -> Vec<PortResult>`:
  ```rust
  pub struct PortResult {
      pub port: u16,
      pub state: PortState,       // Open, Closed, Filtered
      pub service: Option<String>,
      pub banner: Option<String>,
  }
  ```
  - TCP connect scan menggunakan `tokio::net::TcpStream`
  - Timeout per port (default 3 detik)
  - Async dengan semaphore
- [ ] 🔴 Default port list: top 100 most common ports
- [ ] 🟡 CLI flag: `--ports 80,443,8080` atau `--ports 1-1024`

### 11.2 Banner Grabbing
- [ ] 🔴 Fungsi `grab_banner(ip: IpAddr, port: u16) -> Option<String>`:
  - Connect ke port, kirim probe bytes (atau tunggu banner)
  - Baca response bytes (timeout 5 detik)
  - Decode sebagai UTF-8 (lossy)
- [ ] 🟡 Service identification dari banner:
  - SSH: `SSH-2.0-OpenSSH_8.x`
  - FTP: `220 ProFTPD`
  - SMTP: `220 mail.example.com ESMTP`
- [ ] 🟢 Integrasi banner ke fingerprinting (OS detection dari SSH banner)

### 11.3 Integrasi
- [ ] 🔴 Tambahkan port scan ke pipeline setelah discovery
- [ ] 🟡 Asset baru: `AssetType::Service` untuk setiap port terbuka
- [ ] 🟢 Update JSON/HTML report dengan port scan results

### 🏁 Sprint 11 — Definition of Done
- Port scanner menemukan port terbuka
- Banner grabbing mendeteksi service
- Hasil terintegrasi ke report

---

## Sprint 12 — CVE-Specific Detection Rules

**Goal:** Aturan deteksi untuk kerentanan CVE terkenal.

### 12.1 Rule Authoring
- [ ] 🔴 Tulis rules untuk 10 CVE terkenal:
  - `rules/cve-2021-44228-log4shell.yaml` (Log4j RCE)
  - `rules/cve-2021-41773-apache-path-traversal.yaml`
  - `rules/cve-2023-44487-http2-rapid-reset.yaml`
  - `rules/cve-2021-26855-exchange-ssrf.yaml` (ProxyLogon)
  - `rules/cve-2023-22515-confluence-rce.yaml`
  - `rules/cve-2021-34473-exchange-proxyshell.yaml`
  - `rules/cve-2022-22965-spring4shell.yaml`
  - `rules/cve-2019-19781-citrix-path-traversal.yaml`
  - `rules/cve-2023-46747-bigip-rce.yaml`
  - `rules/cve-2024-3400-palo-alto-rce.yaml`

### 12.2 Extended Rule Format
- [ ] 🔴 Tambahkan field ke `Rule` struct:
  ```rust
  pub cve_id: Option<String>,
  pub references: Vec<String>,     // URL referensi
  pub remediation: String,         // saran perbaikan
  pub request_method: HttpMethod,  // GET, POST, PUT, dll
  pub request_headers: HashMap<String, String>,  // custom headers
  pub request_body: Option<String>,              // POST body
  ```
- [ ] 🔴 Update rule loader untuk support field baru
- [ ] 🟡 Support multi-step detection (kirim request A, lalu request B)
- [ ] 🟢 Validasi rule: warning jika payload berbahaya (DELETE, DROP, dll)

### 12.3 Safe Payload Guidelines
- [ ] 🔴 Dokumentasi internal: payload harus read-only
- [ ] 🔴 Untuk Log4Shell: gunakan DNS callback ke domain controlled (contoh: `${jndi:ldap://UNIQUE_ID.oast.temu/a}`)
  - Atau gunakan pattern matching di response header/body tanpa actual callback
- [ ] 🟡 Warning di CLI jika rule menggunakan payload yang berpotensi destructive

### 🏁 Sprint 12 — Definition of Done
- 10 CVE-specific rules berfungsi
- Extended rule format didukung
- Payload aman (read-only)

---

## Sprint 13 — PDF Reporter

**Goal:** Generate laporan eksekutif dalam format PDF.

### 13.1 PDF Generation
- [ ] 🔴 Setup dependency `printpdf` atau `genpdf` di reporter crate
- [ ] 🔴 Fungsi `generate_pdf(result: &ScanResult, output_dir: &Path) -> Result<PathBuf>`
- [ ] 🔴 Layout PDF:
  - **Halaman 1**: Cover page (nama tool, target, tanggal, executive summary)
  - **Halaman 2**: Risk overview (tabel severity count, overall risk rating)
  - **Halaman 3+**: Detail vulnerability (1 vuln per section)
  - **Halaman terakhir**: Daftar assets dan rekomendasi umum
- [ ] 🟡 Color coding severity (Critical=merah, High=oranye, Medium=kuning, Low=hijau)
- [ ] 🟢 Header/footer dengan nomor halaman

### 13.2 Integrasi
- [ ] 🔴 CLI: `temu report generate --format pdf`
- [ ] 🟡 Auto-generate PDF bersama JSON dan HTML setelah scan
- [ ] 🟢 Unit test: generate PDF, validasi file valid

### 🏁 Sprint 13 — Definition of Done
- PDF report ter-generate dengan layout profesional
- Semua data vulnerability tercantum
- File PDF bisa dibuka di viewer standar

---

## Sprint 14 — Multi-Target Input (CIDR & File List)

**Goal:** Support scanning multiple target dari file dan CIDR range.

### 14.1 File List Input
- [ ] 🔴 CLI: `temu scan file --list targets.txt`
- [ ] 🔴 Format file: satu URL per baris
- [ ] 🔴 Implementasi: baca file → loop scan per target → aggregate results
- [ ] 🟡 Progress: "Scanning target 3/10: example.com"
- [ ] 🟢 Support komentar (`#`) di file list

### 14.2 CIDR Input
- [ ] 🔴 CLI: `temu scan network --cidr 192.168.1.0/24`
- [ ] 🔴 Parse CIDR → expand ke list IP
- [ ] 🔴 Untuk setiap IP: port scan → HTTP probe → full scan jika web service ditemukan
- [ ] 🟡 Skip RFC 1918 warning: "Scanning private network range"
- [ ] 🟢 Limit: max 65536 IP per CIDR (warning jika lebih)

### 14.3 Aggregated Report
- [ ] 🔴 Jika multi-target: generate 1 report gabungan + 1 report per target
- [ ] 🟡 Summary page: tabel semua target dengan jumlah vuln masing-masing
- [ ] 🟢 Sorting: target dengan vuln terbanyak di atas

### 🏁 Sprint 14 — Definition of Done
- Scan dari file list berjalan
- Scan dari CIDR berjalan
- Report gabungan ter-generate

---

## Sprint 15 — Advanced Vulnerability Detection

**Goal:** Teknik deteksi yang lebih canggih.

### 15.1 Blind SQL Injection (Time-based)
- [ ] 🔴 Rules: MySQL SLEEP, PostgreSQL pg_sleep, MSSQL WAITFOR DELAY
- [ ] 🔴 Adaptive timing: baseline → payload → cek delta > threshold
- [ ] 🟡 Support berbagai injection point: query param, header, cookie, POST body

### 15.2 Server-Side Request Forgery (SSRF)
- [ ] 🔴 Rules: redirect ke internal IP (127.0.0.1, 169.254.169.254)
- [ ] 🟡 Cek apakah response berisi internal service data

### 15.3 Path Traversal
- [ ] 🔴 Rules: `../../etc/passwd`, `..\\windows\\system32\\drivers\\etc\\hosts`
- [ ] 🔴 Encoding variations: URL encode, double encode, null byte

### 15.4 Open Redirect
- [ ] 🟡 Rules: redirect parameter → external domain
- [ ] 🟡 Cek `Location` header di response

### 15.5 Security Header Analysis
- [ ] 🔴 Cek missing headers: `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, `Strict-Transport-Security`
- [ ] 🔴 Report sebagai `Severity::Low` atau `Severity::Info`
- [ ] 🟢 Rekomendasi spesifik untuk setiap missing header

### 🏁 Sprint 15 — Definition of Done
- Blind SQLi time-based detection berfungsi
- SSRF, path traversal, open redirect rules tersedia
- Security header analysis berjalan

---

## Sprint 16 — Stabilisasi Fase 3

**Goal:** Bug fixing, test coverage, dan polish.

### 16.1 Test Coverage
- [ ] 🔴 Unit test coverage minimal 70% per crate
- [ ] 🔴 Integration test untuk setiap pipeline path
- [ ] 🟡 Benchmark test: scan 100 URLs, ukur waktu dan memory

### 16.2 Error Handling Review
- [ ] 🔴 Semua error ter-handle (tidak ada `unwrap()` di production code)
- [ ] 🟡 Graceful degradation: jika 1 modul gagal, lanjutkan modul lain
- [ ] 🟢 Error summary di akhir scan

### 16.3 Documentation
- [ ] 🔴 Update README.md lengkap
- [ ] 🟡 Rustdoc untuk setiap public function
- [ ] 🟢 Contoh penggunaan untuk setiap subcommand
- [ ] 🟢 CONTRIBUTING.md: cara menambah rules baru

### 🏁 Sprint 16 — Definition of Done
- Test coverage ≥ 70%
- Tidak ada panic/unwrap di production
- Dokumentasi lengkap
- **Fase 3 selesai ✅**

---

# FASE 4 — Optimasi & Stabilisasi (Sprint 17–20)

Tujuan: Performance tuning, distributed scanning, benchmarking.

---

## Sprint 17 — Rate Limit Adaptif & Resilience

**Goal:** Scanner cerdas menyesuaikan kecepatan berdasarkan response target.

### 17.1 Adaptive Rate Limiting
- [ ] 🔴 Deteksi throttling: jika response 429 atau response time naik > 3x baseline
- [ ] 🔴 Implementasi exponential backoff:
  - Level 1: kurangi rate 50%
  - Level 2: kurangi rate 75%
  - Level 3: pause 30 detik, lalu retry
- [ ] 🔴 Recovery: naikkan rate bertahap jika response normal kembali
- [ ] 🟡 Log: "Rate adjusted: 50 rps → 25 rps (server throttling detected)"

### 17.2 Connection Pooling
- [ ] 🟡 Konfigurasi `reqwest::Client` connection pool optimal
- [ ] 🟡 Reuse TCP connections ke host yang sama
- [ ] 🟢 Metrics: jumlah connections aktif, reuse rate

### 17.3 Retry Logic
- [ ] 🔴 Retry otomatis untuk network error (timeout, connection reset)
- [ ] 🔴 Max retry: 3 kali per request
- [ ] 🟡 Jitter: random delay antar retry (hindari thundering herd)

### 🏁 Sprint 17 — Definition of Done
- Rate limit adaptif berfungsi (backoff saat throttled)
- Retry logic menangani transient failures
- Scanner tidak meng-crash target

---

## Sprint 18 — Performance Optimization

**Goal:** Capai target 1000 request/detik, memory < 500MB.

### 18.1 Profiling
- [ ] 🔴 Profile dengan `cargo flamegraph` → identifikasi bottleneck
- [ ] 🔴 Memory profiling dengan `heaptrack` atau `valgrind`
- [ ] 🟡 Identifikasi top 5 hotspot

### 18.2 Optimasi
- [ ] 🔴 Lazy compilation regex (gunakan `once_cell` / `LazyLock`)
- [ ] 🟡 Streaming response body (jangan buffer seluruh body jika tidak perlu)
- [ ] 🟡 Gunakan `rayon` untuk CPU-bound tasks (YAML parsing, regex matching)
- [ ] 🟡 Reduce allocations: reuse buffers, gunakan `&str` daripada `String` dimana mungkin
- [ ] 🟢 Benchmark: ukur req/s sebelum dan sesudah optimasi

### 18.3 Static Binary
- [ ] 🔴 Build statically linked binary untuk Linux x86_64:
  ```
  RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --target x86_64-unknown-linux-gnu
  ```
- [ ] 🟡 Build untuk macOS arm64
- [ ] 🟢 CI/CD: GitHub Actions workflow untuk multi-platform build

### 🏁 Sprint 18 — Definition of Done
- ≥ 1000 req/s pada hardware referensi
- Memory < 500MB untuk 10k host scan
- Static binary tersedia untuk Linux dan macOS

---

## Sprint 19 — Distributed Scanning (Optional)

**Goal:** Support scanning terdistribusi via Redis.

### 19.1 Redis Integration
- [ ] 🟡 Setup dependency `redis` crate
- [ ] 🟡 Definisikan task queue:
  ```
  Queue: temu:tasks      → list of scan tasks (JSON)
  Queue: temu:results     → list of scan results (JSON)
  Key:   temu:status:{id} → scan status per task
  ```
- [ ] 🟡 Worker mode: `temu worker --redis redis://localhost:6379`
  - Poll tasks dari queue
  - Jalankan scan
  - Push results ke results queue

### 19.2 Coordinator Mode
- [ ] 🟡 `temu coordinator --redis redis://localhost:6379 --list targets.txt`
  - Distribusi targets ke workers via Redis
  - Collect results
  - Generate aggregate report
- [ ] 🟢 Dashboard sederhana: jumlah workers, tasks pending/done

### 19.3 Scaling Test
- [ ] 🟢 Test dengan 3 workers, 100 targets
- [ ] 🟢 Ukur speedup vs single worker

### 🏁 Sprint 19 — Definition of Done
- Distributed scanning via Redis berfungsi
- Multiple workers bisa scan secara paralel
- Aggregate report dari distributed scan

---

## Sprint 20 — Benchmarking & Final Polish

**Goal:** Bandingkan dengan tools populer, final release preparation.

### 20.1 Benchmarking vs Popular Tools
- [ ] 🔴 Setup test environment: 5 target websites (self-hosted vulnerable apps)
  - DVWA, OWASP Juice Shop, WebGoat, HackTheBox machines
- [ ] 🔴 Benchmark vs **nmap** (port scanning speed & accuracy)
- [ ] 🔴 Benchmark vs **ffuf** (path fuzzing speed)
- [ ] 🔴 Benchmark vs **nuclei** (vulnerability detection accuracy)
- [ ] 🟡 Dokumentasi hasil: tabel perbandingan speed, accuracy, false positive rate
- [ ] 🟢 Tuning berdasarkan hasil benchmark

### 20.2 Security Audit
- [ ] 🔴 `cargo audit` — cek dependency vulnerabilities
- [ ] 🔴 `cargo clippy` — fix semua warnings
- [ ] 🟡 Review: pastikan tool tidak bisa disalahgunakan (rate limit enforced, scope enforced)

### 20.3 Release Preparation
- [ ] 🔴 Version bump ke `1.0.0`
- [ ] 🔴 Update CHANGELOG.md
- [ ] 🔴 Tag git: `v1.0.0`
- [ ] 🟡 Binary release di GitHub Releases
- [ ] 🟡 README final: installation, usage, examples, contributing
- [ ] 🟢 Homebrew formula (macOS)
- [ ] 🟢 AUR package (Arch Linux)

### 🏁 Sprint 20 — Definition of Done
- Benchmark results documented
- No dependency vulnerabilities
- v1.0.0 released
- **Project complete ✅**

---

# Ringkasan Sprint

| Sprint | Fase | Focus | Deliverable |
|--------|------|-------|-------------|
| 1 | MVP | Project setup + Core crate | Workspace, structs, config, logging |
| 2 | MVP | Discovery crate | Subdomain bruteforce + HTTP probing |
| 3 | MVP | Fingerprint + Fuzzing + Vuln (dasar) | Header detection, path fuzz, YAML rules |
| 4 | MVP | CLI + JSON Reporter + Integration | End-to-end scan, JSON output |
| 5 | Enhance | Discovery enhancement | CT logs, zone transfer |
| 6 | Enhance | Fingerprint enhancement | Wappalyzer rules (50+ tech) |
| 7 | Enhance | Parameter fuzzing + recursive | Hidden params, recursive path |
| 8 | Enhance | CVE Client | NVD integration, SQLite cache |
| 9 | Enhance | Verifier | False positive reduction |
| 10 | Enhance | HTML Reporter | Interactive HTML report |
| 11 | Advanced | Network scanning | Port scan + banner grabbing |
| 12 | Advanced | CVE-specific rules | 10 CVE detection rules |
| 13 | Advanced | PDF Reporter | Executive PDF report |
| 14 | Advanced | Multi-target input | CIDR + file list support |
| 15 | Advanced | Advanced vuln detection | Blind SQLi, SSRF, path traversal |
| 16 | Advanced | Stabilisasi | Tests, error handling, docs |
| 17 | Optimasi | Rate limit adaptif | Smart backoff, retry |
| 18 | Optimasi | Performance | 1000 req/s, static binary |
| 19 | Optimasi | Distributed scanning | Redis-based distributed scan |
| 20 | Optimasi | Benchmark & release | v1.0.0 release |
