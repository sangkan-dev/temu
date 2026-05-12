# Product Requirements Document (PRD)
## Temu - Automated Cybersecurity Scanner

**Version:** 1.0  
**Target Language:** Rust (stable)  
**Architecture:** Modular crate-based workspace  

---

## 1. Vision & Goals

### 1.1 Vision
Membangun *scanner* keamanan siber otomatis yang cepat, andal, dan mudah diperluas, khusus untuk kebutuhan perusahaan (internal red team, security assessment, monitoring). Menggantikan tools tradisional berbasis Python yang lambat pada skala besar.

### 1.2 Goals
- Scanning subdomain, path, parameter, dan teknologi dengan kecepatan tinggi.
- Deteksi kerentanan berbasis aturan dinamis (tidak hardcode payload).
- Integrasi data CVE terbaru dari NVD, CISA KEV, dan Exploit-DB.
- Hasil akurat, *false positive* rendah, dan laporan yang dapat diaudit (JSON, HTML, PDF).
- Arsitektur modular (crates) sehingga setiap komponen dapat dikembangkan dan diuji secara independen.

### 1.3 Non-Goals
- Tidak mengeksploitasi kerentanan secara aktif (hanya verifikasi *proof-of-concept* ringan).
- Tidak untuk scanning tanpa izin (hanya izin internal/perusahaan).
- Tidak mendukung GUI untuk rilis awal (CLI dulu).

---

## 2. Alur Bisnis dan Fitur Utama

Alur bisnis sesuai dengan spesifikasi pengguna:

```text
1. Requirement Gathering & Scope Definition
   ↓
2. Asset Discovery (Subdomain, IP, URL)
   ↓
3. Fingerprinting & Service Enumeration
   ↓
4. Vulnerability Identification (CVE & custom rules)
   ↓
5. Verification (mengurangi false positive)
   ↓
6. Risk Prioritization (CVSS + konteks aset)
   ↓
7. Reporting & Remediation Tracking
```

Setiap tahap diimplementasikan sebagai modul terpisah.

---

## 3. Arsitektur Modular (Crates)

Kita akan menggunakan **Cargo workspace** dengan crate-crate berikut:

| Crate | Fungsi | Dependensi eksternal |
|-------|--------|----------------------|
| `core` | Struktur data bersama (Target, Asset, Vulnerability, dll), logger, config | `serde`, `tracing`, `anyhow` |
| `discovery` | Asset discovery: subdomain bruteforce, CT logs, zone transfer | `trust-dns-proto`, `reqwest`, `tokio` |
| `fingerprint` | Deteksi teknologi (Wappalyzer rules, WAF, OS, web server, framework) | `regex`, `reqwest`, `yaml-rust` |
| `fuzzing` | Path & parameter fuzzing (asinkron, banyak payload) | `tokio`, `reqwest`, `dashmap` |
| `vulnerability` | Load aturan deteksi (YAML), eksekusi payload, bandingkan respon | `yaml-rust`, `reqwest`, `chrono` |
| `cve_client` | Ambil data CVE dari NVD, CISA KEV, cache lokal | `reqwest`, `sqlx` (opsional: SQLite) |
| `verifier` | Verifikasi hasil (ulang payload, cek false positive) | `core`, `vulnerability` |
| `reporter` | Generate laporan (JSON, HTML, PDF) | `serde_json`, `tera` (templating), `printpdf` |
| `cli` | Entrypoint utama, parsing argumen, koordinasi antar modul | `clap`, `tokio` |

Setiap crate akan diuji terpisah dengan `cargo test`.

---

## 4. Spesifikasi Detail per Modul

### 4.1 Core Crate
- Struct `Target` → `domain: String`, `ip_list: Vec<IpAddr>`, `scope: Scope` (include/exclude regex).
- Struct `Asset` → `url: String`, `type: AssetType` (Subdomain, Path, Parameter, IP).
- Struct `Vulnerability` → `id: String`, `name: String`, `severity: Severity`, `cvss_score: f32`, `proof: String`.
- Fungsi konfigurasi dari file TOML (rate limit, timeout, concurrent limit).

### 4.2 Discovery Crate
- **Subdomain bruteforce**: baca file kamus (`.txt`), kirim DNS query async (gunakan `trust-dns-proto`), filter NXDOMAIN. Support wildcard detection.
- **Certificate Transparency logs**: query ke `crt.sh` atau Google CT API, parsing JSON.
- **Zone transfer**: coba `AXFR` jika nameserver mengizinkan.
- **HTTP/HTTPS probing**: untuk subdomain ditemukan, cek apakah live (status 2xx/3xx).
- **Output**: daftar `Asset::Subdomain` dan `Asset::URL`.

### 4.3 Fingerprinting Crate
- **Teknologi web**: implementasi subset dari Wappalyzer patterns (YAML). Deteksi berdasarkan headers (Server, X-Powered-By), HTML meta tags, script sources.
- **WAF detection**: kirim payload `' OR 1=1 -- ` dan lihat jika response code 403/406 serta header `X-Sucuri-ID` dll.
- **OS detection** (jika port terbuka): analisis banner dari TCP handshake (gunakan `tokio::net::TcpStream` dengan timeout).
- **Framework/Library version**: parsing dari response body/style seperti `jQuery v3.5.1`.
- **Outcome**: struktur `TechStack { name, version, confidence }`.

### 4.4 Fuzzing Crate
- **Path fuzzing**: kamus path umum (`/admin`, `/backup`, `.git/HEAD`). Async HTTP `GET` dengan rate limit.
- **Parameter fuzzing** (query argumen): tambahkan parameter acak (`?xyz=1`) dan bandingkan response dengan baseline.
- **Recursive scanning**: setiap path yang ditemukan (status 200/403) akan di-fuzz lagi dengan kamus sub-path.
- **Concurrency**: gunakan `tokio::spawn` dengan semaphore. Default 100 concurrent.
- **Output**: daftar `Asset::Path` dan `Asset::Parameter`.

### 4.5 Vulnerability Crate
- **Aturan deteksi** disimpan di folder `/rules/` dalam YAML. Setiap aturan mengandung:
  ```yaml
  id: SQLI-MYSQL-TIME
  name: "Time-based SQL injection (MySQL)"
  tech_stack: ["mysql", "mariadb"]
  severity: Critical
  cvss: 9.8
  payload: "' OR SLEEP(5) -- "
  verify:
    time_threshold_secs: 5
    response_codes: [200, 500]
  ```
- **Loader**: baca semua file `.yaml` dari folder, parse ke struct `Rule`.
- **Executor**: untuk setiap aturan yang `tech_stack` cocok dengan hasil fingerprinting, kirim payload ke target endpoint (fuzz parameter atau path).
- **Matcher**: bandingkan response time, status code, body content (regex) sesuai aturan.
- **Output**: `Vulnerability` terdeteksi dengan `proof`.

### 4.6 CVE Client Crate
- **Sinkronisasi** dengan NVD API v2.0 setiap 24 jam (wajib ada API key optional).
- **Parse CPE** dari fingerprinting (contoh nginx:1.18.0 menjadi `cpe:2.3:a:nginx:nginx:1.18.0`).
- **Query ke cache lokal** (SQLite) untuk CVE yang cocok dengan CPE.
- **Filter** berdasarkan *exploitability* (CISA KEV diberi prioritas lebih tinggi).
- **Output**: daftar `Vulnerability` dari CVE (tanpa payload, hanya informasi versi).

### 4.7 Verifier Crate
- **Kirim ulang payload** yang menandakan kerentanan dengan parameter acak/konfirmasi.
- **Eliminasi false positive**: misal untuk Time-based blind, bandingkan waktu response dengan baseline normal (non-payload).
- **Kesimpulan**: `Vulnerability::verified = true/false`.

### 4.8 Reporter Crate
- **Output format**: JSON (machine readable), HTML (dashboard sederhana), PDF (laporan eksekutif).
- **Isi:** ringkasan total assets, kerentanan per prioritas, rekomendasi perbaikan.
- **Template HTML** menggunakan `tera`.

### 4.9 CLI Crate
- Gunakan `clap` dengan subcommands:
  - `scan single --url https://example.com`
  - `scan file --list targets.txt`
  - `scan network --cidr 192.168.1.0/24`
  - `cve update` (memperbarui database lokal)
  - `report generate --format html`
- **Parameter rate limit**: `--rate 100` (request/detik)
- **Timeout**: `--timeout 10` (detik)
- **Output path**: `--output ./results/`

---

## 5. Data Flow (Contoh Skenario)

1. User jalankan: `rustscan scan single --url https://staging.company.com --rate 50`
2. **CLI** → `core::Config` → inisialisasi logger, baca rules.
3. **Discovery** → enumerasi subdomain via CT logs dan bruteforce. Ketemu `admin.staging.company.com`.
4. **Fingerprinting** → request ke setiap subdomain, deteksi `nginx/1.18.0`, `PHP/7.4`.
5. **Fuzzing** → coba path `/api/v1/users` (dari kamus) → ketemu parameter `?id=`.
6. **Vulnerability** → muat aturan `SQLI-TIME`, cocok dengan `tech_stack: mysql`, kirim payload `' OR SLEEP(5)` ke `?id=`. Response time > 5 detik.
7. **CVE Client** → cek versi nginx → ambil CVE-2021-23017 (contoh) dari cache.
8. **Verifier** → kirim ulang `' OR SLEEP(6)` → waktu 6 detik. Konfirmasi.
9. **Risk Prioritization** → CVSS 9.8 (Critical) + aset `admin.staging.company.com` termasuk internal = Critical.
10. **Reporter** → generate HTML dan JSON.
11. Output disimpan di `./results/2025-05-12_staging_company.html`

---

## 6. Persyaratan Non-Fungsional

| Parameter | Target |
|-----------|--------|
| Kecepatan scanning | Minimal 1000 request/detik per core |
| Memory usage | < 500 MB untuk scanning 10k host |
| False positive rate | < 5% untuk tipe kerentanan umum (SQLi, XSS) |
| Akurasi fingerprinting | Minimal 90% untuk 500 website teratas (Alexa) |
| Update CVE cache | 1x setiap 24 jam, cache berlaku 7 hari |
| Portabilitas | Binary statically linked, jalan di Linux x86_64 dan macOS arm64 |

---

## 7. Roadmap Pengembangan

### Fase 1 (MVP) - 4 minggu
- [ ] Setup workspace + core crate.
- [ ] Discovery: subdomain bruteforce sederhana + HTTP probing.
- [ ] Fingerprint: deteksi web server (header `Server`).
- [ ] Fuzzing: path fuzzing async dengan kamus kecil.
- [ ] Vulnerability: muat aturan YAML statis (SQLi reflection).
- [ ] CLI: subcommand `scan single`.
- [ ] Reporter: JSON.

### Fase 2 (Enhance) - 6 minggu
- [ ] CT logs dan wildcard detection di discovery.
- [ ] Wappalyzer rules (200+ deteksi framework).
- [ ] Parameter fuzzing.
- [ ] CVE client integrasi NVD + cache SQLite.
- [ ] Verifier (time-based).
- [ ] Laporan HTML.

### Fase 3 (Advanced) - 6 minggu
- [ ] Recursive path fuzzing.
- [ ] Network scanning (port open + banner grabbing).
- [ ] Aturan deteksi untuk CVE spesifik (misal Log4Shell).
- [ ] Output PDF.
- [ ] Dukungan input CIDR dan file list.

### Fase 4 (Optimasi & Stabilisasi)
- [ ] Rate limit adaptif (backoff jika server throttle).
- [ ] Distributed scanning (opsional, via Redis).
- [ ] Benchmarking vs popular tools (nmap, ffuf, nuclei).

---

## 8. Risiko dan Mitigasi

| Risiko | Mitigasi |
|--------|-----------|
| Target website crash karena terlalu banyak request | Rate limit default 50 rps, bisa diatur oleh user. Gunakan `tower::limit` |
| False positive tinggi untuk deteksi CVE berbasis versi | Prioritaskan verifier (payload ringan) sebelum report |
| DNS wildcard menyebabkan subdomain palsu | Kirim request HTTP random subdomain untuk baseline, filter yang menghasilkan status sama |
| Payload berbahaya merusak data | Gunakan payload read-only (contoh: `' AND 1=2 --`), hindari update/delete. Verifikasi hanya dengan SLEEP/benchmark |

---

## 9. Cara Kontribusi / Ekstensi

- **Menambah aturan deteksi baru**: cukup tambahkan file `.yaml` ke `/rules/`, tanpa mengubah kode Rust.
- **Menambah kamus path/subdomain**: letakkan `.txt` di `/dictionaries/`, lalu discovery crate membaca dari sana.
- **Menambah fingerprint rule**: edit file `fingerprint_rules.yaml` (format wappalyzer).

---

## 10. Referensi Teknologi

- **HTTP client**: `reqwest` dengan `rustls` (bukan OpenSSL untuk static build).
- **DNS**: `trust-dns-proto` + `trust-dns-resolver`.
- **Async runtime**: `tokio` (current thread scheduler untuk efisiensi).
- **Parsing HTML**: `scraper` atau `lol_html`.
- **Regex**: `regex` crate (lazy_static untuk kompilasi sekali).
- **Parallelism**: `rayon` untuk tugas CPU-bound (parser YAML).
