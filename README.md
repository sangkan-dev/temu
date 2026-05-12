# Temu

*"Nggoleki oyoting masalah, nemokake celahé, ndandani saka dasar."*
*(Mencari akar masalah, menemukan celahnya, memperbaiki dari fondasi.)*

Temu is an automated cybersecurity scanner built in Rust. 
Like a Javanese philosopher tracing the origin of all things, 
Temu traces every vulnerability back to its root — 
whether it's a misconfigured header, an exposed subdomain, 
or a time-based blind injection sleeping beneath the surface.

---

**Philosophy:**  
In the spirit of *"Sangkan Paraning Dumadi"*, we believe that 
true security comes from understanding the origin of a problem. 
Temu does not just report *what* is broken, 
but helps you understand *why* it broke and *how* to fix it properly.

---

## Build

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test --workspace
```

## Usage

```bash
# Scan a single target (full pipeline: discovery → fingerprint → fuzz → vuln scan)
cargo run -p cli -- scan single --url https://target.example.com

# With options
cargo run -p cli -- scan single \
  --url https://target.example.com \
  --mode hybrid \
  --rate 30 \
  --timeout 10 \
  --output ./results \
  --verbose

# Release binary
./target/release/temu scan single --url https://target.example.com

# Report subcommand
temu report generate --format json --input ./results/2025-05-12_target.json

# Discovery modes: bruteforce | heuristic | passive | hybrid (default)
```

## Output

JSON report is written to `./results/{date}_{domain}.json`:

```json
{
  "target": "https://example.com",
  "scan_started_at": "2025-05-12T10:00:00Z",
  "scan_finished_at": "2025-05-12T10:00:45Z",
  "stats": {
    "subdomains_found": 5,
    "paths_found": 12,
    "vulns_found": 2,
    "duration_secs": 45.2
  },
  "assets": [...],
  "tech_stacks": { "https://example.com": [...] },
  "vulnerabilities": [...]
}
```

## Project Structure

```text
temu/
├── crates/
│   ├── temu_core/       # Shared types, config, logging, errors
│   ├── discovery/       # Subdomain enumeration (DNS bruteforce, CT logs, heuristic)
│   ├── fingerprint/     # Technology detection (headers, body, WAF)
│   ├── fuzzing/         # Path fuzzing with baseline anti-false-positive
│   ├── vulnerability/   # YAML rule loading, filtering, execution
│   ├── reporter/        # JSON report generation
│   └── cli/             # CLI entrypoint (clap), scan orchestrator
├── rules/               # YAML detection rules
├── dictionaries/        # Wordlists for subdomain + path fuzzing
├── config/
│   └── default.toml     # Default configuration
└── results/             # Scan output (gitignored)
```

## Configuration

Override via `config/default.toml` or `TEMU_*` environment variables:

```toml
rate_limit = 50          # Requests per second
timeout_secs = 10
concurrency = 100
user_agent = "Temu/0.1.0"
output_dir = "./results"
rules_dir = "./rules"
dictionaries_dir = "./dictionaries"
```

Environment overrides: `TEMU_RATE_LIMIT`, `TEMU_TIMEOUT_SECS`, `TEMU_CONCURRENCY`, `TEMU_USER_AGENT`, `TEMU_OUTPUT_DIR`, `TEMU_RULES_DIR`, `TEMU_DICTIONARIES_DIR`.