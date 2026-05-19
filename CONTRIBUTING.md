# Contributing to Temu

Temu is a Rust CLI scanner for authorized security assessment. Contributions should keep the scanner safe, deterministic, and useful for analysts.

## Development Checks

Run these before handing off a change:

```bash
cargo fmt --all --check
cargo clippy --all-targets
cargo test --workspace
cargo build
```

Use Rust only. Do not add unsafe code, FFI, or external services for core scanner behavior.

## Adding Vulnerability Rules

Rules live in `rules/*.yaml`. One file should contain one rule.

Required structure:

```yaml
id: "SQLI-MYSQL-TIME"
name: "Time-based SQL injection (MySQL)"
tech_stack: ["mysql", "mariadb"]
severity: critical
cvss: 9.8
payload: "' OR SLEEP(5) -- "
request_method: GET
verify:
  match_type: TimeBased
  response_codes: [200, 500]
  time_threshold_secs: 5
remediation: "Use parameterized queries."
references:
  - "https://owasp.org/www-community/attacks/SQL_Injection"
```

Supported verify types:

- `StatusCode`
- `BodyContains`
- `BodyRegex`
- `HeaderContains`
- `TimeBased`

Optional advanced fields:

```yaml
baseline_payload: "temu-baseline"
injection_points: [QueryParam, Header, Cookie, Body]
injection_name: "temu_probe"
request_headers:
  X-Temu-Probe: "readonly"
request_body: "q={{payload}}"
```

## Rule Safety Requirements

Payloads must be read-only.

Do not use payloads containing:

- `DROP`, `DELETE`, `UPDATE`, `INSERT`, `TRUNCATE`, `ALTER`, `CREATE`
- command execution markers such as `cmd.exe`, `/bin/sh`, `bash -c`, `powershell`
- reverse shell, callback, exfiltration, or destructive denial-of-service behavior

Prefer:

- timing probes with low thresholds,
- benign reflection markers,
- response header/status checks,
- path traversal probes that only attempt to read standard non-secret indicators,
- SSRF probes that use loopback/link-local indicators without outbound callbacks.

## Tests

Add or update tests with every behavior change. Tests must run offline. Use local mocks such as `wiremock` instead of real external APIs or public targets.

For new rules, ensure `cargo test -p vulnerability` passes and the workspace rule loader accepts the file.

## Documentation

Update README usage examples when adding or changing CLI flags. Add rustdoc for new public functions and types.
