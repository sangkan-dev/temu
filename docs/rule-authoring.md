# Temu Rule Authoring

Temu rules are YAML documents loaded at runtime from `rules_dir`. This keeps
detection content updateable without recompiling the scanner.

## Schema Version

New rules should declare:

```yaml
schema_version: "1"
```

Rules without `schema_version` are treated as legacy schema v1 for backward
compatibility. Rules declaring any other version are rejected by
`temu rules validate` and skipped by the runtime loader.

## Required Fields

```yaml
schema_version: "1"
id: "EXAMPLE-REFLECTION"
name: "Example reflected marker"
metadata:
  author: "sangkan-dev"
  license: "MIT"
  source: "https://example.com/rules/example"
  last_verified: "2026-05-24"
compatibility:
  minimum_temu_version: "1.3.0"
  required_capabilities: ["http", "query_param"]
tech_stack: []
severity: medium
cvss: 5.3
payload: "temu-reflection-check"
risk_level: safe
requires_confirmation: false
injection_points: [QueryParam]
injection_name: "q"
request_method: GET
verify:
  match_type: BodyContains
  response_codes: [200]
  body_contains: "temu-reflection-check"
cve_id: null
remediation: "Validate and encode reflected input."
references:
  - "https://owasp.org/www-community/attacks/xss/"
```

## Risk Model

Safe rules run by default. Any rule that is intrusive, destructive, DoS-prone,
time-based, or OAST-aware must declare a non-safe `risk_level` and
`requires_confirmation: true`; users must also pass `--allow-risky-rules`.

Allowed `risk_level` values:

- `safe`
- `intrusive`
- `destructive`
- `dos`
- `unknown`

OAST placeholders such as `{{callback_url}}` and `{{callback_id}}` are always
treated as risky.

## Marketplace Metadata

Marketplace-ready rules should include:

- `metadata.author`
- `metadata.license`
- `metadata.source`
- `metadata.last_verified`
- `compatibility.minimum_temu_version`
- `compatibility.required_capabilities`

Known capabilities currently include:

- `http`
- `headers`
- `body`
- `query_param`
- `cookie`
- `multi_step`
- `time_based`
- `oast`
- `browser_crawl`
- `api_discovery`
- `stateful_dast`
- `network_service`
- `tls_fingerprint`

## Network Service Rules

Network checks use a separate schema and never enter the HTTP path/payload
executor. They match protocol evidence already collected by read-only service
profiling:

```yaml
schema_version: "1"
rule_type: network
id: "NETWORK-REDIS-NO-AUTH"
name: "Redis accepts commands without authentication"
metadata:
  author: "sangkan-dev"
  license: "MIT"
compatibility:
  minimum_temu_version: "1.5.0"
  required_capabilities: ["network_service"]
protocols: ["redis"]
products: ["Redis"]
severity: high
cvss: 8.6
risk_level: safe
requires_confirmation: false
matcher:
  protocol_response_regex: "(?i)^\\+PONG"
  auth_required: false
remediation: "Require authentication and restrict network exposure."
```

Available network matchers are `banner_regex`, `protocol_response_regex`,
`status_handshake`, `tls_detected`, and `auth_required`. A rule must include at
least one matcher. The scanner supplies sanitized banner/handshake evidence,
protocol, product, version, confidence, and observed TLS metadata in reports.

Network rules must remain read-only. Authentication brute force, data mutation,
service reconfiguration, and DoS/crash validation are not valid safe rules.

## Validation And Checksums

Validate rules locally:

```bash
temu rules validate --rules-dir ./rules
```

Generate a deterministic checksum manifest for release review:

```bash
temu rules checksum --rules-dir ./rules
```

The checksum output includes one SHA-256 per YAML file and a bundle SHA-256 over
the sorted file manifest. Publish it alongside external rules releases so users
can audit rule bundle drift.

## Rust-Native Extensions

Rust-native detector, fingerprint, and verifier traits exist for compile-time
extension modules. They are intentionally not dynamic runtime plugins. Prefer
YAML rules unless custom logic cannot be represented safely in schema v1.
