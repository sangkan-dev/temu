# Temu Rules Repository

Decision: keep `https://github.com/sangkan-dev/temu` as the scanner engine repository and use `https://github.com/sangkan-dev/temu-rules` as the rules-as-code repository.

Why:

- Rule updates can happen daily without touching engine release history.
- Upstream cache changes from Wappalyzer, FingerprintHub, NVD, and future network sources can be reviewed separately.
- Temu users can fork `temu-rules` and point `TEMU_RULES_REPO_URL` or `temu rules update --repo-url` to their own raw repository URL.
- Engine releases stay reproducible because bundled rules remain versioned in `temu`, while external rules are opt-in updates.

## Repository Layout

```text
temu-rules/
├── .github/workflows/
│   ├── update-rules.yml
│   └── validate-rules.yml
├── staging/
│   └── candidates/              # Non-executable CVE candidate descriptors
├── fingerprint/
│   └── fingerprint_rules.yaml
├── vulnerability/
│   ├── sql-injection.yaml
│   ├── xss.yaml
│   └── cve/
│       └── 2026.yaml
├── network/
│   ├── ssh.yaml
│   ├── tls.yaml
│   └── http-banner.yaml
├── upstream/
│   ├── fingerprint/
│   ├── cve/
│   └── network/
├── rules-manifest.json
└── README.md
```

## Manifest

`temu rules update` reads `rules-manifest.json` from the raw repository base URL. Rules are written to `rules_dir`; dictionary files are written to `dictionaries_dir`.

```json
{
  "fingerprint": "fingerprint/fingerprint_rules.yaml",
  "vulnerability": [
    "vulnerability/sql-injection.yaml",
    "vulnerability/xss.yaml",
    "vulnerability/cve/2026.yaml"
  ],
  "network": [
    "network/ssh.yaml",
    "network/tls.yaml",
    "network/http-banner.yaml"
  ],
  "dictionaries": [
    "dictionaries/paths-small.txt",
    "dictionaries/parameters-small.txt",
    "dictionaries/subdomains-small.txt",
    "dictionaries/subdomains-medium.txt"
  ]
}
```

## Workflows

The cron workflow belongs in `temu-rules`, not in `temu`.

`update-rules.yml` should:

- Run on `schedule` and `workflow_dispatch`.
- Fetch upstream fingerprints/NVD/CISA KEV/Exploit-DB/network/dictionary references into `upstream/`.
- Promote low-risk fingerprint and dictionary updates into active files.
- Generate CVE candidate descriptors in `staging/candidates/` with `executable: false`, `risk_level: unknown`, and `requires_confirmation: true`.
- Validate YAML/JSON syntax.
- Open a pull request instead of committing directly to `main`.

`validate-rules.yml` should:

- Run on pull requests.
- Validate YAML syntax.
- Validate that first-party vulnerability and network rules declare risk correctly.
- Validate `rules-manifest.json` paths exist, including dictionary paths.
- Reject any `staging/` candidate path in `rules-manifest.json`.

## Temu Integration

Default raw URL:

```text
https://raw.githubusercontent.com/sangkan-dev/temu-rules/main
```

Usage:

```bash
temu rules update
temu rules update --repo-url https://raw.githubusercontent.com/sangkan-dev/temu-rules/main
TEMU_RULES_REPO_URL=https://raw.githubusercontent.com/example/custom-temu-rules/main temu rules update
temu rules validate --rules-dir ./rules
temu rules checksum --rules-dir ./rules
temu rules simulate --rules-dir ./rules --target-fixture http://127.0.0.1:3000/
```

Risk policy:

- `risk_level: safe` rules run by default.
- `risk_level: intrusive`, `risk_level: destructive`, `risk_level: dos`, or `requires_confirmation: true` rules require `temu scan ... --allow-risky-rules` or `TEMU_ALLOW_RISKY_RULES=true`.
- NVD data should be used freely for metadata and candidate generation, but active probes must still carry a risk label because NVD does not distinguish read-only checks from crash, write, or RCE validation paths.
- CVE metadata findings state their CPE applicability reason and remain unverified until an active reviewed rule confirms the exposure.

Marketplace policy:

- New executable rules should use `schema_version: "1"`.
- Legacy rules without `schema_version` are accepted as schema v1, but external repositories should migrate them before publication.
- Rule metadata should include `author`, `license`, `source`, and `last_verified`.
- Compatibility should declare `minimum_temu_version` and any `required_capabilities`.
- Release PRs should attach the output of `temu rules checksum` so reviewers can compare deterministic SHA-256 bundle drift.

The engine repository should keep `.github/workflows/release.yml` and other engine checks only.
