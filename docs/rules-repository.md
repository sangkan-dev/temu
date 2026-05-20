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

`temu rules update` reads `rules-manifest.json` from the raw repository base URL.

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
  ]
}
```

## Workflows

The cron workflow belongs in `temu-rules`, not in `temu`.

`update-rules.yml` should:

- Run on `schedule` and `workflow_dispatch`.
- Fetch upstream fingerprints/CVE/network references into `upstream/`.
- Validate YAML/JSON syntax.
- Open a pull request instead of committing directly to `main`.

`validate-rules.yml` should:

- Run on pull requests.
- Validate YAML syntax.
- Validate that first-party vulnerability and network rules use read-only payloads.
- Validate `rules-manifest.json` paths exist.

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
```

The engine repository should keep `.github/workflows/release.yml` and other engine checks only.
