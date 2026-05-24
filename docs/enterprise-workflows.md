# Enterprise Workflows

## Scheduled Target Profiles

Temu can execute one target profile from an external cron job:

```bash
temu schedule run --profile ./config/target-profile.example.toml --once
```

For a local long-running scheduler:

```bash
temu schedule run --profile ./config/target-profile.example.toml
```

The profile controls target scope, rate limit, optional authenticated session
profile, rules repository refresh, output directory, webhook, and the
`fail_on_severity` exit policy. With `--once`, a matching severity causes a
non-zero exit code suitable for CI or cron alerting.

## Baseline Diff And Suppression

Compare two scan JSON artifacts:

```bash
temu report diff \
  --baseline ./results/previous.json \
  --current ./results/current.json \
  --suppressions ./config/suppressions.example.toml
```

The diff classifies findings as `new`, `fixed`, `unchanged`, or
`severity_changed`. Suppressions require a reason and may set `expires_at`;
expired suppressions no longer hide findings.

## Trend History

Every normal scan or scheduled scan records target history in:

```text
results/.cache/scan_history.sqlite
```

Each report set also writes `*_trend.json`, and the HTML report renders the
available trend points for findings, assets, CVE findings, and scan duration.

## Team Exports

Normal scan report sets include SARIF and Markdown artifacts. Existing JSON
reports can also be converted explicitly:

```bash
temu report generate --format sarif --input ./results/current.json
temu report generate --format markdown --input ./results/current.json
```

Scheduled profiles can set `webhook_url`; Temu sends a concise JSON
`content` message compatible with common Slack/Discord incoming webhook
handlers after a completed scan.
