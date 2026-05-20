# Safe Payload Guidelines

Temu safe rules must stay detection-only and read-only.

- Do not use payloads that modify data, such as `DROP`, `DELETE`, `UPDATE`, `INSERT`, or `TRUNCATE`.
- Do not use payloads that execute commands, open shells, download files, or trigger reverse callbacks.
- Prefer version, header, status-code, and benign endpoint checks before active proof checks.
- For Log4Shell-style detection, use a benign marker or controlled out-of-band domain only when explicitly configured by the operator.
- If a rule needs multiple requests, use `detection_steps` and keep every step read-only.
- Rules that need intrusive, destructive, or DoS-prone probes must set `risk_level: intrusive`, `risk_level: destructive`, `risk_level: dos`, or `requires_confirmation: true`.
- Risky rules are still loaded, but Temu skips them unless the user enables `--allow-risky-rules` or `TEMU_ALLOW_RISKY_RULES=true`.
