# Safe Payload Guidelines

Temu rules must stay detection-only and read-only.

- Do not use payloads that modify data, such as `DROP`, `DELETE`, `UPDATE`, `INSERT`, or `TRUNCATE`.
- Do not use payloads that execute commands, open shells, download files, or trigger reverse callbacks.
- Prefer version, header, status-code, and benign endpoint checks before active proof checks.
- For Log4Shell-style detection, use a benign marker or controlled out-of-band domain only when explicitly configured by the operator.
- If a rule needs multiple requests, use `detection_steps` and keep every step read-only.
- Rules that include risky payload markers are still loaded, but the loader emits a warning so CLI runs surface the issue.
