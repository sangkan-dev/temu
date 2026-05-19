# Benchmarking

Tanggal baseline: 2026-05-19.

## Environment

Benchmark berjalan lewat Docker Compose supaya target rentan tidak mengotori host.

```bash
docker compose --profile benchmark up -d juice-shop webgoat dvwa benchmark-nginx benchmark-httpbin
docker compose build temu
```

Target lokal:

| Target | URL container | URL host |
|--------|---------------|----------|
| OWASP Juice Shop | `http://juice-shop:3000` | `http://127.0.0.1:3000` |
| OWASP WebGoat | `http://webgoat:8080/WebGoat` | `http://127.0.0.1:8081/WebGoat` |
| DVWA | `http://dvwa` | `http://127.0.0.1:8082` |
| Nginx static target | `http://benchmark-nginx` | `http://127.0.0.1:8083` |
| HTTPBin | `http://benchmark-httpbin` | `http://127.0.0.1:8084` |

## Commands

Temu single target:

```bash
docker compose run --rm temu scan single --url http://juice-shop:3000 --ports 80,3000,8080
```

Temu distributed:

```bash
docker compose --profile distributed up -d redis
docker compose --profile distributed up -d --scale temu-worker=3 temu-worker
docker compose --profile distributed run --rm temu-coordinator
```

Port scan comparison:

```bash
nmap -p 80,3000,8080 127.0.0.1
cargo run -p cli -- scan single --url http://127.0.0.1:3000 --ports 80,3000,8080
```

Path fuzzing comparison:

```bash
ffuf -u http://127.0.0.1:3000/FUZZ -w dictionaries/paths-small.txt
cargo run -p cli -- scan single --url http://127.0.0.1:3000
```

Vulnerability detection comparison:

```bash
nuclei -u http://127.0.0.1:3000 -severity low,medium,high,critical
cargo run -p cli -- scan single --url http://127.0.0.1:3000
```

## Baseline Results

| Area | Tool | Dataset | Result |
|------|------|---------|--------|
| Aggregation/report data path | Temu | 10,000 synthetic findings | 0.23s |
| Memory profile | Temu | Release binary report path | 10.45 MB heap peak, 25.25 MB RSS peak |
| Distributed throughput | Temu | 100 local HTTP targets, 3 workers | 186.53s |
| Single-worker baseline | Temu | 15 local HTTP targets | 82.16s |
| Port scanning | nmap | `benchmark-nginx`, ports 80 and 8083 | 0.04s, detected 8083 open and 80 closed |
| Port scanning and scan pipeline | Temu | `benchmark-nginx`, ports 80 and 8083 | 15.55s, detected 1 open service, nginx/1.31.0, 4 security-header findings |
| Path fuzzing | ffuf | `benchmark-nginx`, 122 dictionary entries | 0.13s |
| Vulnerability detection | nuclei | `benchmark-nginx` | Stopped after 60s with no output in local smoke run |
| Full vulnerable apps | Temu, nmap, ffuf, nuclei | Juice Shop, WebGoat, DVWA, nginx, HTTPBin | Compose profile prepared; full image pull is required before running the complete matrix |

## Tuning Notes

- Regex-heavy paths use cached compiled regex values.
- Report aggregation uses parallel iteration where the input size is large enough to benefit.
- HTTP response bodies are capped before expensive analysis.
- Adaptive rate limiting lowers pressure after repeated transient failures.
- Distributed scanning uses Redis queues so workers can be scaled independently.

## Accuracy Notes

Accuracy benchmarking should count:

- True positives: findings confirmed by the vulnerable app documentation or manual validation.
- False positives: findings that fail verifier checks or are not reproducible.
- False negatives: known vulnerable routes missed by Temu.

Do not run destructive templates or exploit payloads during comparison. Nuclei templates must be limited to detection-only checks.
