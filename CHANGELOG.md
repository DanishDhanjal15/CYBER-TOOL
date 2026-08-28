# Changelog

All notable changes to WebRecon are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-08-28

Initial public release.

### Scanning engine
- 26 default web checks + 1 opt-in: security headers, cookies, CORS, HTTP
  methods, directory listing, info disclosure, JWT, CSRF, open redirect, XSS,
  SQLi, command injection, path traversal, SSTI, SSRF, IDOR, secrets/JS, NoSQL,
  host-header, CRLF, XXE, GraphQL, CVE matching, rate-limiting, templates,
  DOM-XSS (browser), and opt-in brute-force.
- Validation-first: every finding carries a confidence level and, where
  applicable, a copy-paste PoC.
- OAST out-of-band listener to confirm blind SSRF / RCE.
- Nuclei-style YAML template engine (bundled + `--templates`).
- Optional headless-browser (Playwright) DOM-XSS + screenshots.
- Authenticated/grey-box scanning (`--cookie`, `--header`, `--auth-bearer`).
- OpenAPI/Swagger ingestion, scan profiles (quick/standard/deep).

### Intelligence & workflow
- SQLite scan history, baseline + diff (`--baseline` / `--diff`), `history`.
- Finding dedup + attack-path correlation.
- CVE matching with EPSS + CISA KEV, and Exploit-DB / Metasploit exploit
  availability (plus optional local `searchsploit`).
- Continuous monitoring with alerts (webhook / Slack / Discord / email / log).
- Rate-limiting detection + per-endpoint algorithm recommendations.

### Extra analyzers
- `mlscan` — ML model backdoor / supply-chain scanner.
- `cicd` — CI/CD workflow vulnerability scanner with patches.
- `predict` — HPC / data-centre early-failure prediction from telemetry.

### Reporting
- Console, HTML, JSON, and SARIF (GitHub code-scanning) reports.

### Safety
- Authorization gate on every scan; intrusive checks are opt-in with attempt
  caps and lockout awareness.
