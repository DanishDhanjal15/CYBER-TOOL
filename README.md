# WebRecon

**A from-scratch, offline Python CLI web-security scanner + vulnerability-management toolkit.**
Point it at a URL or IP and it runs reconnaissance plus 26+ web attack checks,
prioritises findings by real exploitability (CVE/EPSS/KEV + Exploit-DB),
tracks them over time, and can continuously monitor and alert — all locally,
with no cloud and no paid APIs.

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey.svg)
![Status](https://img.shields.io/badge/status-beta-orange.svg)

> ⚠️ **Authorized testing only.** Use WebRecon strictly against systems you own
> or have **explicit written permission** to test. Unauthorized scanning,
> brute-forcing, or exploitation may be illegal. The tool asks you to confirm
> authorization before every scan. See [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md).

## Quick start

```bash
git clone https://github.com/DanishDhanjal15/CYBER-TOOL.git
cd CYBER-TOOL
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .

python -m webrecon scan http://testphp.vulnweb.com --authorize   # a public, authorized test target
python -m webrecon list-checks
```

Reports land in `./reports/` (open the `.html` in a browser). Full docs below.

## Contents

- [Features](#features) · [GUI](#gui-dark-theme) · [CLI usage](#cli-usage)
- [Rate-limiting audit](#rate-limiting-audit--algorithm-advice) ·
  [Brute-force audit](#weak-credential--brute-force-audit-opt-in) ·
  [Continuous monitoring](#continuous-monitoring--alerts)
- [Scan history & diff](#scan-history-diff--prioritization-vuln-management-features) ·
  [ML / CI-CD / failure-prediction analyzers](#beyond-web-scanning--three-more-analyzers)
- [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md) · [Code of Conduct](CODE_OF_CONDUCT.md)

---

## Features

**Reconnaissance**
- DNS records (A/AAAA/MX/NS/TXT) + reverse DNS
- Common-port TCP scan + banner grab
- TLS/SSL certificate & protocol audit (expiry, self-signed, legacy TLS)
- Technology fingerprinting (server/framework headers, meta generator)
- robots.txt / sitemap.xml + sensitive-file exposure probe (`.env`, `.git`, backups…)

**Vulnerability checks** (OWASP-aligned)

| Check name       | Detects                                            | OWASP |
|------------------|----------------------------------------------------|-------|
| `headers`        | Missing security headers (CSP, HSTS, X-Frame…)     | A05   |
| `cookies`        | Missing HttpOnly / Secure / SameSite               | A05   |
| `cors`           | Wildcard / reflected CORS origin                   | A05   |
| `methods`        | Dangerous HTTP methods (TRACE/PUT/DELETE)          | A05   |
| `dirlisting`     | Directory listing enabled                          | A05   |
| `infodisclosure` | Version banners, verbose stack traces              | A05/A06 |
| `csrf`           | POST forms without anti-CSRF token                 | A01   |
| `openredirect`   | Open redirect via redirect-style params            | A01   |
| `xss`            | Reflected cross-site scripting                     | A03   |
| `sqli`           | SQL injection (error-based; time-based aggressive) | A03   |
| `cmdi`           | OS command injection                               | A03   |
| `traversal`      | Path traversal / local file inclusion              | A01   |
| `ssti`           | Server-side template injection (7*7 → 49)          | A03   |
| `ssrf`           | Server-side request forgery (cloud-metadata + OOB) | A10   |
| `jwt`            | Insecure JWT (alg=none, no expiry, secret claims)  | A02   |
| `idor`           | IDOR heuristic on object-reference params          | A01   |
| `secrets`        | Hard-coded secrets / source maps / internal hosts in JS | A05 |
| `nosqli`         | NoSQL (MongoDB) operator injection                 | A03   |
| `hostheader`     | Host header injection (reset-link/cache poisoning) | A03   |
| `crlf`           | CRLF injection / HTTP response splitting            | A03   |
| `xxe`            | XML external entity injection                       | A05   |
| `graphql`        | GraphQL introspection / IDE exposure               | A05   |
| `templates`      | YAML template engine (extensible CVE/misconfig)    | —     |
| `domxss`         | DOM-based XSS via real headless browser (Playwright) | A03 |

**Recon also flags:** subdomain takeover (dangling CNAME), missing/weak SPF·DMARC·DNSSEC (email spoofing), and deprecated TLS versions.

**Validation-first:** every finding carries a **confidence** level
(`CONFIRMED` / `PROBABLE` / `POTENTIAL`) and, where applicable, a **copy-paste
PoC** (a `curl` command) that reproduces it — so you can verify before acting.

**Reporting**
- Rich colored console summary with severity breakdown + 0–100 risk score
- Self-contained **HTML** report (executive summary, per-finding cards with
  evidence / impact / remediation / references, recon table)
- **JSON** report for automation / re-use

**Safety**
- Authorization confirmation gate (`--authorize` to skip the prompt)
- Non-destructive by default; intrusive tests behind `--aggressive`
- Rate limiting, timeouts, same-host crawl scope, custom User-Agent

---

## Install

```bash
cd tool
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux/Mac: source .venv/bin/activate
pip install -r requirements.txt
# or install as a command:
pip install -e .
```

## Rate-limiting audit + algorithm advice

The `ratelimit` check (runs by default) sends a short polite burst to
representative endpoints — homepage, login forms, and a diverse sample of API /
search / param URLs — and detects whether the server throttles (HTTP 429,
`RateLimit-*` / `Retry-After` headers, or a "too many requests" body). It stops
as soon as throttling is seen.

Crucially, for every endpoint it also **recommends the right algorithm for that
endpoint type** and where to enforce it:

| Endpoint type | Recommended algorithm | Why |
|---------------|-----------------------|-----|
| **auth / login** | Sliding Window Counter (per-account) + per-IP + exponential backoff | resist credential stuffing; no window-edge burst |
| **read API** | Token Bucket (per API key/IP) | allows short bursts, smooth refill |
| **write / mutation** | Sliding Window Counter (tighter limits) | accurate, stops spam |
| **search / export** | Leaky Bucket (constant drain) | protects the backend from spikes |
| **upload** | Token Bucket + per-user quota | caps bandwidth/storage abuse |
| **general** | Sliding Window Counter (per IP) | accurate, cheap default |

A missing limiter on a **login** endpoint is a **HIGH** finding (brute-force /
credential-stuffing surface); on other endpoints it scales MEDIUM→LOW. When
rate limiting *is* present, it's reported as INFO with the detected mechanism.
Tune the burst size with `--rl-burst` (default 20).

## Weak-credential / brute-force audit (opt-in)

Test a login form against a password list and flag any account that accepts a
weak password, so you can change it. **Opt-in and authorized-only** — it never
runs in a normal scan.

```bash
# Try the bundled top-100 weak passwords against common usernames
python -m webrecon scan https://example.com --authorize --bruteforce

# Use rockyou.txt (or any list); cap total attempts; target a username
python -m webrecon scan https://example.com --authorize --bruteforce \
    --wordlist /path/to/rockyou.txt --username admin --max-attempts 500
```

**Safety rails (built in):**
- Never runs by default — only with `--bruteforce` (or `--checks bruteforce`),
  on top of the standard `--authorize` gate.
- **Attempt cap** (`--max-attempts`, default 200). rockyou has millions of
  entries; realistic *online* guessing tests the top-N — testing all of them
  would trigger lockout and act as a DoS.
- **Stops on lockout** — if the target signals account lockout / rate limiting,
  it stops and reports that as a *positive* control.
- If a weak password is accepted → **CRITICAL** finding with a "change it now +
  add lockout/rate-limit/MFA" remediation. If many attempts run with **no**
  lockout at all → a **MEDIUM** "no brute-force protection" finding.

## Scan history, diff & prioritization (vuln-management features)

Every scan is saved to a local SQLite database, so you can track a target over
time, see only what changed, and prioritise by real exploitability.

```bash
# First scan — save it as the baseline for this target
python -m webrecon scan https://example.com --authorize --baseline

# Later scan — show only what's NEW or FIXED since the baseline
python -m webrecon scan https://example.com --authorize --diff

# List past scans (risk score + severity counts + which is the baseline)
python -m webrecon history
python -m webrecon history --target https://example.com

# One-off scan without touching history
python -m webrecon scan https://example.com --authorize --no-store
```

**What runs automatically on every scan:**
- **Dedup** — duplicate detections of the same issue collapse into one (noise ↓).
- **Correlation / attack chains** — related findings combine into higher-signal
  meta-findings (e.g. *exposed .env + hard-coded AWS key → credential-exposure
  chain*, *XSS + no CSP*, *multiple RCE-class injections*).
- **CVE matching (`cve` check)** — product/library versions from banners and JS
  bundles are matched to a bundled CVE database and ranked by **EPSS**
  (exploit probability) and **CISA KEV** (proven exploited in the wild). Extend
  it with `--cve-db <your.json>`.
- **Exploit intelligence** — each matched CVE is enriched with public-exploit
  availability: **Exploit-DB** IDs, **Metasploit** module presence, and (if the
  local `searchsploit` CLI is installed) a live offline Exploit-DB search. A CVE
  with a working exploit is tagged **`[EXPLOIT AVAILABLE]`**, marked CONFIRMED,
  and — when it's also KEV — escalated to CRITICAL, because it's low-effort for
  an attacker. Findings link straight to the Exploit-DB entry. *(VulnDB is a
  paid product with no free API; the free equivalents used here are Exploit-DB,
  Metasploit, and NVD.)*

Flags: `--db <path>` (history DB, default `webrecon.db`), `--no-store`,
`--diff`, `--baseline`, `--cve-db <path>`.

## Continuous monitoring & alerts

Keep watching a target (or a whole list) and get alerted the moment a **new**
vulnerability appears. Each cycle scans, diffs against the previous scan, and
fires alerts only on new findings — the first scan becomes the baseline.

```bash
# Watch one target every hour; alert on new HIGH/CRITICAL findings via Slack/Discord
python -m webrecon monitor https://example.com --authorize \
    --interval 1h --min-severity high \
    --webhook https://hooks.slack.com/services/XXX/YYY/ZZZ

# Watch many targets from a file, log alerts to a JSONL file
python -m webrecon monitor --targets-file targets.txt --authorize \
    --interval 30m --log-file alerts.jsonl

# Single cycle (for cron / CI / testing) instead of a persistent loop
python -m webrecon monitor https://example.com --authorize --once --webhook <url>

# Email alerts (SMTP)
python -m webrecon monitor https://example.com --authorize --interval 6h \
    --email-to you@corp.com --smtp-host smtp.corp.com \
    --smtp-user bot --smtp-pass '***'
```

**Alert channels:** console (always), **webhook** (Slack / Discord / Teams /
generic JSON — auto-detected), **JSONL log file**, and **SMTP email**. A broken
channel never stops the loop. `--min-severity` gates what's worth alerting on;
`--profile quick|standard|deep` sets scan depth per cycle. Run it under your OS
scheduler (systemd/Task Scheduler) or leave it running — Ctrl+C stops it.

## Beyond web scanning — three more analyzers

WebRecon also ships three offline analyzers that reuse the same reporting
pipeline (console + HTML + JSON). They are heuristic/static (no AI, no network)
and produce the same colour-coded, PoC-carrying findings.

```bash
# 1) ML backdoor / model supply-chain scan
#    Detects code-execution backdoors in model files (pickle __reduce__ RCE,
#    Keras Lambda) and unsafe loading / undefended federated training in code.
python -m webrecon mlscan ./path/to/models_or_repo

# 2) CI/CD workflow vulnerability scan (+ patches)
#    Flags poisoned pipelines, script injection, unpinned actions, secret leaks,
#    broad token perms, curl|bash — each finding includes a copy-paste patch.
python -m webrecon cicd ./path/to/repo

# 3) HPC / data-centre early-failure prediction
#    Statistical prediction over telemetry (SMART / ECC / thermal): per-component
#    risk score + estimated time-to-failure + recommended action.
python -m webrecon predict ./telemetry.csv        # or .json
```

**What they detect**

| Command   | Detects | Remediation shipped |
|-----------|---------|---------------------|
| `mlscan`  | pickle RCE-on-load, Keras Lambda, `torch.load` w/o `weights_only`, `pickle/yaml.load`, `trust_remote_code=True`, federated aggregation with no robust/DP defenses, unverified training data | safetensors, `weights_only=True`, Krum/trimmed-mean/Bulyan, clipping+DP, Neural Cleanse/STRIP, data provenance |
| `cicd`    | `pull_request_target` poisoning, `${{ github.event.* }}` script injection, unpinned actions, `write-all` token, secrets echoed, `curl\|bash`, hardcoded credentials | before/after YAML patch per finding |
| `predict` | SMART 5/187/197/198 sectors, rising ECC errors, sustained thermals, wear — with trend extrapolation & z-score anomaly | proactive replacement / workload migration + time-to-failure window |

> These are honest offline models: `mlscan` inspects artifacts **without loading
> them**; `predict` is statistical (thresholds + linear trend + anomaly), not a
> trained deep model. Both are designed to run in CI and on exported data.

## GUI (dark theme)

A desktop GUI ships alongside the CLI (built on Tkinter — no extra install):

```bash
python -m webrecon.gui
# or, after `pip install -e .`
webrecon-gui
```

Enter a target, tick **"I am authorized to scan this target"**, and hit
**Scan**. You get a live log, a colour-coded findings table with a detail pane
(description / impact / remediation / evidence), a Recon tab, and buttons to
open the generated HTML/JSON reports.

## CLI usage

```bash
# Basic scan (asks for authorization confirmation)
python -m webrecon scan http://testphp.vulnweb.com

# Skip the prompt (you confirm authorization via the flag)
python -m webrecon scan http://testphp.vulnweb.com --authorize

# Enable intrusive tests, more crawling, verbose output
python -m webrecon scan https://example.com --authorize --aggressive --depth 3 -v

# Only run specific checks
python -m webrecon scan https://example.com --authorize --checks headers,cookies,sqli

# List available checks
python -m webrecon list-checks

# Scan profiles: quick (fast), standard (default), deep (thorough + intrusive)
python -m webrecon scan https://example.com --authorize --profile deep

# Authenticated / grey-box scan (scan behind a login)
python -m webrecon scan https://example.com --authorize \
    --cookie "session=abc123" --header "X-Api-Key: xyz"
python -m webrecon scan https://example.com --authorize --auth-bearer <JWT>

# Seed API endpoints from an OpenAPI / Swagger spec (headless API testing)
python -m webrecon scan https://api.example.com --authorize \
    --openapi ./openapi.json --checks sqli,ssti,ssrf,idor

# Emit SARIF for GitHub code-scanning / CI
python -m webrecon scan https://example.com --authorize -f html,json,sarif

# Confirm BLIND vulns (SSRF/RCE) out-of-band — needs a target-reachable listener
python -m webrecon scan https://example.com --authorize --oast \
    --oast-host your-public-host:9999

# Run extra YAML detection templates (Nuclei-style, drop-in extensible)
python -m webrecon scan https://example.com --authorize --templates ./my-templates/

# DOM-XSS + screenshots in a real headless browser (needs Playwright installed)
pip install playwright && playwright install chromium
python -m webrecon scan https://example.com --authorize --browser
```

### Out-of-band (OAST) confirmation
Blind SSRF, blind OS-command injection, and blind XXE produce no visible
response change. With `--oast`, WebRecon starts a callback listener and injects
payloads that make the target call it; a recorded callback upgrades the finding
to **CONFIRMED**. For real external targets, expose a reachable address with
`--oast-host host:port` (a public IP/port the target can reach).

### YAML template engine
`webrecon/data/templates/*.yaml` holds Nuclei-style detection rules (exposed
`.git`/`.env`, phpinfo, Spring actuator, Tomcat manager, …). Add your own `.yaml`
files and pass `--templates <dir>` — no Python needed. Schema is documented in
`webrecon/templates_engine/engine.py`.

### Scan profiles
| Profile    | Depth | Max URLs | Intrusive |
|------------|-------|----------|-----------|
| `quick`    | 1     | 40       | no        |
| `standard` | 2     | 150      | no        |
| `deep`     | 3     | 400      | yes       |

If installed with `pip install -e .`, use the `webrecon` command directly:

```bash
webrecon scan http://testphp.vulnweb.com --authorize
```

Reports are written to `./reports/` (override with `-o`). Open the `.html` file
in any browser.

### Exit codes
`0` clean · `1` High/Critical findings present · `2` bad target · `3`
authorization declined. Useful in CI to fail a build on serious findings.

---

## Safe practice targets

Test against intentionally vulnerable, authorized apps:
- `http://testphp.vulnweb.com` (public, by Acunetix)
- **OWASP Juice Shop** or **DVWA** (run locally in Docker)

---

## Project layout

```
webrecon/
  cli.py            CLI entrypoint
  engine.py         orchestrates recon -> crawl -> checks
  core/             target parsing, http client, crawler, config
  recon/            dns, ports, tls, fingerprint, files
  checks/           one module per vulnerability check (plugin style)
  model/            Finding / ScanResult / Severity
  report/           console, json, html renderers (+ jinja2 template)
  data/             payloads, wordlists, signatures
```

### Extending
Add a new check by subclassing `webrecon.checks.base.Check`, implementing
`run(target, http, crawl, config) -> list[Finding]`, and registering it in
`webrecon/checks/__init__.py`.

---

## Disclaimer
This software is provided for educational and authorized security assessment
purposes only. The authors accept no liability for misuse. Automated findings
may include false positives — always verify manually before acting.
