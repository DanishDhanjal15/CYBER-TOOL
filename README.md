# WebRecon

A from-scratch **Python CLI web vulnerability scanner**. Point it at a URL or IP
and it runs reconnaissance plus a battery of common web attack checks, then
produces a color-coded terminal summary and detailed **HTML + JSON** reports.

> ⚠️ **Authorized testing only.** Use WebRecon strictly against systems you own
> or have **explicit written permission** to test. Unauthorized scanning may be
> illegal. The tool asks you to confirm authorization before every scan.

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
