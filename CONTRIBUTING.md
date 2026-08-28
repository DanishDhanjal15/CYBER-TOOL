# Contributing to WebRecon

Thanks for your interest! WebRecon is built to be **easy to extend** — most
new coverage is a small, self-contained addition.

## Ground rules

- **Authorized-testing only.** Contributions must not encourage or enable
  unauthorized attacks. Keep the authorization gate and safety rails intact.
- Be respectful — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Dev setup

```bash
git clone https://github.com/DanishDhanjal15/CYBER-TOOL.git
cd CYBER-TOOL
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Linux/Mac: source .venv/bin/activate
pip install -e ".[dev]"     # installs the package + pytest
```

## Run the checks before you push

```bash
pytest -q                   # full unit-test suite
python smoke_test.py        # quick end-to-end sanity check
```

Both must pass. CI runs the same on every pull request.

## How to add things (no core changes needed)

**A new vulnerability check** — create `webrecon/checks/mycheck.py`:

```python
from webrecon.checks.base import Check
from webrecon.model.finding import Finding
from webrecon.model.severity import Severity

class MyCheck(Check):
    name = "mycheck"
    description = "What it detects."
    def run(self, target, http, crawl, config):
        # ... probe, then return a list of Finding(...)
        return []
```

Register it in `webrecon/checks/__init__.py` (add to `_REGISTRY`, or `_OPTIN`
if it is intrusive). Add a test in `tests/`.

**A new detection template** — drop a `.yaml` file in
`webrecon/data/templates/` (schema is documented in
`webrecon/templates_engine/engine.py`). No Python required.

**New CVEs** — add entries to `webrecon/data/cve/known_cves.json`
(`edb_id`/`msf` optional, for exploit intelligence).

**New payloads** — extend the lists in `webrecon/data/payloads/`.

## Pull requests

- Keep PRs focused; one feature/fix per PR.
- Include a test for new behavior.
- Match the surrounding code style (stdlib-first, minimal deps, clear names).
- Update `README.md` / `CHANGELOG.md` if you add user-facing features.

## Reporting bugs / ideas

Open an issue with steps to reproduce (for bugs) or a clear use case (for
features). For security issues in WebRecon itself, see [SECURITY.md](SECURITY.md).
