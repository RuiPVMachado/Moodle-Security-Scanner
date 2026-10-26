# Moodle Security Scanner 2.0

Evidence-based security testing for Moodle LMS.

Version 2.0 replaces the old hard-coded CVE tables and heuristic "Critical"
findings with live advisory data, exact version matching, passive checks and
a small number of actively confirmed tests. Every finding is labelled with
its source and whether it was actively verified.

> **Authorization required.** Use this tool only against Moodle installations
> you own or have written permission to test. Active modules (`xss`, `sqli`,
> `lfi`) send requests to application logic and must not be used against
> third-party sites.

## Principles

- **No invented CVEs.** CVEs come from OSV.dev, not from a hand-written
  table. Moodle Security Announcements remain the manual authority for
  advisories whose CVE is still pending.
- **Version != exploit.** A version match means "this release is in a known
  affected range"; it is not proof that the vulnerability is exploitable on
  this deployment.
- **Two evidence classes.** Findings are either `verified` (the scanner
  observed the behaviour) or `version` (OSV advisory match). Reports keep them
  separate.
- **Bounded and respectful.** Requests have timeouts, response-size caps,
  retries, a global rate limiter and per-module concurrency.
- **No destructive payloads.** The scanner does not upload shells, create
  questions, attempt authentication bypasses or send `alert(1)`.

## Installation

```bash
git clone https://github.com/RuiPVMachado/Moodle-Security-Scanner.git
cd Moodle-Security-Scanner
python -m pip install -r requirements.txt
```

Python 3.10+ is supported.

## Quick start

```bash
# Fast, mostly passive assessment
python moodle_scanner.py -t https://moodle.example.com --profile fast -o report.json

# Balanced: version/CVE, passive, auth, API, reflected-XSS canaries, plugin inventory
# (includes the inert reflected-XSS canary, so use it only with authorization)
python moodle_scanner.py -t https://moodle.example.com --authorized -o report.html

# Deep, authorized test with credentials
python moodle_scanner.py -t https://moodle.example.com \
  --profile deep --authorized \
  --username auditor --password '***' \
  -o report.sarif
```

The scanner first requests the homepage, extracts `M.cfg.wwwroot` and rebases
all requests on the real Moodle root. If the target is not Moodle it aborts
unless `--force` is passed. If the exact release cannot be fingerprinted,
supply it explicitly with `--moodle-version 4.1.11` so the CVE matcher can
still work.

## Profiles

| Profile | Modules | Typical use |
| --- | --- | --- |
| `fast` | version, cve, passive, auth, api | CI, quick exposure review |
| `balanced` (default) | fast + xss, plugin, session | Normal assessment |
| `deep` | balanced + sqli, lfi, rce | Authorized penetration test |
| `external` | cve, passive, api, xss, sqli, lfi, plugin, supplychain | Black-box, no credentials |
| `all` | every registered module | Explicit full run |

`--modules` accepts a comma-separated list and overrides the profile's module
list. `version` is always executed first. `--no-active` removes `xss`, `sqli`,
`lfi`, `rce` and `session`.

For a contracted black-box assessment without any Moodle account:

```bash
python moodle_scanner.py -t https://moodle.example.com \
  --profile external --authorized \
  --rate-limit 5 -o external-report.json
```

This profile never tries to log in or guess credentials. It uses the
version/CVE layer, passive exposure checks, API/CORS/open-redirect checks,
inert reflected-XSS canaries, differential SQLi, LFI signatures, component
inventory and `composer.lock` supply-chain matching.

## Modules

| Module | What it does | Evidence |
| --- | --- | --- |
| `version` | Extracts `M.cfg.wwwroot`, mobile `$CFG->version`, generator/comment metadata and `lib/upgrade.txt` | Exact release or branch with confidence |
| `cve` | Queries OSV.dev for `moodle/moodle` by exact version; enriches with CISA KEV and FIRST EPSS; optional safe validators | Version-based advisories + validation status |
| `passive` | HTTPS/HSTS/TLS certificate/CSP/XFO/cookie flags, exposed backups/`.git`/`.env`/SQL dumps/phpinfo/Adminer, directory listing, debug errors, `security.txt` | Direct response evidence |
| `auth` | Login form CSRF token, optional credential login, optional default-credential test, optional Host-header bypass | Confirmed only |
| `api` | REST token checks, `service-nologin`, XML-RPC discovery, admin web-service exposure, CORS, open redirect, debug errors | Confirmed data/response |
| `xss` | Reflected HTML-injection canaries (`<mss...>`), no JavaScript execution | Raw reflection of both canaries |
| `sqli` | Differential database-error payloads; time-based only with `--deep` | Two payloads vs two controls |
| `lfi` | `/etc/passwd`, `win.ini`, Moodle `config.php` (raw or base64) signatures | Actual file content |
| `rce` | Explicit coverage marker. Known RCEs are matched by `cve`; exposures by `passive` | No destructive checks |
| `plugin` | Conservative component inventory via `version.php` reachability; source disclosure if served as text | Inventory only |
| `session` | Session-fixation check with credentials | Cookie unchanged across login |
| `supplychain` | If `composer.lock` is exposed, checks exact Packagist versions against OSV | Version-based dependency advisories |

## Vulnerability data

The scanner does not maintain a CVE list. It uses:

- **OSV.dev** — `POST https://api.osv.dev/v1/query` with
  `{"package":{"name":"moodle/moodle","ecosystem":"Packagist"},"version":"4.1.11"}`.
  OSV returns affected ranges, fixed releases and CVSS vectors. Results are
  cached in `data/cache/` for 24 hours.
- **composer.lock** — if public, exact Packagist dependency versions are sent
  to OSV's batch API. This can reveal vulnerable libraries that Moodle core
  advisories do not cover.
- **CISA KEV** — `known_exploited_vulnerabilities.json` for prioritisation.
- **FIRST EPSS** — `https://api.first.org/data/v1/epss` for exploitation
  probability.
- **Moodle Security Announcements** — `https://moodle.org/security/` is the
  authoritative source for advisories whose CVE is still `Pending`. OSV
  advisories usually link to the corresponding MSA; the scanner does not
  scrape the MSA page automatically.
- **Moodle plugins directory API** — `https://download.moodle.org/api/1.3/pluglist.php`
  for component/version metadata. It is not a vulnerability database.

`data/moodle_version_map.json` maps the numeric `$CFG->version` value
(e.g. `2026042004`) to the official release (`5.2.4`). It is generated from
Moodle git tags and can be regenerated when a new release is published:

```bash
python scripts/build_version_map.py
```

## CVE validation: version match vs. working exploit

A version match answers **"is this release in the affected range?"**. It does
not prove that the vulnerable code path is reachable on this deployment.
The scanner therefore labels every CVE finding with a validation status:

| Status | Meaning |
| --- | --- |
| `available` | A safe read-only validator exists; run it with `--validate-cves --authorized` |
| `confirmed` | The safe validator observed the vulnerable behaviour (not full exploitation) |
| `not-confirmed` | The safe validator did not observe it; could be patched, backported or blocked |
| `not-observed` | The target required authentication or the request failed |
| `manual` | Requires an authenticated/state-changing action; not automated |

Currently there is a safe validator for **CVE-2025-26533** (SQL injection in
the course search module list filter). It sends a non-existent module name;
vulnerable Moodle tries to use it as a table name and returns a database read
exception. No SQL payload is injected and nothing is modified.

```bash
python moodle_scanner.py -t https://moodle.example.com \
  -m version,cve --validate-cves --authorized \
  --offline --no-enrich -o cve-report.json
```

CVEs that require creating a calculated question, uploading a file,
restoring a backup, changing grades, or using a browser/account are marked
`manual` with the reason. That is deliberate: automatically "proving" those
would be an exploit framework, not a scanner. Version matches remain
`version` findings until a safe check or manual validation confirms them.

## Reports

| Format | Command | Notes |
| --- | --- | --- |
| JSON | `-o report.json` | Full structured output, schema 2.0 |
| HTML | `-o report.html` | Escaped output, severity badges, CVSS/EPSS/KEV |
| TXT | `-o report.txt` | Manager-friendly plain text |
| SARIF | `-o report.sarif` | GitHub Code Scanning / CI integration |

For CI:

```bash
python moodle_scanner.py -t "$MOODLE_URL" --profile fast --offline \
  --fail-on High -o report.sarif
```

`--fail-on Critical|High|Medium|Low` exits with code `2` when a finding at or
above the threshold exists. `--offline` uses cached OSV/KEV/EPSS data only.

## Accuracy and limitations

- No scanner can guarantee zero false positives. This tool reduces them by
  requiring controls, real file signatures, exact versions and explicit
  labels, and by refusing to call a page "vulnerable" just because it returned
  HTTP 200.
- Reflected-XSS findings prove HTML injection, not JavaScript execution. A
  browser confirmation is still required for an executable-XSS claim.
- SQLi error-based findings prove an error delta, not full data extraction.
- A CVE marked `confirmed` by a safe validator means the vulnerable behaviour
  was observed, not that data was extracted or code executed. Full exploitation
  is out of scope.
- Version-based findings must be confirmed against the installed build and
  patches; backports and vendor builds can change applicability.
- Plugin CVEs require the plugin version. The `plugin` module reports an
  inventory and source disclosure, not unverified plugin CVEs.
- Stored XSS, DOM XSS, SSRF, deserialization and authenticated business-logic
  flaws require a browser, a test account and a dedicated manual assessment.

## Development

```bash
ruff check .
mypy modules moodle_scanner.py
pytest -q
pip-audit -r requirements.txt
```

The test suite uses local mock HTTP responses and does not scan the internet.
CI runs lint, type checking and tests on Python 3.11 and 3.13.

## Legacy entry points

`moodle_security_scanner.py` remains a deprecated wrapper for
`moodle_scanner.py`. `results_to_txt.py` and `results_to_docx.py` can convert
an existing JSON report into manager-oriented TXT/DOCX files.

## Disclaimer

This tool is provided for educational and legitimate security testing only.
The authors accept no liability for misuse or damage caused by this program.
