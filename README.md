# Moodle Security Scanner 2.1

Evidence-based security testing for Moodle LMS.

Version 2.1 adds a shared authenticated session, Moodle Security Announcements
(MSA) matching for pending CVEs, a per-CVE safe-validation registry, a full
plugin inventory with version parsing, and an authenticated Moodle
configuration audit. Every finding keeps its source and whether it was
actively verified.

> **Authorization required.** Use this tool only against Moodle installations
> you own or have written permission to test. Active modules (`xss`, `sqli`,
> `lfi`, `rce`, `session`, `config`) are skipped unless `--authorized` is
> passed. They send requests to application logic and must not be used against
> third-party sites.

## Principles

- **No invented CVEs.** CVEs come from OSV.dev and Moodle Security
  Announcements, not from a hand-written table. MSA findings with a CVE
  still pending are labelled `MSA` instead of inventing an identifier.
- **Version != exploit.** A version match means "this release is in a known
  affected range"; it is not proof that the vulnerability is exploitable on
  this deployment.
- **Two evidence classes.** Findings are either `verified` (the scanner
  observed the behaviour) or `version` (OSV/MSA advisory match). Reports keep
  them separate.
- **Explicit authorization.** Active modules are removed from the run unless
  `--authorized` is supplied; the scan records which modules were skipped.
- **Bounded and respectful.** Requests have timeouts, response-size caps,
  retries, a shared rate limiter, a global request budget and same-host
  redirect policy.
- **No destructive payloads.** The scanner does not upload shells, create
  questions, attempt authentication bypasses, send `alert(1)`, or trigger
  restore/DoS paths.

## Installation

```bash
git clone https://github.com/RuiPVMachado/Moodle-Security-Scanner.git
cd Moodle-Security-Scanner
python -m pip install -r requirements.txt
```

Python 3.10+ is supported.

## Quick start

```bash
# One command: auto profile, one authorization prompt, optional login prompt,
# and a timestamped HTML report. Active modules are skipped if you answer no.
python moodle_scanner.py -t https://moodle.example.com

# Non-interactive version: assert authorization, read the password from stdin.
printf '%s' "$MOODLE_TEST_PASSWORD" | python moodle_scanner.py \
  -t https://moodle.example.com -y \
  --username auditor --password-stdin

# Fast, mostly passive assessment (no injection tests)
python moodle_scanner.py -t https://moodle.example.com --safe -o report.json

# Explicit balanced profile with an output format of your choice
python moodle_scanner.py -t https://moodle.example.com --authorized -o report.html

# Deep, authorized test with credentials.
# The session is created once and reused by every module.
printf '%s' "$MOODLE_TEST_PASSWORD" | python moodle_scanner.py \
  -t https://moodle.example.com \
  --profile deep --authorized \
  --username auditor --password-stdin \
  --max-requests 500 -o report.sarif
```

The default `auto` profile runs every module, skips active tests unless
authorized, and writes `moodle-scan-<host>-<timestamp>.html` when `-o` is
omitted. Use `--no-report` to print the console summary only, `--no-interactive`
for CI, and `-y` to assert written authorization without a prompt.

`--password`, `--password-stdin`, `--password-file` and the
`MOODLE_SCANNER_PASSWORD` environment variable are supported. Prefer stdin or
the environment variable so the password does not appear in the process list.

The scanner first requests the homepage, extracts `M.cfg.wwwroot` and rebases
all requests on the real Moodle root. If the target is not Moodle it aborts
unless `--force` is passed. If the exact release cannot be fingerprinted,
supply it explicitly with `--moodle-version 4.1.11` so the CVE matcher can
still work.

## Profiles

| Profile | Modules | Typical use |
| --- | --- | --- |
| `auto` (default) | every module, with active tests skipped until authorized | One-command assessment |
| `fast` | version, cve, passive, auth, api | CI, quick exposure review |
| `balanced` | fast + xss, config, plugin, session, supplychain | Normal authorized assessment |
| `deep` | balanced + sqli, lfi, rce | Authorized penetration test |
| `external` | cve, passive, api, xss, sqli, lfi, plugin, supplychain | Black-box, no credentials |
| `all` | every registered module | Explicit full run |

`--modules` accepts a comma-separated list and overrides the profile's module
list. `version` is always executed first. Active modules are skipped unless
`--authorized` is present. `--no-active` removes `xss`, `sqli`, `lfi`, `rce`,
`session` and `config`. `--auto`/`--full` are aliases for `auto`; `--safe` is
an alias for `fast`.

`config` is an authenticated read-only audit. It runs only when credentials or
cookies produced an authenticated session; otherwise it returns an Info entry
instead of guessing.

### Safety and request controls

- Credentials are resolved from `--password`, `--password-stdin`,
  `--password-file` or `MOODLE_SCANNER_PASSWORD`; the password is never logged.
- The scanner authenticates once and reuses the cookie jar for authenticated
  modules (`cve`, `xss`, `sqli`, `lfi`, `config`, `auth`, `session`).
  Public-exposure modules (`passive`, `api`, `plugin`, `supplychain`) always
  run as a guest so an authenticated page is not mislabeled as public.
- Redirects are followed only within the same host (and the normal
  `http` → `https` upgrade). Use `--allow-external-redirects` only when a known
  SSO flow requires it.
- `--max-requests N` is a target-request budget shared by every module and
  redirect. When it is exhausted, the run records partial coverage.
- `--crawl-pages N` lets active modules conservatively walk up to N same-origin
  authenticated pages, skipping logout/delete/edit/enrol/backup links. It is
  off by default.
- Active modules do not run without `--authorized`; the report lists the
  modules that were skipped.

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
| `cve` | Queries OSV.dev and Moodle Security Announcements by exact version; enriches with CISA KEV and FIRST EPSS; optional safe validators | Version-based advisories + validation status |
| `passive` | HTTPS/HSTS/TLS certificate/CSP/XFO/cookie flags, exposed backups/`.git`/`.env`/SQL dumps/phpinfo/Adminer, directory listing, debug errors, `security.txt` | Direct response evidence |
| `auth` | Login form CSRF token, credential login, optional default-credential test, optional Host-header bypass | Confirmed only |
| `api` | REST token checks, `service-nologin`, XML-RPC discovery, admin web-service exposure, CORS, open redirect, debug errors | Confirmed data/response |
| `config` | Authenticated read-only audit of Moodle's security overview and phpinfo (debug, guest/web-service settings, PHP session flags) | Observed admin-page state |
| `xss` | Reflected HTML-injection canaries (`<mss...>`), no JavaScript execution | Raw reflection of both canaries |
| `sqli` | Differential database-error payloads; time-based only with `--deep`; login forms are never targeted | Two payloads vs two controls |
| `lfi` | `/etc/passwd`, `win.ini`, Moodle `config.php` (raw or base64) signatures | Actual file content |
| `rce` | Explicit coverage marker. Known RCEs are matched by `cve`; exposures by `passive` | No destructive checks |
| `plugin` | Parallel component inventory via `version.php`; parses exposed `$plugin->version/release` and detects source disclosure | Inventory + version evidence |
| `session` | Session-fixation check with credentials | Cookie unchanged across login |
| `supplychain` | If `composer.lock` is exposed, checks exact Packagist versions against OSV | Version-based dependency advisories |

`cve` now merges OSV and MSA by CVE. When an MSA has no CVE yet, the finding
keeps the MSA identifier and is marked `manual` rather than inventing a CVE.
MSA pages are cached in `data/cache/`; `--offline` uses the last cache,
`--msa-pages N` controls how many announcement pages are read (default 12),
and `--no-msa` disables the MSA source.

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
- **Moodle Security Announcements** — `https://moodle.org/security/` is parsed
  automatically (index pages are cached for 24 hours). This is the only source
  that catches advisories whose CVE is still `Pending`, and it often reaches a
  release before OSV/GitHub advisories. MSA and OSV findings are merged by CVE.
- **Moodle plugins directory API** — `https://download.moodle.org/api/1.3/pluglist.php`
  for component/version metadata. It is not a vulnerability database; plugin
  CVE matching still needs a version and a plugin advisory feed.

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
| `available` | A safe bounded validator exists; run it with `--validate-cves --authorized` |
| `confirmed` | The safe validator observed the vulnerable behaviour (not full exploitation) |
| `not-confirmed` | The safe validator did not observe it; could be patched, backported or blocked |
| `not-observed` | The target required authentication or the request failed |
| `manual` | Requires an authenticated/state-changing action or a browser; not automated |
| `out-of-scope` | Restore RCE, destructive file processing or DoS; never automated here |

Safe validators currently exist for:

- **CVE-2025-26533** — sends a non-existent module name to `course/search.php`;
  vulnerable Moodle returns a database read exception. No SQL is injected.
- **CVE-2025-67852** — checks whether the OAuth login flow accepts an external
  `wantsurl` and returns an external `Location`.
- **CVE-2025-62396** — looks for router error details/directory listing from
  `r.php` without changing state.
- **CVE-2025-67855** — sends an inert `javascript:` canary to the policy tool
  return URL; confirms reflection only, not browser execution.
- **CVE-2025-62399 / CVE-2025-67853** — send six bounded attempts with a
  non-existent user/email and observe whether rate limiting/CAPTCHA appears.
  This never targets a real account and never proves account compromise.

```bash
# Authenticate once, then run safe validators and the authenticated config audit
printf '%s' "$MOODLE_TEST_PASSWORD" | python moodle_scanner.py \
  -t https://moodle.example.com \
  -m version,cve,config --validate-cves --authorized \
  --username auditor --password-stdin \
  --offline --no-enrich -o cve-report.json
```

CVEs that require creating a calculated question, uploading a file,
restoring a backup, changing grades, creating content or using a browser are
marked `manual`. Restore RCE and TeX DoS are marked `out-of-scope`. That is
deliberate: automatically "proving" those would be an exploit framework, not a
scanner. Version matches remain `version` findings until a safe check or manual
validation confirms them.

`--validate-cves` requires `--authorized`; without it, CVE findings keep their
`available`/`manual` status and no active validation request is sent.

## Reports

| Format | Command | Notes |
| --- | --- | --- |
| JSON | `-o report.json` | Full structured output, schema 2.0 |
| HTML | `-o report.html` | Escaped output, severity badges, CVSS/EPSS/KEV, validation matrix |
| TXT | `-o report.txt` | Manager-friendly plain text |
| SARIF | `-o report.sarif` | GitHub Code Scanning / CI integration |

Reports now show authentication state, CVE validation counts, MSA identifiers
and separate average risk scores for verified and version-based findings.

For CI:

```bash
python moodle_scanner.py -t "$MOODLE_URL" --profile fast --offline \
  --fail-on High -o report.sarif
```

`--fail-on Critical|High|Medium|Low` exits with code `2` when a finding at or
above the threshold exists. Add `--fail-on-verified` to ignore version-only
matches and fail only on actively confirmed behaviour. `--offline` uses cached
OSV/MSA/KEV/EPSS data only.

## Accuracy and limitations

- No scanner can guarantee zero false positives. This tool reduces them by
  requiring controls, real file signatures, exact versions and explicit
  labels, and by refusing to call a page "vulnerable" just because it returned
  HTTP 200.
- Reflected-XSS findings prove HTML injection, not JavaScript execution. A
  browser confirmation is still required for an executable-XSS claim.
- SQLi error-based findings prove an error delta, not full data extraction.
  Login/session forms are explicitly excluded from SQLi/LFI discovery to avoid
  lockouts.
- A CVE marked `confirmed` by a safe validator means the vulnerable behaviour
  was observed, not that data was extracted or code executed. Full exploitation
  is out of scope.
- The rate-limit validators confirm only that six bounded attempts with a
  non-existent identity were not throttled. They do not attack real accounts.
- MSA parsing depends on Moodle's public announcement HTML; if the markup
  changes, the scanner reports MSA as unavailable instead of guessing. MSA
  ranges are explicit, and "earlier unsupported versions" are not inferred.
- The config audit depends on the authenticated account having access to
  `report/security/index.php` and `admin/phpinfo.php`; a non-admin test account
  will produce an Info entry. HTML parsing across Moodle versions is
  best-effort, and the raw report remains the authority.
- Version-based findings must be confirmed against the installed build and
  patches; backports and vendor builds can change applicability.
- Plugin CVEs require the plugin version and a plugin advisory feed. The
  `plugin` module reports an inventory, exposed versions and source disclosure;
  it does not invent plugin CVEs.
- Stored XSS, DOM XSS, SSRF, deserialization and authenticated business-logic
  flaws require a browser, a test account and a dedicated manual assessment.

## Development

```bash
ruff check .
mypy modules moodle_scanner.py
pytest -q
pip-audit -r requirements.txt
```

The test suite uses local mock HTTP responses and a local fake Moodle server;
it does not scan the internet. CI runs lint, type checking and tests on Python
3.10, 3.11 and 3.13.

## Legacy entry points

`moodle_security_scanner.py` remains a deprecated wrapper for
`moodle_scanner.py`. `results_to_txt.py` and `results_to_docx.py` can convert
an existing JSON report into manager-oriented TXT/DOCX files.

## Disclaimer

This tool is provided for educational and legitimate security testing only.
The authors accept no liability for misuse or damage caused by this program.
