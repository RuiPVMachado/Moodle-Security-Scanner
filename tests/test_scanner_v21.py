import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import moodle_scanner
from modules.cache import cache_filename
from modules.config_tester import MoodleConfigTester
from modules.cve_matcher import CVEMatcher, MoodleCVETester
from modules.cve_validation import _SAFE_VALIDATORS, default_validation, validate_finding
from modules.discovery import _safe_crawl_url, extract_forms
from modules.msa import MSAMatcher, parse_msa_html
from modules.plugin_tester import MoodlePluginTester
from modules.schema import calculate_risk_score, normalize_vulnerability
from moodle_scanner import (
    MoodleScanner,
    _default_report_path,
    _interactive_setup,
    _selected_modules,
)


class FakeResponse:
    def __init__(self, text="", status_code=200, url="https://example.com/", headers=None):
        self.text = text
        self.status_code = status_code
        self.url = url
        self.headers = headers or {}
        self.content = (text or "").encode()
        self.raw = None

    def json(self):
        return json.loads(self.text)


class FakeSession:
    def __init__(self, routes=None, responder=None):
        self.routes = routes or {}
        self.responder = responder
        self.calls = []

    def get(self, url, params=None, headers=None, allow_redirects=True, timeout=None, **kwargs):
        self.calls.append(("GET", url, params, headers))
        if self.responder is not None:
            return self.responder("GET", url, params)
        for prefix, response in self.routes.items():
            if url.startswith(prefix):
                return response
        return FakeResponse(status_code=404, url=url)

    def post(self, url, data=None, headers=None, allow_redirects=True, timeout=None, **kwargs):
        self.calls.append(("POST", url, data, headers))
        if self.responder is not None:
            return self.responder("POST", url, data)
        for prefix, response in self.routes.items():
            if url.startswith(prefix):
                return response
        return FakeResponse(status_code=404, url=url)


def _args(**overrides):
    values = dict(
        target="example.com",
        modules="version,cve,passive,auth,api,config,xss,sqli,lfi,rce,plugin,session,supplychain",
        output=None,
        proxy=None,
        cookies=None,
        timeout=30,
        delay=0,
        threads=5,
        user_agent="pytest-agent",
        no_verify_ssl=False,
        verbose=False,
        quiet=True,
        profile="balanced",
        cache_dir=None,
        max_tests=20,
        max_response_bytes=2_000_000,
        authorized=False,
        offline=True,
        no_enrich=True,
        no_active=False,
        deep=False,
        force=False,
        test_default_credentials=False,
        username=None,
        password=None,
        fail_on=None,
        format=None,
        rate_limit=0,
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def test_msa_parser_and_match(tmp_path):
    html = """
    <div class="forumpost">
      <h3 data-region-content="forum-post-core-subject">
        MSA-26-9999: Example serious issue
      </h3>
      <div class="post-content-container">
        <p>An example description.</p>
        <table><tr><td>Severity/Risk:</td><td><strong>Serious</strong></td></tr>
        <tr><td>Versions affected:</td><td>5.2 to 5.2.3, 4.5 to 4.5.14</td></tr>
        <tr><td>Versions fixed:</td><td><strong>5.2.4, 4.5.15</strong></td></tr>
        <tr><td>CVE identifier:</td><td>Pending</td></tr></table>
        <a href="https://moodle.org/mod/forum/discuss.php?d=123">Discuss</a>
      </div>
    </div>
    """
    parsed = parse_msa_html(html)
    assert len(parsed) == 1
    assert parsed[0]["msa_id"] == "MSA-26-9999"
    assert parsed[0]["severity"] == "High"
    assert parsed[0]["fixed_versions"] == ["5.2.4", "4.5.15"]

    matcher = MSAMatcher(offline=True, cache_dir=Path(tmp_path))
    matcher.cache.write(f"msa_advisories_{matcher.max_pages}.json", parsed)
    findings = matcher.match("4.5.6", "https://example.com/")
    assert len(findings) == 1
    assert findings[0]["source"] == "MSA"
    assert findings[0]["cve"] is None
    assert findings[0]["metadata"]["msa_id"] == "MSA-26-9999"
    assert not matcher.match("4.5.15", "https://example.com/")


def test_cvss4_is_used_for_severity_when_database_severity_is_missing():
    sample = {
        "id": "GHSA-test-v4",
        "summary": "Test CVSS4 advisory",
        "aliases": ["CVE-2026-99999"],
        "severity": [
            {
                "type": "CVSS_V4",
                "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            }
        ],
        "affected": [{"package": {"name": "moodle/moodle"}, "ranges": []}],
    }
    matcher = CVEMatcher(offline=True, enrich=False)
    finding = matcher._finding_from_osv(sample, "4.5.6", "https://example.com/")
    assert finding["severity"] == "Critical"
    assert finding["cvss_score"] is not None
    assert finding["cvss_vector"].startswith("CVSS:4")


def test_long_cache_names_are_hashed_and_stable():
    name = "epss_" + "_".join(f"CVE-2026-{index:04d}" for index in range(60)) + ".json"
    first = cache_filename(name)
    second = cache_filename(name)
    assert first == second
    assert len(first) <= 120
    assert first.endswith(".json")
    assert first != cache_filename(name + "-different")


def test_risk_score_uses_kev_epss_and_validation():
    base = calculate_risk_score("High", "high", "medium", 7.0)
    enriched = calculate_risk_score("High", "high", "medium", 7.0, kev=True)
    confirmed = calculate_risk_score(
        "High", "high", "medium", 7.0, validation_status="confirmed"
    )
    not_confirmed = calculate_risk_score(
        "High", "high", "medium", 7.0, validation_status="not-confirmed"
    )
    epss = calculate_risk_score("High", "high", "medium", 7.0, epss=0.15)
    assert enriched >= 85
    assert confirmed > base
    assert not_confirmed < base
    assert epss > base


def test_open_redirect_validator_confirms_external_location():
    session = FakeSession(
        {
            "https://example.com/auth/oauth2/login.php": FakeResponse(
                status_code=302,
                headers={"Location": "https://mss-open-redirect.example/"},
                url="https://example.com/auth/oauth2/login.php",
            )
        }
    )
    result = validate_finding(
        {"cve": "CVE-2025-67852", "title": "Open redirect"},
        session,
        "https://example.com/",
    )
    assert result["status"] == "confirmed"
    assert "Location" in result["evidence"]


def test_error_disclosure_validator_confirms_router_listing():
    session = FakeSession(
        {
            "https://example.com/r.php": FakeResponse(
                "<html>Index of /var/www/moodle</html>",
                url="https://example.com/r.php",
            )
        }
    )
    result = validate_finding(
        {"cve": "CVE-2025-62396", "title": "Error disclosure"},
        session,
        "https://example.com/",
    )
    assert result["status"] == "confirmed"


def test_policy_return_url_validator_confirms_reflected_canary():
    session = FakeSession(
        responder=lambda method, url, params: FakeResponse(
            str((params or {}).get("returnurl", "")),
            url=url,
        )
    )
    result = validate_finding(
        {"cve": "CVE-2025-67855", "title": "Reflected XSS"},
        session,
        "https://example.com/",
    )
    assert result["status"] == "confirmed"


def test_rate_limit_validator_distinguishes_throttled_and_unthrottled():
    responses = [
        FakeResponse('{"error":"Invalid login"}', url="https://example.com/login/token.php"),
    ] * 6
    session = FakeSession(responder=lambda method, url, params: responses.pop(0))
    result = validate_finding(
        {"cve": "CVE-2025-62399", "title": "Brute force"},
        session,
        "https://example.com/",
    )
    assert result["status"] == "confirmed"

    throttled = FakeSession(
        responder=lambda method, url, params: FakeResponse(
            "Too many attempts", status_code=429, url=url
        )
    )
    result = validate_finding(
        {"cve": "CVE-2025-62399", "title": "Brute force"},
        throttled,
        "https://example.com/",
    )
    assert result["status"] == "not-confirmed"


def test_default_validation_exposes_known_safe_and_out_of_scope_cves():
    assert default_validation({"cve": "CVE-2025-67852"})["status"] == "available"
    assert default_validation({"cve": "CVE-2025-67847"})["status"] == "out-of-scope"
    assert "CVE-2025-67852" in _SAFE_VALIDATORS


def test_plugin_metadata_parser():
    source = (
        "<?php\n"
        "$plugin->component = 'mod_forum';\n"
        "$plugin->version = 2024100700;\n"
        "$plugin->release = '4.5.6';\n"
    )
    metadata = MoodlePluginTester._parse_plugin_metadata(source)
    assert metadata == {
        "version": "2024100700",
        "release": "4.5.6",
        "component": "mod_forum",
    }


def test_config_audit_reports_warning_rows():
    html = """
    <table class="admintable securityreport table generaltable checktable">
      <tr><td><span class="badge bg-warning text-dark">Warning</span></td>
          <td><a href="?detail=debugging">Debugging</a></td>
          <td>Debugging is enabled.</td><td></td></tr>
    </table>
    """
    tester = MoodleConfigTester(
        "https://example.com/",
        session=FakeSession(
            {
                "https://example.com/report/security/index.php": FakeResponse(
                    html, url="https://example.com/report/security/index.php"
                )
            }
        ),
        authenticated=True,
    )
    result = tester.run_tests()
    assert len(result["vulnerabilities"]) == 1
    assert result["vulnerabilities"][0]["severity"] == "Medium"


def test_auto_profile_selects_every_module():
    scanner = MoodleScanner(_args(modules=None, profile="auto"))
    assert {"cve", "passive", "api", "xss", "sqli", "lfi", "config", "plugin"}.issubset(
        set(scanner.modules_to_run)
    )
    assert scanner.deep is True


def test_interactive_setup_prompts_target_authorization_and_credentials(monkeypatch):
    args = _args(
        target=None,
        profile="auto",
        modules=None,
        authorized=False,
        username=None,
        password=None,
    )
    answers = iter(
        ["https://moodle.example.com", "y", "auditor"]
    )
    monkeypatch.setattr("moodle_scanner._is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr("moodle_scanner.getpass.getpass", lambda prompt="": "secret")
    _interactive_setup(args)
    assert args.target == "https://moodle.example.com"
    assert args.authorized is True
    assert args.username == "auditor"
    assert args.password == "secret"


def test_default_report_path_is_host_scoped_and_format_aware():
    html_path = _default_report_path("https://moodle.example.com/", None)
    json_path = _default_report_path("moodle.example.com", "json")
    assert html_path.startswith("moodle-scan-moodle.example.com-")
    assert html_path.endswith(".html")
    assert json_path.endswith(".json")


def test_selected_modules_respects_explicit_module_list():
    args = _args(modules="version,cve", profile="auto")
    assert _selected_modules(args) == ["version", "cve"]


def test_crawl_filter_skips_state_changing_and_external_links():
    assert _safe_crawl_url("https://example.com/course/view.php?id=2", "https://example.com/")
    assert not _safe_crawl_url("https://evil.example/course/view.php", "https://example.com/")
    assert not _safe_crawl_url("https://example.com/login/index.php", "https://example.com/")
    assert not _safe_crawl_url("https://example.com/mod/forum/delete.php?id=1", "https://example.com/")
    assert not _safe_crawl_url(
        "https://example.com/course/view.php?id=2&sesskey=abc", "https://example.com/"
    )
    assert not _safe_crawl_url("https://example.com/theme/boost/style.css", "https://example.com/")


def test_login_forms_are_not_used_for_injection_discovery():
    forms = list(
        extract_forms(
            '<form action="/login/index.php" method="post">'
            '<input name="username" value="x">'
            '<input name="password" value="y">'
            '<input name="logintoken" value="z">'
            "</form>",
            "https://example.com/",
            "https://example.com/",
        )
    )
    assert forms == []


def test_scanner_authenticates_once_and_shares_cookies(monkeypatch):
    def fake_login(session, target_url, username, password, **kwargs):
        return SimpleNamespace(
            success=True,
            message="ok",
            cookies={"MoodleSession": "abc"},
            login_url=target_url.rstrip("/") + "/login/index.php",
            admin_access=True,
        )

    monkeypatch.setattr(moodle_scanner, "login_to_moodle", fake_login)
    scanner = MoodleScanner(_args(username="auditor", password="secret"))
    scanner._authenticate()
    assert scanner.authenticated is True
    assert scanner.cookies == {"MoodleSession": "abc"}
    assert scanner.results["scan_info"]["authenticated"] is True


def test_fail_on_verified_ignores_version_only_findings():
    scanner = MoodleScanner(
        _args(fail_on="High", fail_on_verified=True, modules="version")
    )
    scanner.results["vulnerabilities"] = [
        normalize_vulnerability(
            {
                "title": "Version-only issue",
                "severity": "High",
                "source": "OSV",
                "evidence_type": "version",
                "verified": False,
            },
            module_name="cve",
            target_url=scanner.target_url,
        )
    ]
    scanner._apply_fail_on()
    assert scanner.exit_code == 0
    scanner.results["vulnerabilities"][0]["verified"] = True
    scanner._apply_fail_on()
    assert scanner.exit_code == 2


def test_active_modules_are_skipped_without_authorization():
    scanner = MoodleScanner(_args(modules="version,xss,sqli,cve"))
    assert "xss" in scanner.modules_to_run
    scanner._warn_authorization()
    assert "xss" not in scanner.modules_to_run
    assert "sqli" not in scanner.modules_to_run
    assert "cve" in scanner.modules_to_run


def test_msa_and_osv_findings_merge_by_cve():
    osv = [
        {
            "title": "OSV title",
            "cve": "CVE-2030-0001",
            "severity": "High",
            "references": ["https://osv.example/1"],
            "fixed_versions": ["4.5.9"],
            "description": "A sufficiently long OSV description for the finding.",
            "evidence": "OSV evidence.",
        }
    ]
    msa = [
        {
            "title": "MSA-99-0001: MSA title",
            "cve": "CVE-2030-0001",
            "severity": "Critical",
            "references": ["https://moodle.org/mod/forum/discuss.php?d=1"],
            "fixed_versions": ["4.5.10"],
            "description": "MSA description",
            "evidence": "MSA evidence.",
            "metadata": {"msa_id": "MSA-99-0001"},
        }
    ]
    merged = MoodleCVETester._merge_osv_and_msa(osv, msa)
    assert len(merged) == 1
    assert merged[0]["severity"] == "Critical"
    assert merged[0]["metadata"]["msa_id"] == "MSA-99-0001"
    assert "4.5.10" in merged[0]["fixed_versions"]
    assert "https://moodle.org/mod/forum/discuss.php?d=1" in merged[0]["references"]


def test_scan_result_schema_has_validation_and_msa_fields():
    finding = normalize_vulnerability(
        {
            "title": "MSA finding",
            "severity": "High",
            "source": "MSA",
            "evidence_type": "version",
            "validation": {"status": "manual"},
            "metadata": {"msa_id": "MSA-99-0001"},
        },
        module_name="cve",
        target_url="https://example.com/",
    )
    assert finding["validation_status"] == "manual"
    assert finding["metadata"]["msa_id"] == "MSA-99-0001"


def test_scanner_end_to_end_with_local_moodle_and_authenticated_config():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def _cookie(self):
            return "MoodleSession=test" in (self.headers.get("Cookie") or "")

        def _send(self, body="", status=200, headers=None):
            payload = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(payload)

        def _redirect(self, location):
            self.send_response(303)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            port = self.server.server_address[1]
            if self.path == "/":
                self._send(
                    "<html><head><script>M.cfg = "
                    f'{{"wwwroot":"http://127.0.0.1:{port}/"}};</script></head>'
                    "<body><a href=\"https://download.moodle.org/mobile?"
                    'version=2024100706&lang=en">app</a></body></html>'
                )
                return
            if self.path.startswith("/login/index.php"):
                self._send(
                    '<form method="post"><input name="username">'
                    '<input name="password"><input name="logintoken" value="t">'
                    "</form>"
                )
                return
            if self.path.startswith("/my/"):
                if not self._cookie():
                    self._redirect("/login/index.php")
                    return
                self._send("<h1>Dashboard</h1>")
                return
            if self.path.startswith("/admin/index.php"):
                if not self._cookie():
                    self._redirect("/login/index.php")
                    return
                self._send("<h1>Site administration</h1>")
                return
            if self.path.startswith("/report/security/index.php"):
                if not self._cookie():
                    self._redirect("/login/index.php")
                    return
                self._send(
                    '<table class="admintable securityreport checktable">'
                    '<tr><td><span class="badge bg-warning text-dark">Warning</span></td>'
                    '<td><a href="?detail=debugging">Debugging</a></td>'
                    "<td>Debugging is enabled.</td><td></td></tr></table>"
                )
                return
            self._send("not found", status=404)

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            if self.path.startswith("/login/index.php"):
                self._send(
                    "",
                    status=303,
                    headers={
                        "Location": "/my/",
                        "Set-Cookie": "MoodleSession=test; Path=/; HttpOnly",
                    },
                )
                return
            self._send("not found", status=404)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}/"
        scanner = MoodleScanner(
            _args(
                target=base,
                modules="version,config",
                authorized=True,
                username="auditor",
                password="secret",
                profile="fast",
                max_tests=10,
            )
        )
        scanner.run()
        assert scanner.authenticated is True
        assert scanner.results["scan_info"]["authenticated"] is True
        titles = [item["title"] for item in scanner.results["vulnerabilities"]]
        assert any("Debugging" in title for title in titles)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
