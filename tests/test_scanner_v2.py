import base64
import json
from types import SimpleNamespace

from modules.auth_tester import MoodleAuthTester
from modules.cve_matcher import CVEMatcher, MoodleCVETester
from modules.cve_validation import default_validation, validate_finding
from modules.discovery import replace_query_param
from modules.lfi_tester import MoodleLFITester
from modules.rce_tester import MoodleRCETester
from modules.schema import deduplicate_vulnerabilities, normalize_vulnerability
from modules.sqli_tester import MoodleSQLITester
from modules.supplychain import MoodleSupplyChainTester
from modules.version_detector import MoodleVersionDetector, extract_m_cfg
from moodle_scanner import MoodleScanner


class FakeResponse:
    def __init__(self, text="", status_code=200, url="https://example.com/"):
        self.text = text
        self.status_code = status_code
        self.url = url
        self.headers = {}
        self.raw = None


class FakeSession:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        for prefix, response in self.routes.items():
            if url.startswith(prefix):
                return response
        return FakeResponse(status_code=404, url=url)


def _args(**overrides):
    values = dict(
        target="example.com",
        modules="version,cve,passive,auth,api,xss,sqli,lfi,rce,plugin,session",
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


def test_extract_m_cfg_and_wwwroot():
    html = '<script>M.cfg = {"wwwroot":"https://moodle.example.com/moodle"};</script>'
    assert extract_m_cfg(html)["wwwroot"] == "https://moodle.example.com/moodle"


def test_version_detection_from_mobile_link_and_rebase():
    html = (
        '<script>M.cfg = {"wwwroot":"https://moodle.example.com/moodle"};</script>'
        '<a href="https://download.moodle.org/mobile?version=2026042004&lang=en">app</a>'
    )
    session = FakeSession({"https://moodle.example.com/moodle/": FakeResponse(html)})
    detector = MoodleVersionDetector(
        "https://moodle.example.com/moodle/login/index.php",
        session=session,
    )
    info = detector.detect_version()
    assert info["version"] == "5.2.4"
    assert info["version_confidence"] == "high"
    assert info["wwwroot"] == "https://moodle.example.com/moodle/"
    assert detector.target_url == "https://moodle.example.com/moodle/"


def test_version_detection_upgrade_txt_sentinel_is_branch_only():
    home = FakeResponse('<html><a href="https://moodle.org">Moodle</a></html>')
    upgrade = FakeResponse("=== 4.5 Onwards ===\n\nThis file has been replaced by UPGRADING.md.")
    session = FakeSession(
        {
            "https://example.com/lib/upgrade.txt": upgrade,
            "https://example.com/": home,
        }
    )
    detector = MoodleVersionDetector("https://example.com/", session=session)
    info = detector.detect_version()
    assert "version" not in info
    assert info["version_branch"] == "4.5+"


def test_osv_finding_parsing_and_version_ranges():
    sample = {
        "id": "GHSA-test-1234",
        "summary": "Moodle test vulnerability",
        "details": "A test advisory.",
        "aliases": ["CVE-2024-43425"],
        "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-94"]},
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            }
        ],
        "affected": [
            {
                "package": {"name": "moodle/moodle"},
                "ranges": [
                    {
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "4.1.12"},
                            {"fixed": "4.4.2"},
                        ]
                    }
                ],
            }
        ],
        "references": [{"url": "https://moodle.org/mod/forum/discuss.php?d=1"}],
    }
    matcher = CVEMatcher(offline=True, enrich=False)
    assert matcher._is_affected("4.1.11", sample) is True
    assert matcher._is_affected("4.1.12", sample) is False
    finding = matcher._finding_from_osv(sample, "4.1.11", "https://moodle.example.com/")
    assert finding["cve"] == "CVE-2024-43425"
    assert finding["severity"] == "High"
    assert finding["verified"] is False
    assert "4.1.12" in finding["fixed_versions"]
    assert finding["cvss_score"] is not None


def test_deduplication_prefers_verified_finding():
    weak = {
        "title": "CVE-2024-43425",
        "cve": "CVE-2024-43425",
        "url": "https://example.com/",
        "severity": "High",
        "confidence": "medium",
        "risk_score": 50,
        "verified": False,
        "references": ["https://a.example"],
        "metadata": {},
    }
    strong = dict(weak)
    strong.update({"confidence": "high", "risk_score": 80, "verified": True})
    result = deduplicate_vulnerabilities([weak, strong])
    assert len(result) == 1
    assert result[0]["verified"] is True
    assert "https://a.example" in result[0]["references"]


def test_html_report_escapes_target_controlled_evidence(tmp_path):
    output = tmp_path / "report.html"
    scanner = MoodleScanner(_args(output=str(output), modules="version"))
    scanner.results["vulnerabilities"] = [
        normalize_vulnerability(
            {
                "title": "Test <script>alert(1)</script>",
                "description": "<img src=x onerror=alert(2)>",
                "severity": "Medium",
                "evidence": "<script>alert(3)</script>",
                "url": "https://example.com/?x=<script>alert(4)</script>",
                "verified": True,
                "source": "active",
            },
            module_name="xss",
            target_url=scanner.target_url,
        )
    ]
    scanner.generate_summary()
    scanner._save_html(str(output))
    report = output.read_text(encoding="utf-8")
    assert "<script>alert(3)</script>" not in report
    assert "&lt;script&gt;alert(3)&lt;/script&gt;" in report
    assert "<img src=x onerror=alert(2)>" not in report


def test_auth_csrf_check_does_not_flag_valid_moodle_form():
    tester = MoodleAuthTester("https://example.com/", session=FakeSession({}))
    results = {"vulnerabilities": [], "info": []}
    tester._check_login_form(
        '<form><input name="username"><input name="password">'
        '<input name="logintoken" value="abc"></form>',
        "https://example.com/login/index.php",
        results,
    )
    assert results["vulnerabilities"] == []


def test_auth_csrf_check_flags_form_without_token():
    tester = MoodleAuthTester("https://example.com/", session=FakeSession({}))
    results = {"vulnerabilities": [], "info": []}
    tester._check_login_form(
        '<form><input name="username"><input name="password"></form>',
        "https://example.com/login/index.php",
        results,
    )
    assert len(results["vulnerabilities"]) == 1
    assert results["vulnerabilities"][0]["severity"] == "High"


def test_lfi_requires_real_file_signature():
    tester = MoodleLFITester("https://example.com/", session=FakeSession({}))
    assert tester._confirm_file_read("filename=" + "../../etc/passwd", "../../etc/passwd") is None
    finding = tester._confirm_file_read(
        "root:x:0:0:root:/root:/bin/bash",
        "../../etc/passwd",
    )
    assert finding is not None
    assert finding[1] == "High"

    config = "<?php $CFG->dbtype = 'mysqli'; $CFG->dbuser = 'moodle';"
    encoded = base64.b64encode(config.encode()).decode()
    finding = tester._confirm_file_read(encoded, "php://filter/convert.base64-encode/resource=config.php")
    assert finding is not None
    assert finding[1] == "Critical"


def test_sqli_does_not_treat_version_numbers_as_errors():
    errors = MoodleSQLITester._db_errors("Moodle 4.1.11 released on 2023-01-01")
    assert errors == set()
    errors = MoodleSQLITester._db_errors("You have an error in your SQL syntax near '1'")
    assert errors


def test_rce_module_is_non_destructive():
    tester = MoodleRCETester("https://example.com/")
    result = tester.run_tests()
    assert result["vulnerabilities"] == []
    assert result["info"]


def test_replace_query_param_does_not_duplicate():
    url = replace_query_param(
        "https://example.com/file.php?file=old&x=1",
        "file",
        "../../etc/passwd",
    )
    assert url.count("file=") == 1
    assert "x=1" in url
    assert "%2Fetc%2Fpasswd" in url or "etc%2Fpasswd" in url


def test_parse_modules_includes_new_modules():
    scanner = MoodleScanner(_args(modules="cve,passive,plugin,session"))
    assert scanner.modules_to_run[:1] == ["version"]
    assert {"cve", "passive", "plugin", "session"}.issubset(set(scanner.modules_to_run))


def test_fail_on_high_sets_exit_code():
    scanner = MoodleScanner(_args(fail_on="High", modules="version"))
    scanner.results["vulnerabilities"] = [
        normalize_vulnerability(
            {"title": "Confirmed issue", "severity": "High", "verified": True},
            module_name="passive",
            target_url=scanner.target_url,
        )
    ]
    scanner._apply_fail_on()
    assert scanner.exit_code == 2


def test_fail_on_does_not_trigger_for_low():
    scanner = MoodleScanner(_args(fail_on="High", modules="version"))
    scanner.results["vulnerabilities"] = [
        normalize_vulnerability(
            {"title": "Low issue", "severity": "Low", "verified": True},
            module_name="passive",
            target_url=scanner.target_url,
        )
    ]
    scanner._apply_fail_on()
    assert scanner.exit_code == 0


class ValidatorSession:
    def __init__(self, body, url="https://example.com/course/search.php"):
        self.body = body
        self.url = url

    def get(self, url, params=None, **kwargs):
        probe_value = (params or {}).get("modulelist", "")
        return FakeResponse(self.body.format(probe=probe_value), url=url)


def test_default_validation_marks_rce_manual():
    validation = default_validation(
        {
            "cve": "CVE-2024-43425",
            "title": "Moodle: remote code execution via calculated question types",
        }
    )
    assert validation["status"] == "manual"
    assert "alter" in validation["reason"].lower() or "autentic" in validation["reason"].lower()


def test_default_validation_offers_safe_check_for_course_search_sqli():
    validation = default_validation(
        {"cve": "CVE-2025-26533", "title": "SQL injection risk in course search"}
    )
    assert validation["status"] == "available"
    assert validation["method"] == "safe-active"


def test_cve_2025_26533_validator_confirms_database_error():
    session = ValidatorSession(
        "dmlreadexception: Table 'moodle.{probe}' doesn't exist"
    )
    result = validate_finding(
        {"cve": "CVE-2025-26533", "title": "SQL injection in course search"},
        session,
        "https://example.com/",
    )
    assert result["status"] == "confirmed"
    assert "sem injetar SQL" in result["reason"]


def test_cve_2025_26533_validator_detects_login_wall():
    session = ValidatorSession(
        '<form><input type="hidden" name="logintoken" value="x"></form>',
        url="https://example.com/login/index.php",
    )
    result = validate_finding(
        {"cve": "CVE-2025-26533", "title": "SQL injection in course search"},
        session,
        "https://example.com/",
    )
    assert result["status"] == "not-observed"


def test_cve_2025_26533_validator_negative_result():
    session = ValidatorSession("<html>No courses found</html>")
    result = validate_finding(
        {"cve": "CVE-2025-26533", "title": "SQL injection in course search"},
        session,
        "https://example.com/",
    )
    assert result["status"] == "not-confirmed"


def test_schema_preserves_validation_metadata():
    finding = normalize_vulnerability(
        {
            "title": "CVE test",
            "severity": "High",
            "cve": "CVE-2025-26533",
            "validation": {
                "status": "confirmed",
                "method": "safe-active",
                "reason": "observed",
            },
        },
        module_name="cve",
        target_url="https://example.com/",
    )
    assert finding["validation_status"] == "confirmed"
    assert finding["validation"]["method"] == "safe-active"


class JsonResponse:
    def __init__(self, payload, url="https://example.com/composer.lock"):
        self.payload = payload
        self.url = url
        self.status_code = 200
        self.headers = {}
        self.raw = None
        self.content = json.dumps(payload).encode()
        self.text = self.content.decode()

    def json(self):
        return self.payload

    def raise_for_status(self):
        return None


class LockSession:
    def __init__(self, payload):
        self.payload = payload

    def get(self, url, **kwargs):
        return JsonResponse(self.payload, url=url)


class OsvBatchSession:
    def __init__(self, payload):
        self.payload = payload

    def post(self, url, json=None, timeout=None):
        return JsonResponse(self.payload, url=url)


def test_supplychain_parses_lock_and_matches_osv(tmp_path):
    lock = {
        "packages": [
            {"name": "guzzlehttp/guzzle", "version": "7.0.0"},
            {"name": "vendor/dev-only", "version": "dev-main"},
        ]
    }
    osv = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-test-supply",
                        "summary": "Guzzle test advisory",
                        "details": "A test dependency issue.",
                        "aliases": ["CVE-2024-0001"],
                        "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-400"]},
                        "affected": [
                            {
                                "package": {"name": "guzzlehttp/guzzle"},
                                "ranges": [
                                    {
                                        "events": [
                                            {"introduced": "0"},
                                            {"fixed": "7.4.5"},
                                        ]
                                    }
                                ],
                            }
                        ],
                        "references": [{"url": "https://example.com/advisory"}],
                    }
                ]
            }
        ]
    }
    tester = MoodleSupplyChainTester(
        "https://example.com/",
        session=LockSession(lock),
        cache_dir=str(tmp_path),
        offline=False,
        max_tests=10,
    )
    tester.osv_session = OsvBatchSession(osv)
    result = tester.run_tests()
    assert len(result["vulnerabilities"]) == 1
    finding = result["vulnerabilities"][0]
    assert finding["cve"] == "CVE-2024-0001"
    assert finding["source"] == "OSV/composer"
    assert "7.4.5" in finding["fixed_versions"]
    assert finding["metadata"]["package"] == "guzzlehttp/guzzle"


def test_supplychain_missing_lock_is_info(tmp_path):
    tester = MoodleSupplyChainTester(
        "https://example.com/",
        session=FakeSession({}),
        cache_dir=str(tmp_path),
        offline=True,
    )
    result = tester.run_tests()
    assert result["vulnerabilities"] == []
    assert any("composer.lock" in item["title"] for item in result["info"])


def test_cve_tester_requires_authorization_for_active_validation(monkeypatch):
    monkeypatch.setattr(
        CVEMatcher,
        "match",
        lambda self, version, target_url: [
            {
                "title": "SQL injection risk in course search",
                "description": "SQL injection",
                "severity": "High",
                "cve": "CVE-2025-26533",
                "confidence": "high",
                "verified": False,
                "source": "OSV",
                "evidence_type": "version",
            }
        ],
    )
    tester = MoodleCVETester(
        "https://example.com/",
        offline=True,
        validate_cves=True,
        authorized=False,
        use_msa=False,
    )
    tester.set_version_info({"version": "4.4.5", "version_confidence": "high"})
    result = tester.run_tests()
    assert result["vulnerabilities"][0]["validation_status"] == "manual"
    assert any(item["title"] == "Validação de CVEs não executada" for item in result["info"])
