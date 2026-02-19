import argparse

from modules.schema import normalize_vulnerability
from moodle_scanner import MoodleScanner


def _make_args(target="example.com", modules="all"):
    return argparse.Namespace(
        target=target,
        modules=modules,
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
    )


def test_normalize_url_adds_https_and_trailing_slash():
    scanner = MoodleScanner(_make_args(target="moodle.example.com"))
    assert scanner.target_url == "https://moodle.example.com/"


def test_parse_modules_ignores_unknown_and_duplicates():
    scanner = MoodleScanner(_make_args(modules="version,auth,sqli,unknown,auth"))
    assert scanner.modules_to_run == ["version", "auth", "sqli"]


def test_generate_summary_includes_counts_and_risk_metadata():
    scanner = MoodleScanner(_make_args(modules="version,auth,sqli"))

    scanner.results["vulnerabilities"] = [
        normalize_vulnerability(
            {
                "title": "SQL Injection",
                "description": "Injectable parameter",
                "severity": "Critical",
                "payload": "' OR 1=1 --",
                "evidence": "Database error leaked",
            },
            module_name="sqli",
            target_url=scanner.target_url,
        ),
        normalize_vulnerability(
            {
                "title": "Weak Login Policy",
                "description": "Weak credentials accepted",
                "severity": "Medium",
            },
            module_name="auth",
            target_url=scanner.target_url,
        ),
    ]

    scanner.generate_summary()
    summary = scanner.results["summary"]

    assert summary["total_vulnerabilities"] == 2
    assert summary["severity_counts"]["Critical"] == 1
    assert summary["severity_counts"]["Medium"] == 1
    assert summary["vulnerabilities_by_module"]["sqli"] == 1
    assert summary["vulnerabilities_by_module"]["auth"] == 1
    assert summary["average_risk_score"] > 0
    assert (
        summary["top_vulnerabilities"][0]["risk_score"]
        >= summary["top_vulnerabilities"][1]["risk_score"]
    )
