#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Convert scanner JSON output into a manager-friendly TXT report."""

import argparse
import json
from pathlib import Path
from typing import Any


def _severity_key(vuln: dict[str, Any]) -> int:
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    return order.get(vuln.get("severity", "Info"), 99)


def render_report(data: dict[str, Any]) -> str:
    scan_info = data.get("scan_info", {})
    summary = data.get("summary", {})
    vulns = data.get("vulnerabilities", [])
    max_evidence_chars = 800

    lines = [
        "=" * 80,
        "MOODLE SECURITY SCAN REPORT (MANAGER EXPORT)",
        "=" * 80,
        f"Target: {scan_info.get('target', 'Unknown')}",
        f"Scan Date: {scan_info.get('timestamp', 'Unknown')}",
        f"Scanner Version: {scan_info.get('scanner_version', 'Unknown')}",
        f"Status: {scan_info.get('status', 'Unknown')}",
        "",
        "SCAN SUMMARY",
        "-" * 80,
        f"Total Vulnerabilities Found: {summary.get('total_vulnerabilities', len(vulns))}",
        f"Average Risk Score: {summary.get('average_risk_score', 0)}",
        f"Critical: {summary.get('severity_counts', {}).get('Critical', 0)}",
        f"High: {summary.get('severity_counts', {}).get('High', 0)}",
        f"Medium: {summary.get('severity_counts', {}).get('Medium', 0)}",
        f"Low: {summary.get('severity_counts', {}).get('Low', 0)}",
        f"Info: {summary.get('severity_counts', {}).get('Info', 0)}",
        "",
        "REMEDIATION ROADMAP",
        "-" * 80,
        "Immediate (0-24h): Fix Critical findings and lock down sensitive endpoints.",
        "Short-term (1-7d): Patch affected Moodle core/plugins and harden config.",
        "Medium-term (1-4w): Add continuous monitoring and recurring scans.",
        "",
        "SAFE VALIDATION NOTE",
        "-" * 80,
        "This report includes defensive remediation and validation guidance only.",
        "",
        "DETAILED FINDINGS",
        "=" * 80,
    ]

    if not vulns:
        lines.append("No vulnerabilities found.")
        return "\n".join(lines)

    for index, vuln in enumerate(sorted(vulns, key=_severity_key), 1):
        evidence = str(vuln.get("evidence", "N/A"))
        if len(evidence) > max_evidence_chars:
            evidence = evidence[:max_evidence_chars] + "\n...[truncated for readability; see JSON report]"

        lines.extend(
            [
                f"{index}. [{vuln.get('severity', 'Unknown')}] {vuln.get('title', 'Unknown vulnerability')}",
                "-" * 80,
                f"Module: {vuln.get('module', 'unknown')}",
                f"Confidence: {vuln.get('confidence', 'unknown')}",
                f"Exploitability: {vuln.get('exploitability', 'unknown')}",
                f"Risk Score: {vuln.get('risk_score', 'unknown')}",
                f"Description: {vuln.get('description', 'No description provided.')}",
                f"URL: {vuln.get('url', 'N/A')}",
                f"Evidence: {evidence}",
            ]
        )

        if vuln.get("payload"):
            lines.append("Payload Details: omitted in manager report")

        if vuln.get("cve"):
            lines.append(f"CVE: {vuln.get('cve')}")
            lines.append(f"Reference: https://nvd.nist.gov/vuln/detail/{vuln.get('cve')}")

        if vuln.get("cwe"):
            cwe = str(vuln.get("cwe"))
            lines.append(f"CWE: {cwe}")
            lines.append(f"Reference: https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html")

        lines.extend(
            [
                f"Remediation: {vuln.get('remediation', 'No remediation provided.')}",
                "Fix Steps (Actionable):",
                "  1) Assign an owner and change window.",
                "  2) Patch/update impacted Moodle component or plugin.",
                "  3) Disable/remove vulnerable component if no patch is available.",
                "  4) Restrict access/authentication for sensitive endpoints.",
                "  5) Re-test and document closure evidence.",
                "Safe Validation Checklist:",
                "  - Confirm endpoint no longer behaves as vulnerable.",
                "  - Confirm production errors do not expose sensitive internals.",
                "  - Re-run scanner module and verify finding is gone/downgraded.",
                "",
            ]
        )

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert scanner JSON output into manager TXT report")
    parser.add_argument("-i", "--input", required=True, help="Input JSON file (e.g., results.json)")
    parser.add_argument("-o", "--output", default="manager_report.txt", help="Output TXT file")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    with input_path.open("r", encoding="utf-8") as source:
        data = json.load(source)

    output_path.write_text(render_report(data), encoding="utf-8")
    print(f"Report written to {output_path}")


if __name__ == "__main__":
    main()
