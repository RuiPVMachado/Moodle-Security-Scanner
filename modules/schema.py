#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Common vulnerability schema utilities for scanner modules."""

from typing import Any, Dict, List, Optional

SEVERITY_VALUES = ("Critical", "High", "Medium", "Low", "Info")
CONFIDENCE_VALUES = ("high", "medium", "low")
EXPLOITABILITY_VALUES = ("high", "medium", "low")

SEVERITY_SCORE = {
    "Critical": 50,
    "High": 35,
    "Medium": 20,
    "Low": 10,
    "Info": 5,
}

CONFIDENCE_SCORE = {
    "high": 30,
    "medium": 20,
    "low": 10,
}

EXPLOITABILITY_SCORE = {
    "high": 20,
    "medium": 12,
    "low": 6,
}


def normalize_severity(value: Optional[str]) -> str:
    if not value:
        return "Info"

    normalized = value.strip().lower()
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "med": "Medium",
        "low": "Low",
        "info": "Info",
        "informational": "Info",
    }
    return mapping.get(normalized, "Info")


def _normalize_level(
    value: Optional[str],
    allowed_values: tuple[str, str, str],
    default_value: str,
) -> str:
    if not value:
        return default_value

    normalized = value.strip().lower()
    if normalized in allowed_values:
        return normalized
    return default_value


def _infer_confidence(raw_vulnerability: Dict[str, Any]) -> str:
    if raw_vulnerability.get("confidence"):
        return _normalize_level(raw_vulnerability.get("confidence"), CONFIDENCE_VALUES, "medium")

    if raw_vulnerability.get("cve") or raw_vulnerability.get("evidence"):
        return "high"

    if raw_vulnerability.get("payload"):
        return "medium"

    return "low"


def _infer_exploitability(raw_vulnerability: Dict[str, Any], severity: str) -> str:
    if raw_vulnerability.get("exploitability"):
        return _normalize_level(
            raw_vulnerability.get("exploitability"),
            EXPLOITABILITY_VALUES,
            "medium",
        )

    if severity in ("Critical", "High") and raw_vulnerability.get("payload"):
        return "high"

    if severity == "Info":
        return "low"

    return "medium"


def calculate_risk_score(severity: str, confidence: str, exploitability: str) -> int:
    score = (
        SEVERITY_SCORE.get(severity, SEVERITY_SCORE["Info"])
        + CONFIDENCE_SCORE.get(confidence, CONFIDENCE_SCORE["medium"])
        + EXPLOITABILITY_SCORE.get(exploitability, EXPLOITABILITY_SCORE["medium"])
    )
    return min(score, 100)


def normalize_vulnerability(
    raw_vulnerability: Dict[str, Any],
    module_name: str,
    target_url: str,
) -> Dict[str, Any]:
    title = raw_vulnerability.get("title") or "Unnamed vulnerability"
    description = raw_vulnerability.get("description") or "No description provided."
    severity = normalize_severity(raw_vulnerability.get("severity"))
    confidence = _infer_confidence(raw_vulnerability)
    exploitability = _infer_exploitability(raw_vulnerability, severity)
    risk_score = calculate_risk_score(severity, confidence, exploitability)

    references = raw_vulnerability.get("references")
    if not isinstance(references, list):
        references = []

    return {
        "schema_version": "1.0",
        "title": title,
        "description": description,
        "severity": severity,
        "confidence": confidence,
        "exploitability": exploitability,
        "risk_score": risk_score,
        "module": module_name,
        "url": raw_vulnerability.get("url") or target_url,
        "evidence": raw_vulnerability.get("evidence") or "",
        "payload": raw_vulnerability.get("payload"),
        "cve": raw_vulnerability.get("cve"),
        "cwe": raw_vulnerability.get("cwe"),
        "remediation": raw_vulnerability.get("remediation") or "No remediation provided.",
        "references": references,
        "metadata": raw_vulnerability.get("metadata") or {},
    }


def normalize_vulnerabilities(
    vulnerabilities: List[Dict[str, Any]],
    module_name: str,
    target_url: str,
) -> List[Dict[str, Any]]:
    return [normalize_vulnerability(vuln, module_name, target_url) for vuln in vulnerabilities]
