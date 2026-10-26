#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Common finding schema, scoring and deduplication.

A finding is not a proof.  Every item carries:

* ``source``: OSV, passive, active, plugin inventory, ...
* ``evidence_type``: version, passive, active, info
* ``verified``: True only when the scanner actively confirmed the behaviour
* ``confidence``/``exploitability`` and, when available, ``cvss_score``/``epss``

Reports can therefore separate confirmed issues from version-based advisories
and heuristic observations instead of mixing everything into one "Critical"
list.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

SEVERITY_VALUES = ("Critical", "High", "Medium", "Low", "Info")
CONFIDENCE_VALUES = ("high", "medium", "low")
EXPLOITABILITY_VALUES = ("high", "medium", "low")
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

# Additive fallback score used only when no CVSS base score is available.
# It is intentionally conservative: a missing header is not a 9.8.
SEVERITY_SCORE = {
    "Critical": 45,
    "High": 35,
    "Medium": 18,
    "Low": 8,
    "Info": 2,
}

CONFIDENCE_SCORE = {
    "high": 20,
    "medium": 12,
    "low": 6,
}

EXPLOITABILITY_SCORE = {
    "high": 20,
    "medium": 10,
    "low": 4,
}

MAX_EVIDENCE_CHARS = 4000


def normalize_severity(value: Optional[str]) -> str:
    if not value:
        return "Info"

    normalized = value.strip().lower()
    mapping = {
        "critical": "Critical",
        "serious": "High",
        "high": "High",
        "medium": "Medium",
        "med": "Medium",
        "moderate": "Medium",
        "low": "Low",
        "minor": "Low",
        "info": "Info",
        "informational": "Info",
    }
    return mapping.get(normalized, "Info")


def _normalize_level(
    value: Optional[str],
    allowed_values: Tuple[str, ...],
    default_value: str,
) -> str:
    if not value:
        return default_value
    normalized = value.strip().lower()
    return normalized if normalized in allowed_values else default_value


def _infer_confidence(raw: Dict[str, Any], source: str, verified: bool) -> str:
    if raw.get("confidence"):
        return _normalize_level(raw.get("confidence"), CONFIDENCE_VALUES, "medium")
    if verified:
        return "high"
    if raw.get("cve") and source.lower() in {"osv", "msa", "nvd"}:
        return "high"
    if raw.get("evidence"):
        return "medium"
    if raw.get("payload"):
        return "low"
    return "low"


def _infer_exploitability(raw: Dict[str, Any], severity: str, verified: bool) -> str:
    if raw.get("kev"):
        return "high"
    if raw.get("exploitability"):
        return _normalize_level(raw.get("exploitability"), EXPLOITABILITY_VALUES, "medium")
    if severity == "Info":
        return "low"
    if verified and severity in ("Critical", "High"):
        return "high"
    return "medium"


def calculate_risk_score(
    severity: str,
    confidence: str,
    exploitability: str,
    cvss_score: Optional[float] = None,
) -> int:
    """Return a 0-100 prioritisation score.

    When a CVSS base score exists it is the most defensible source, so it is
    used directly (CVSS 9.8 -> 98).  Otherwise a transparent additive score is
    used and capped at 100.
    """

    if cvss_score is not None:
        try:
            return max(0, min(100, int(round(float(cvss_score) * 10))))
        except (TypeError, ValueError):
            pass
    score = (
        SEVERITY_SCORE.get(severity, SEVERITY_SCORE["Info"])
        + CONFIDENCE_SCORE.get(confidence, CONFIDENCE_SCORE["medium"])
        + EXPLOITABILITY_SCORE.get(exploitability, EXPLOITABILITY_SCORE["medium"])
    )
    return min(score, 100)


def _as_float(value: Any) -> Optional[float]:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "sim"}
    return bool(value)


def normalize_vulnerability(
    raw_vulnerability: Dict[str, Any],
    module_name: str,
    target_url: str,
) -> Dict[str, Any]:
    raw = raw_vulnerability or {}
    title = str(raw.get("title") or "Unnamed vulnerability")
    description = str(raw.get("description") or "No description provided.")

    cvss_score = _as_float(raw.get("cvss_score"))
    severity = normalize_severity(raw.get("severity"))
    if not raw.get("severity") and cvss_score is not None:
        if cvss_score >= 9.0:
            severity = "Critical"
        elif cvss_score >= 7.0:
            severity = "High"
        elif cvss_score >= 4.0:
            severity = "Medium"
        elif cvss_score > 0:
            severity = "Low"

    verified = _as_bool(raw.get("verified", False))
    source = str(raw.get("source") or module_name)
    confidence = _infer_confidence(raw, source, verified)
    exploitability = _infer_exploitability(raw, severity, verified)
    risk_score = calculate_risk_score(severity, confidence, exploitability, cvss_score)

    references = raw.get("references")
    if not isinstance(references, list):
        references = []
    references = [str(item) for item in references if str(item).strip()][:20]

    evidence = str(raw.get("evidence") or "")
    if len(evidence) > MAX_EVIDENCE_CHARS:
        evidence = evidence[:MAX_EVIDENCE_CHARS] + "\n...[truncated]"

    fixed_versions = raw.get("fixed_versions")
    if not isinstance(fixed_versions, list):
        fixed_versions = []

    metadata = raw.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}

    validation = raw.get("validation")
    if not isinstance(validation, dict):
        validation = {}

    return {
        "schema_version": "2.0",
        "title": title,
        "description": description,
        "severity": severity,
        "confidence": confidence,
        "exploitability": exploitability,
        "risk_score": risk_score,
        "module": module_name,
        "url": raw.get("url") or target_url,
        "evidence": evidence,
        "payload": raw.get("payload"),
        "cve": raw.get("cve"),
        "cwe": raw.get("cwe"),
        "remediation": str(raw.get("remediation") or "No remediation provided."),
        "references": references,
        "verified": verified,
        "source": source,
        "evidence_type": str(raw.get("evidence_type") or ("active" if verified else "heuristic")),
        "fixed_versions": fixed_versions,
        "cvss_score": cvss_score,
        "cvss_vector": raw.get("cvss_vector"),
        "epss": _as_float(raw.get("epss")),
        "epss_percentile": _as_float(raw.get("epss_percentile")),
        "kev": _as_bool(raw.get("kev", False)),
        "validation_status": str(
            raw.get("validation_status") or validation.get("status") or ""
        ),
        "validation": validation,
        "metadata": metadata,
    }


def normalize_vulnerabilities(
    vulnerabilities: Iterable[Dict[str, Any]],
    module_name: str,
    target_url: str,
) -> List[Dict[str, Any]]:
    return [
        normalize_vulnerability(vuln, module_name, target_url)
        for vuln in vulnerabilities
        if isinstance(vuln, dict)
    ]


def _finding_key(finding: Dict[str, Any]) -> Tuple[str, str, str]:
    cve = str(finding.get("cve") or "").strip().upper()
    title = str(finding.get("title") or "").strip().lower()
    url = str(finding.get("url") or "").strip().lower()
    metadata = finding.get("metadata") or {}
    parameter = str(metadata.get("parameter") or metadata.get("field") or "").strip().lower()
    if cve:
        return ("cve", cve, parameter or url)
    return ("title", title, parameter or url)


def deduplicate_vulnerabilities(
    findings: Iterable[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Keep the strongest version of duplicate findings.

    Prefer actively verified findings, then higher confidence, then higher
    risk score.  CVE findings from OSV and a module-specific check are merged
    instead of being reported twice.
    """

    best: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for finding in findings:
        key = _finding_key(finding)
        current = best.get(key)
        if current is None:
            best[key] = finding
            continue
        candidate_score = (
            1 if finding.get("verified") else 0,
            {"high": 3, "medium": 2, "low": 1}.get(str(finding.get("confidence")), 0),
            int(finding.get("risk_score") or 0),
        )
        current_score = (
            1 if current.get("verified") else 0,
            {"high": 3, "medium": 2, "low": 1}.get(str(current.get("confidence")), 0),
            int(current.get("risk_score") or 0),
        )
        if candidate_score > current_score:
            # Preserve useful references/metadata from the weaker duplicate.
            merged_refs = list(current.get("references") or [])
            for ref in finding.get("references") or []:
                if ref not in merged_refs:
                    merged_refs.append(ref)
            finding["references"] = merged_refs
            best[key] = finding

    return sort_vulnerabilities(best.values())


def sort_vulnerabilities(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        findings,
        key=lambda item: (
            SEVERITY_ORDER.get(str(item.get("severity")), 999),
            -int(item.get("risk_score") or 0),
            str(item.get("title") or ""),
        ),
    )
