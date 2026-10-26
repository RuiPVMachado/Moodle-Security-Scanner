#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Moodle Security Announcements (MSA) matching.

OSV/GitHub advisories lag behind Moodle's own announcements and sometimes list
a CVE as pending for months.  This module reads the public
``https://moodle.org/security/`` forum, extracts the structured fields from
each MSA post (severity, affected versions, fixed versions, CVE identifiers)
and matches them against the detected release.

The parser is intentionally conservative: a finding is produced only when the
detected version is inside an explicit version range from the MSA.  Pending
CVEs are reported under their MSA identifier rather than being invented.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from bs4 import BeautifulSoup

from modules.cache import JsonCache
from modules.http import RateLimiter, build_session

try:
    from packaging.version import Version
except ImportError:  # pragma: no cover
    Version = None  # type: ignore

MSA_INDEX_URL = "https://moodle.org/security/index.php"
MSA_FORUM_URL = "https://moodle.org/mod/forum/discuss.php?d={discussion}"
NVD_URL = "https://nvd.nist.gov/vuln/detail/{}"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_MSA_RE = re.compile(r"(MSA-\d{2}-\d{4}):\s*(.+)", re.IGNORECASE)
_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")
_RANGE_RE = re.compile(
    r"(\d+\.\d+(?:\.\d+)?)\s+to\s+(\d+\.\d+(?:\.\d+)?)",
    re.IGNORECASE,
)
_SEVERITY_MAP = {
    "critical": "Critical",
    "serious": "High",
    "high": "High",
    "moderate": "Medium",
    "medium": "Medium",
    "minor": "Low",
    "low": "Low",
}


def _version(value: str):
    if Version is None:
        return None
    try:
        return Version(value.replace(" ", ""))
    except Exception:
        return None


def _version_list(text: str) -> List[str]:
    result: List[str] = []
    for match in _VERSION_RE.finditer(text or ""):
        value = match.group(0)
        if value not in result:
            result.append(value)
    return result


def _parse_ranges(text: str) -> List[Tuple[str, str]]:
    ranges: List[Tuple[str, str]] = []
    for match in _RANGE_RE.finditer(text or ""):
        ranges.append((match.group(1), match.group(2)))
    return ranges


def _branch(version: str) -> str:
    parts = version.split(".")
    return ".".join(parts[:2])


class MSAMatcher:
    """Fetch, cache and match Moodle Security Announcements."""

    def __init__(
        self,
        *,
        logger: Optional[logging.Logger] = None,
        timeout: float = 30.0,
        cache_dir: Optional[Path] = None,
        cache_ttl: int = 24 * 60 * 60,
        offline: bool = False,
        max_pages: int = 12,
    ) -> None:
        self.logger = logger or logging.getLogger("MoodleMSA")
        self.timeout = timeout
        self.offline = offline
        self.max_pages = max(1, int(max_pages))
        self.cache = JsonCache(
            cache_dir,
            ttl=cache_ttl,
            offline=offline,
            logger=self.logger,
        )
        self.session = build_session(
            verify_ssl=True,
            timeout=timeout,
            user_agent=(
                "Mozilla/5.0 (compatible; MoodleSecurityScanner/2.1; "
                "+https://github.com/RuiPVMachado/Moodle-Security-Scanner)"
            ),
            retries=2,
            rate_limiter=RateLimiter(0.2),
        )
        self.data_available = True

    # ------------------------------------------------------------------ fetch
    def _fetch_page(self, page: int) -> Optional[str]:
        try:
            response = self.session.get(
                MSA_INDEX_URL,
                params={"o": 3, "s": 10, "p": page},
                timeout=self.timeout,
            )
        except Exception as exc:
            self.logger.warning("MSA page request failed: %s", exc)
            return None
        if response is None or response.status_code != 200:
            self.logger.debug(
                "MSA page %s returned HTTP %s",
                page,
                getattr(response, "status_code", None),
            )
            return None
        return response.text or ""

    def _load_advisories(self) -> List[Dict[str, Any]]:
        def loader() -> Optional[List[Dict[str, Any]]]:
            advisories: List[Dict[str, Any]] = []
            seen: set[str] = set()
            for page in range(self.max_pages):
                html = self._fetch_page(page)
                if not html:
                    if page == 0:
                        return None
                    break
                parsed = parse_msa_html(html)
                if not parsed:
                    break
                for advisory in parsed:
                    key = advisory.get("msa_id") or advisory.get("title") or ""
                    if key and key not in seen:
                        seen.add(key)
                        advisories.append(advisory)
            return advisories or None

        cached = self.cache.get(f"msa_advisories_{self.max_pages}.json", loader)
        if cached is None:
            self.data_available = False
            return []
        self.data_available = True
        if not isinstance(cached, list):
            return []
        return [item for item in cached if isinstance(item, dict)]

    # ------------------------------------------------------------------ match
    def match(self, version: str, target_url: str) -> List[Dict[str, Any]]:
        parsed_version = _version(version)
        if parsed_version is None:
            return []

        findings: List[Dict[str, Any]] = []
        for advisory in self._load_advisories():
            ranges = advisory.get("affected_ranges") or []
            fixed = advisory.get("fixed_versions") or []
            affected = False
            matched_ranges: List[Tuple[str, str]] = []
            for start, end in ranges:
                start_version = _version(str(start))
                end_version = _version(str(end))
                if start_version is None or end_version is None:
                    continue
                if start_version <= parsed_version <= end_version:
                    affected = True
                    matched_ranges.append((str(start), str(end)))
            if not affected and not ranges:
                # Fall back to branch + fixed version when the MSA only gives
                # a branch list (for example "5.2, 5.1, 5.0, 4.5").
                if _branch(version) in advisory.get("affected_branches", []):
                    branch_fixed = [
                        item
                        for item in fixed
                        if _branch(str(item)) == _branch(version)
                    ]
                    if not branch_fixed:
                        affected = True
                    else:
                        parsed_fixed = _version(str(branch_fixed[0]))
                        affected = parsed_fixed is not None and parsed_version < parsed_fixed
                        if affected:
                            matched_ranges.append((version, str(branch_fixed[0])))
            if not affected:
                continue

            findings.append(self._finding_from_msa(advisory, version, target_url, matched_ranges))

        self.logger.info("%s MSA advisories affect Moodle %s.", len(findings), version)
        return findings

    def _finding_from_msa(
        self,
        advisory: Dict[str, Any],
        version: str,
        target_url: str,
        matched_ranges: Sequence[Tuple[str, str]],
    ) -> Dict[str, Any]:
        msa_id = str(advisory.get("msa_id") or "").strip()
        summary = str(advisory.get("summary") or advisory.get("title") or "").strip()
        cve_ids = [str(item).upper() for item in advisory.get("cve_ids") or []]
        cve = cve_ids[0] if cve_ids else None
        fixed = [str(item) for item in advisory.get("fixed_versions") or []]
        references = [MSA_INDEX_URL]
        if advisory.get("discussion_id"):
            references.insert(
                0,
                MSA_FORUM_URL.format(discussion=advisory["discussion_id"]),
            )
        for commit in advisory.get("commits") or []:
            if commit not in references:
                references.append(str(commit))
        if cve:
            references.append(NVD_URL.format(cve))

        range_text = ", ".join(f"{start} – {end}" for start, end in matched_ranges)
        evidence = (
            f"Moodle {version} is inside the MSA affected range ({range_text}). "
            f"Affected: {advisory.get('affected_text') or range_text}. "
            f"Fixed: {', '.join(fixed) if fixed else 'see advisory'}. "
            "This conclusion is based on the official MSA, not on exploitation."
        )
        remediation = (
            f"Upgrade to a fixed release for this branch: "
            f"{', '.join(fixed) if fixed else 'see the MSA'}."
        )
        description = str(advisory.get("description") or summary)
        if advisory.get("affected_text") or fixed:
            description += (
                f"\n\nVersions affected: {advisory.get('affected_text') or 'unknown'}."
                f"\nVersions fixed: {', '.join(fixed) if fixed else 'unknown'}."
            )
        return {
            "title": f"{msa_id}: {summary}" if msa_id else summary,
            "description": description,
            "severity": advisory.get("severity") or "Medium",
            "confidence": "high",
            "exploitability": "medium",
            "cve": cve,
            "cwe": None,
            "url": target_url,
            "evidence": evidence,
            "remediation": remediation,
            "references": list(dict.fromkeys(references))[:16],
            "verified": False,
            "source": "MSA",
            "evidence_type": "version",
            "fixed_versions": fixed,
            "cvss_score": None,
            "cvss_vector": None,
            "epss": None,
            "epss_percentile": None,
            "kev": False,
            "metadata": {
                "msa_id": msa_id,
                "cve_ids": cve_ids,
                "affected_ranges": list(matched_ranges),
                "affected_text": advisory.get("affected_text"),
                "fixed_versions": fixed,
                "advisory_date": advisory.get("date"),
                "tracker": advisory.get("tracker"),
                "detected_version": version,
            },
        }


def parse_msa_html(html: str) -> List[Dict[str, Any]]:
    """Parse one MSA index page into advisory dictionaries."""

    soup = BeautifulSoup(html or "", "html.parser")
    advisories: List[Dict[str, Any]] = []

    for post in soup.select("div.forumpost"):
        subject = post.select_one("[data-region-content='forum-post-core-subject']")
        if subject is None:
            continue
        title = subject.get_text(" ", strip=True)
        match = _MSA_RE.match(title)
        if not match:
            continue
        msa_id = match.group(1).upper()
        summary = match.group(2).strip()

        content = post.select_one(".post-content-container") or post
        rows: Dict[str, str] = {}
        for row in content.find_all("tr"):
            cells = row.find_all(["td", "th"])
            if len(cells) < 2:
                continue
            label = cells[0].get_text(" ", strip=True).rstrip(":").strip().lower()
            value = cells[1].get_text(" ", strip=True)
            if label:
                rows[label] = value

        description = ""
        first_paragraph = content.find("p")
        if first_paragraph is not None:
            description = first_paragraph.get_text(" ", strip=True)

        affected_text = rows.get("versions affected", "")
        fixed_text = rows.get("versions fixed", "")
        cve_text = (
            rows.get("cve identifier")
            or rows.get("cve identifiers")
            or rows.get("cve id")
            or ""
        )
        severity_text = rows.get("severity/risk") or rows.get("severity") or ""
        severity = _SEVERITY_MAP.get(severity_text.strip().lower(), "Medium")

        affected_ranges = _parse_ranges(affected_text)
        affected_branches: List[str] = []
        if not affected_ranges:
            for item in _version_list(affected_text):
                branch = _branch(item)
                if branch not in affected_branches:
                    affected_branches.append(branch)

        fixed_versions = _version_list(fixed_text)
        commits = [
            link.get("href")
            for link in content.find_all("a", href=True)
            if "github.com/moodle/moodle" in str(link.get("href"))
        ]
        discussion = post.find("a", href=re.compile(r"discuss\.php\?d=\d+"))
        discussion_id = None
        if discussion is not None:
            found = re.search(r"d=(\d+)", str(discussion.get("href")))
            if found:
                discussion_id = found.group(1)
        time_tag = post.find("time")
        date = time_tag.get("datetime") if time_tag is not None else None

        advisories.append(
            {
                "msa_id": msa_id,
                "title": title,
                "summary": summary,
                "description": description,
                "severity": severity,
                "affected_text": affected_text,
                "affected_ranges": affected_ranges,
                "affected_branches": affected_branches,
                "fixed_versions": fixed_versions,
                "cve_ids": [item.upper() for item in _CVE_RE.findall(cve_text)],
                "cve_text": cve_text,
                "commits": commits,
                "discussion_id": discussion_id,
                "date": date,
                "tracker": rows.get("tracker issue", ""),
            }
        )
    return advisories
