#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Version-aware Moodle CVE matching using OSV.dev.

Hard-coded CVE tables age badly and, in this project, contained CVEs from
other products.  OSV publishes machine-readable advisories for the
``moodle/moodle`` Packagist package, including the affected version ranges
and fixed releases.  This module queries OSV by the exact detected version
and enriches the result with CISA KEV and FIRST EPSS when available.

The output is deliberately marked ``verified=False``: a version match means
"this release is in a known affected range", not "the vulnerability was
exploited successfully".
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from modules.cache import cache_filename
from modules.cve_validation import default_validation, validate_finding
from modules.http import build_session
from modules.msa import MSAMatcher

try:  # optional dependency, used only to calculate CVSS base scores
    from packaging.version import Version
except ImportError:  # pragma: no cover
    Version = None  # type: ignore

try:
    from cvss import CVSS2, CVSS3, CVSS4
except ImportError:  # pragma: no cover
    CVSS2 = None  # type: ignore
    CVSS3 = None  # type: ignore
    CVSS4 = None  # type: ignore

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_URL = "https://api.first.org/data/v1/epss"
OSV_VULN_URL = "https://osv.dev/vulnerability/{}"
NVD_URL = "https://nvd.nist.gov/vuln/detail/{}"
CISA_KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_EXACT_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_SEVERITY_MAP = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MODERATE": "Medium",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Info",
    "INFORMATIONAL": "Info",
}
_SEVERITY_RANK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def severity_from_cvss(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    try:
        value = float(score)
    except (TypeError, ValueError):
        return None
    if value >= 9.0:
        return "Critical"
    if value >= 7.0:
        return "High"
    if value >= 4.0:
        return "Medium"
    if value > 0:
        return "Low"
    return "Info"


def normalize_version(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    cleaned = str(value).strip().lstrip("vV")
    cleaned = cleaned.split("+")[0].split(" ")[0].strip()
    return cleaned or None


def is_exact_version(value: Optional[str]) -> bool:
    version = normalize_version(value)
    return bool(version and _EXACT_VERSION_RE.match(version))


def _default_cache_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "cache"


class CVEMatcher:
    """Query OSV.dev and enrich advisories with KEV/EPSS."""

    def __init__(
        self,
        *,
        logger: Optional[logging.Logger] = None,
        timeout: float = 30.0,
        cache_dir: Optional[Path] = None,
        cache_ttl: int = 24 * 60 * 60,
        offline: bool = False,
        enrich: bool = True,
    ) -> None:
        self.logger = logger or logging.getLogger("MoodleCVEMatcher")
        self.timeout = timeout
        self.cache_dir = Path(cache_dir) if cache_dir else _default_cache_dir()
        self.cache_ttl = cache_ttl
        self.offline = offline
        self.enrich = enrich
        self.data_available = True
        self.session = build_session(
            verify_ssl=True,
            timeout=timeout,
            user_agent="MoodleSecurityScanner/2.1 (CVE data)",
            retries=2,
        )
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            self.cache_dir = Path(tempfile.gettempdir()) / "mss-cache"
            try:
                self.cache_dir.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass

    # ------------------------------------------------------------------ cache
    def _cache_path(self, name: str) -> Path:
        return self.cache_dir / cache_filename(name, max_length=100)

    def _read_cache(self, name: str) -> Tuple[Optional[Any], bool]:
        path = self._cache_path(name)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None, False
        cached_at = float(payload.get("_cached_at", 0))
        age = time.time() - cached_at
        return payload.get("data"), age <= self.cache_ttl

    def _write_cache(self, name: str, data: Any) -> None:
        path = self._cache_path(name)
        payload = {"_cached_at": time.time(), "data": data}
        try:
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, path)
        except OSError as exc:
            self.logger.debug("Não foi possível guardar a cache %s: %s", path, exc)

    def _cached(self, name: str, loader) -> Optional[Any]:
        data, fresh = self._read_cache(name)
        if fresh and data is not None:
            return data
        if self.offline:
            return data
        try:
            loaded = loader()
        except Exception as exc:
            self.logger.warning("Fonte online indisponível (%s); a usar cache se existir.", exc)
            return data
        if loaded is None:
            return data
        self._write_cache(name, loaded)
        return loaded

    # -------------------------------------------------------------------- OSV
    def _query_osv(self, version: str) -> Optional[Dict[str, Any]]:
        body = {
            "package": {"name": "moodle/moodle", "ecosystem": "Packagist"},
            "version": version,
        }
        response = self.session.post(OSV_QUERY_URL, json=body, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, dict) else None

    def match(self, version: str, target_url: str) -> List[Dict[str, Any]]:
        normalized = normalize_version(version)
        if not normalized or not is_exact_version(normalized):
            return []

        data = self._cached(
            f"osv_moodle_{normalized}.json",
            lambda: self._query_osv(normalized),
        )
        self.data_available = data is not None
        if not data:
            return []

        findings: List[Dict[str, Any]] = []
        seen: set = set()
        for vulnerability in data.get("vulns", []) or []:
            if not isinstance(vulnerability, dict):
                continue
            if not self._is_affected(normalized, vulnerability):
                continue
            finding = self._finding_from_osv(vulnerability, normalized, target_url)
            if not finding:
                continue
            key = finding.get("cve") or finding.get("metadata", {}).get("osv_id")
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)

        if self.enrich and findings:
            self._enrich(findings)

        findings.sort(
            key=lambda item: (
                0 if item.get("kev") else 1,
                -float(item.get("cvss_score") or 0),
                item.get("cve") or "",
            )
        )
        self.logger.info(
            "%s advisories OSV afetam Moodle %s (correspondência por versão).",
            len(findings),
            normalized,
        )
        return findings

    def _is_affected(self, version: str, vulnerability: Dict[str, Any]) -> bool:
        if Version is None:
            return True
        try:
            parsed_version = Version(version)
        except Exception:
            return True

        affected_entries = vulnerability.get("affected") or []
        for affected in affected_entries:
            package = affected.get("package") or {}
            if package.get("name") != "moodle/moodle":
                continue
            for version_range in affected.get("ranges") or []:
                events = version_range.get("events") or []
                if self._range_affects(parsed_version, events):
                    return True
        # Some advisories only list explicit versions.
        for affected in affected_entries:
            package = affected.get("package") or {}
            if package.get("name") != "moodle/moodle":
                continue
            for listed in affected.get("versions") or []:
                if normalize_version(listed) == version:
                    return True
        return False

    @staticmethod
    def _range_affects(version, events: Sequence[Dict[str, str]]) -> bool:
        is_affected = False
        for event in events:
            if not isinstance(event, dict):
                continue
            introduced = event.get("introduced")
            fixed = event.get("fixed")
            last_affected = event.get("last_affected")
            try:
                if introduced is not None:
                    if str(introduced) == "0" or version >= Version(str(introduced)):
                        is_affected = True
                if fixed is not None and version >= Version(str(fixed)):
                    is_affected = False
                if last_affected is not None and version > Version(str(last_affected)):
                    is_affected = False
            except Exception:
                continue
        return is_affected

    def _finding_from_osv(
        self,
        vulnerability: Dict[str, Any],
        version: str,
        target_url: str,
    ) -> Optional[Dict[str, Any]]:
        osv_id = str(vulnerability.get("id") or "").strip()
        summary = str(vulnerability.get("summary") or "").strip()
        details = str(vulnerability.get("details") or "").strip()
        if not osv_id and not summary:
            return None

        aliases = [str(alias) for alias in vulnerability.get("aliases") or []]
        cve = next((alias for alias in aliases if _CVE_RE.fullmatch(alias)), None)
        cve = cve.upper() if cve else None

        database_specific = vulnerability.get("database_specific") or {}
        severity_raw = str(database_specific.get("severity") or "").upper()
        cwe_ids = database_specific.get("cwe_ids") or []
        cwe = cwe_ids[0] if cwe_ids else None

        fixed_versions = self._extract_fixed_versions(vulnerability)
        cvss_score, cvss_vector = self._extract_cvss(vulnerability)
        severity = _SEVERITY_MAP.get(severity_raw)
        derived_severity = severity_from_cvss(cvss_score)
        if derived_severity and (
            severity is None
            or _SEVERITY_RANK.get(derived_severity, 0) > _SEVERITY_RANK.get(severity, 0)
        ):
            severity = derived_severity
        if severity is None:
            severity = "Medium"

        references: List[str] = [OSV_VULN_URL.format(osv_id)] if osv_id else []
        if cve:
            references.append(NVD_URL.format(cve))
        for reference in vulnerability.get("references") or []:
            url = str(reference.get("url") or "").strip()
            if url and url not in references:
                references.append(url)
        references = references[:12]

        if fixed_versions:
            remediation = (
                "Atualizar para uma versão corrigida: "
                + ", ".join(fixed_versions)
                + ". Confirmar o build e os patches aplicados, porque a "
                "correspondência é feita por versão."
            )
        else:
            remediation = (
                "Aplicar as atualizações de segurança do Moodle/MSA e confirmar "
                "o build instalado. A correspondência é feita por versão."
            )

        title = f"{cve}: {summary}" if cve and summary else summary or cve or osv_id
        evidence = (
            f"Moodle {version} está dentro do intervalo afetado do advisory "
            f"{osv_id}"
            + (f" ({cve})" if cve else "")
            + ". Esta conclusão é baseada em versão, não em exploração ativa."
        )
        if cvss_vector:
            evidence += f" CVSS: {cvss_vector}"

        return {
            "title": title,
            "description": details or summary or "Advisory de segurança do Moodle.",
            "severity": severity,
            "confidence": "high",
            "exploitability": "medium",
            "cve": cve,
            "cwe": cwe,
            "url": target_url,
            "evidence": evidence,
            "remediation": remediation,
            "references": references,
            "verified": False,
            "source": "OSV",
            "evidence_type": "version",
            "fixed_versions": fixed_versions,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "epss": None,
            "epss_percentile": None,
            "kev": False,
            "metadata": {
                "osv_id": osv_id,
                "aliases": aliases,
                "severity_raw": severity_raw,
                "cwe_ids": cwe_ids,
                "detected_version": version,
            },
        }

    @staticmethod
    def _extract_fixed_versions(vulnerability: Dict[str, Any]) -> List[str]:
        fixed: List[str] = []
        for affected in vulnerability.get("affected") or []:
            package = affected.get("package") or {}
            if package.get("name") != "moodle/moodle":
                continue
            for version_range in affected.get("ranges") or []:
                for event in version_range.get("events") or []:
                    value = event.get("fixed") if isinstance(event, dict) else None
                    if value:
                        cleaned = normalize_version(str(value))
                        if cleaned and cleaned not in fixed:
                            fixed.append(cleaned)

        def sort_key(value: str):
            if Version is None:
                return value
            try:
                return Version(value)
            except Exception:
                return Version("0")

        return sorted(fixed, key=sort_key)

    @staticmethod
    def _extract_cvss(vulnerability: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
        for entry in vulnerability.get("severity") or []:
            if not isinstance(entry, dict):
                continue
            severity_type = str(entry.get("type") or "").upper()
            vector = str(entry.get("score") or "").strip()
            if not vector:
                continue

            calculator = None
            if severity_type.startswith("CVSS_V4") or vector.startswith("CVSS:4"):
                calculator = CVSS4
            elif severity_type.startswith("CVSS_V3") or vector.startswith("CVSS:3"):
                calculator = CVSS3
            elif severity_type.startswith("CVSS_V2") or vector.startswith("CVSS:2"):
                calculator = CVSS2
            if calculator is None:
                continue
            try:
                return float(calculator(vector).scores()[0]), vector
            except Exception:
                # Keep the vector even when the local calculator cannot parse it.
                return None, vector
        return None, None

    # -------------------------------------------------------------- enrichment
    def _load_kev(self) -> set:
        data = self._cached("cisa_kev.json", self._fetch_kev)
        if not isinstance(data, dict):
            return set()
        return {
            str(item.get("cveID") or "").upper()
            for item in data.get("vulnerabilities") or []
            if item.get("cveID")
        }

    def _fetch_kev(self) -> Optional[Dict[str, Any]]:
        response = self.session.get(KEV_URL, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, dict) else None

    def _fetch_epss(self, cves: Sequence[str]) -> Optional[Dict[str, Any]]:
        if not cves:
            return {}
        response = self.session.get(
            EPSS_URL,
            params={"cve": ",".join(cves)},
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, dict) else None

    def _enrich(self, findings: List[Dict[str, Any]]) -> None:
        cves = sorted({finding["cve"] for finding in findings if finding.get("cve")})
        kev = self._load_kev() if cves else set()
        epss_data: Dict[str, Dict[str, Any]] = {}
        if cves:
            payload = self._cached(
                "epss_" + "_".join(cves[:40]) + ".json",
                lambda: self._fetch_epss(cves[:40]),
            )
            if isinstance(payload, dict):
                for item in payload.get("data") or []:
                    cve_id = str(item.get("cve") or "").upper()
                    if cve_id:
                        epss_data[cve_id] = item

        for finding in findings:
            cve = finding.get("cve")
            if not cve:
                continue
            if cve in kev:
                finding["kev"] = True
                finding["exploitability"] = "high"
                finding["references"] = list(
                    dict.fromkeys(list(finding.get("references") or []) + [CISA_KEV_URL])
                )
            item = epss_data.get(cve)
            if item:
                try:
                    score = float(item.get("epss"))
                    finding["epss"] = score
                    finding["epss_percentile"] = float(item.get("percentile") or 0)
                    if not finding.get("kev"):
                        if score >= 0.10:
                            finding["exploitability"] = "high"
                        elif score >= 0.01:
                            finding["exploitability"] = "medium"
                        else:
                            finding["exploitability"] = "low"
                except (TypeError, ValueError):
                    pass


class MoodleCVETester:
    """Module adapter so the CVE matcher participates in the normal pipeline."""

    def __init__(
        self,
        target_url: str,
        logger: Optional[logging.Logger] = None,
        timeout: int = 30,
        proxy: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        delay: float = 0,
        user_agent: Optional[str] = None,
        verify_ssl: bool = True,
        session=None,
        offline: bool = False,
        cache_dir: Optional[str] = None,
        enrich: bool = True,
        validate_cves: bool = False,
        authorized: bool = False,
        use_msa: bool = True,
        msa_max_pages: int = 12,
        **_: Any,
    ) -> None:
        self.target_url = target_url
        self.logger = logger or logging.getLogger("MoodleCVETester")
        self.timeout = timeout
        self.offline = offline
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.enrich = enrich
        self.session = session
        self.validate_cves = validate_cves
        self.authorized = authorized
        self.use_msa = use_msa
        self.msa_max_pages = max(1, int(msa_max_pages or 12))
        self.version_info: Dict[str, Any] = {}

    def set_version_info(self, version_info: Dict[str, Any]) -> None:
        self.version_info = version_info or {}

    def run_tests(self) -> Dict[str, List[Dict[str, Any]]]:
        version = normalize_version(self.version_info.get("version"))
        confidence = self.version_info.get("version_confidence", "unknown")
        info: List[Dict[str, Any]] = []

        if not version or not is_exact_version(version):
            info.append(
                {
                    "title": "Correspondência de CVEs ignorada",
                    "description": (
                        "Não foi detetada uma versão Moodle exata (X.Y.Z). "
                        "Sem versão exata não é seguro afirmar que um CVE se aplica."
                    ),
                    "severity": "Info",
                    "verified": True,
                    "source": "OSV",
                    "evidence_type": "info",
                }
            )
            return {"vulnerabilities": [], "info": info}

        matcher = CVEMatcher(
            logger=self.logger,
            timeout=self.timeout,
            cache_dir=self.cache_dir,
            offline=self.offline,
            enrich=self.enrich,
        )
        findings = matcher.match(version, self.target_url)

        msa_findings: List[Dict[str, Any]] = []
        if self.use_msa:
            msa = MSAMatcher(
                logger=self.logger,
                timeout=self.timeout,
                cache_dir=self.cache_dir,
                offline=self.offline,
                max_pages=self.msa_max_pages,
            )
            msa_findings = msa.match(version, self.target_url)
            if not msa.data_available:
                info.append(
                    {
                        "title": "Fonte MSA indisponível",
                        "description": (
                            "Não foi possível obter os Moodle Security Announcements "
                            "(offline sem cache ou falha de rede). A correspondência "
                            "por OSV foi mantida, mas pode faltar um CVE ainda Pending."
                        ),
                        "severity": "Info",
                        "verified": True,
                        "source": "MSA",
                        "evidence_type": "info",
                    }
                )
            elif msa_findings and self.enrich:
                matcher._enrich(msa_findings)

        findings = self._merge_osv_and_msa(findings, msa_findings)

        if not matcher.data_available and not msa_findings:
            info.append(
                {
                    "title": "Fonte de CVEs indisponível",
                    "description": (
                        "Não foi possível obter dados do OSV (offline sem cache ou "
                        "falha de rede). Não é possível afirmar que a instalação não "
                        "tem CVEs conhecidos."
                    ),
                    "severity": "Info",
                    "verified": True,
                    "source": "OSV",
                    "evidence_type": "info",
                }
            )
            return {"vulnerabilities": [], "info": info}
        if not matcher.data_available and msa_findings:
            info.append(
                {
                    "title": "OSV indisponível; MSA utilizada",
                    "description": (
                        "Não foi possível obter o OSV, mas os Moodle Security "
                        "Announcements foram consultados. O resultado pode faltar "
                        "CVEs sem MSA correspondente."
                    ),
                    "severity": "Info",
                    "verified": True,
                    "source": "OSV",
                    "evidence_type": "info",
                }
            )

        if confidence != "high":
            for finding in findings:
                finding["confidence"] = "medium"
                finding["evidence"] = (
                    str(finding.get("evidence") or "")
                    + f" Atenção: a versão foi detetada com confiança {confidence}."
                )

        for finding in findings:
            finding["validation"] = default_validation(finding)
            if self.validate_cves:
                if not self.authorized:
                    finding["validation"] = {
                        **finding["validation"],
                        "status": "manual",
                        "method": "manual",
                        "reason": "A validação ativa requer --authorized.",
                    }
                elif finding["validation"].get("status") == "available":
                    finding["validation"] = validate_finding(
                        finding,
                        self.session,
                        self.target_url,
                        timeout=self.timeout,
                        logger=self.logger,
                    )
            finding["validation_status"] = finding["validation"].get("status")

        if self.validate_cves and not self.authorized:
            info.append(
                {
                    "title": "Validação de CVEs não executada",
                    "description": (
                        "Foi pedido --validate-cves sem --authorized. "
                        "Nenhum check ativo foi enviado ao alvo."
                    ),
                    "severity": "Info",
                    "verified": True,
                    "source": "OSV",
                    "evidence_type": "info",
                }
            )

        if not findings:
            info.append(
                {
                    "title": "Sem CVEs conhecidos para a versão detetada",
                    "description": (
                        f"O OSV não devolveu advisories aplicáveis a Moodle {version}. "
                        "Isto não prova que a instalação esteja segura."
                    ),
                    "severity": "Info",
                    "verified": True,
                    "source": "OSV",
                    "evidence_type": "info",
                }
            )
        return {"vulnerabilities": findings, "info": info}

    @staticmethod
    def _merge_osv_and_msa(
        osv_findings: List[Dict[str, Any]],
        msa_findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Merge by CVE/OSV id, preserving MSA references and fixed versions."""

        merged: List[Dict[str, Any]] = list(osv_findings)
        by_cve: Dict[str, Dict[str, Any]] = {
            str(item.get("cve") or "").upper(): item
            for item in merged
            if item.get("cve")
        }
        by_msa: Dict[str, Dict[str, Any]] = {
            str((item.get("metadata") or {}).get("msa_id") or ""): item
            for item in merged
            if (item.get("metadata") or {}).get("msa_id")
        }

        for finding in msa_findings:
            cve = str(finding.get("cve") or "").upper()
            msa_id = str((finding.get("metadata") or {}).get("msa_id") or "")
            existing = by_cve.get(cve) if cve else by_msa.get(msa_id)
            if existing is None:
                merged.append(finding)
                if cve:
                    by_cve[cve] = finding
                if msa_id:
                    by_msa[msa_id] = finding
                continue

            existing.setdefault("metadata", {})
            if msa_id:
                existing["metadata"]["msa_id"] = msa_id
            existing["references"] = list(
                dict.fromkeys(
                    list(existing.get("references") or [])
                    + list(finding.get("references") or [])
                )
            )[:16]
            existing["fixed_versions"] = list(
                dict.fromkeys(
                    list(existing.get("fixed_versions") or [])
                    + list(finding.get("fixed_versions") or [])
                )
            )
            if not existing.get("description") or len(str(existing.get("description"))) < 80:
                existing["description"] = finding.get("description") or existing.get("description")
            existing["evidence"] = (
                str(existing.get("evidence") or "")
                + f" Também listado em {msa_id} (Moodle Security Announcements)."
            )
            if _SEVERITY_RANK.get(str(finding.get("severity")), 0) > _SEVERITY_RANK.get(
                str(existing.get("severity")), 0
            ):
                existing["severity"] = finding.get("severity")

        return merged
