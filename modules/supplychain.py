#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unauthenticated supply-chain audit through an exposed composer.lock.

If a Moodle web root exposes ``composer.lock``, the exact PHP dependency
versions are public.  Those packages can be checked against OSV's Packagist
ecosystem without authentication or state-changing requests.  This is a
high-value black-box finding: a vulnerable library may be reachable even when
Moodle core itself is patched.

The module does not claim the dependency is exploitable; it reports the
version match and leaves exploitation validation manual.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from modules.http import build_session
from modules.schema import normalize_severity

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://osv.dev/vulnerability/{}"
NVD_URL = "https://nvd.nist.gov/vuln/detail/{}"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class MoodleSupplyChainTester:
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
        deep: bool = False,
        max_tests: int = 100,
        **_: Any,
    ) -> None:
        self.target_url = target_url.rstrip("/") + "/"
        self.timeout = timeout
        self.offline = offline
        self.deep = deep
        self.max_packages = max(1, min(int(max_tests or 100), 100))
        self.version_info: Dict[str, Any] = {}
        self.logger = logger or logging.getLogger("MoodleSupplyChainTester")
        self.cache_dir = (
            Path(cache_dir)
            if cache_dir
            else Path(__file__).resolve().parent.parent / "data" / "cache"
        )
        self.session = session or build_session(
            verify_ssl=verify_ssl,
            timeout=timeout,
            user_agent=user_agent,
            proxy=proxy,
            cookies=cookies,
        )
        self.osv_session = build_session(
            verify_ssl=True,
            timeout=timeout,
            user_agent="MoodleSecurityScanner/2.1 (composer audit)",
        )

    def set_version_info(self, version_info: Dict[str, Any]) -> None:
        self.version_info = version_info or {}

    def run_tests(self) -> Dict[str, List[Dict[str, Any]]]:
        results: Dict[str, List[Dict[str, Any]]] = {"vulnerabilities": [], "info": []}
        lock_url = self.target_url + "composer.lock"
        try:
            response = self.session.get(lock_url, timeout=self.timeout, allow_redirects=False)
        except Exception as exc:
            self.logger.debug("Erro ao obter composer.lock: %s", exc)
            return results

        if response.status_code != 200:
            results["info"].append(
                {
                    "title": "composer.lock não exposto",
                    "description": (
                        "Não foi possível auditar dependências PHP por falta "
                        "do lockfile."
                    ),
                    "severity": "Info",
                    "verified": True,
                    "source": "supplychain",
                    "evidence_type": "info",
                }
            )
            return results

        try:
            lock_data = response.json()
        except ValueError:
            results["info"].append(
                {
                    "title": "composer.lock inválido",
                    "description": "O ficheiro existe mas não é JSON válido.",
                    "severity": "Info",
                    "verified": True,
                    "source": "supplychain",
                    "evidence_type": "info",
                }
            )
            return results

        packages = self._parse_lock(lock_data)
        if not packages:
            return results

        queries = [
            {
                "package": {"name": name, "ecosystem": "Packagist"},
                "version": version,
            }
            for name, version in packages
        ]
        lock_hash = hashlib.sha256(response.content).hexdigest()[:16]
        payload = self._cached_osv(lock_hash, queries)
        if payload is None:
            results["info"].append(
                {
                    "title": "Auditoria de compositor indisponível",
                    "description": (
                        "O OSV não respondeu e não existe cache para este lockfile. "
                        "Não é possível afirmar que as dependências estão seguras."
                    ),
                    "severity": "Info",
                    "verified": True,
                    "source": "supplychain",
                    "evidence_type": "info",
                }
            )
            return results

        seen = set()
        for (name, version), entry in zip(packages, payload.get("results", [])):
            for vulnerability in (entry or {}).get("vulns", []) or []:
                finding = self._finding_from_osv(
                    name, version, vulnerability, lock_url
                )
                if not finding:
                    continue
                key = (name, finding.get("cve") or finding.get("metadata", {}).get("osv_id"))
                if key in seen:
                    continue
                seen.add(key)
                results["vulnerabilities"].append(finding)

        if results["vulnerabilities"]:
            results["info"].append(
                {
                    "title": "Dependências PHP auditadas",
                    "description": (
                        f"{len(packages)} pacotes de composer.lock verificados; "
                        f"{len(results['vulnerabilities'])} advisories aplicáveis. "
                        "A exploração não foi validada."
                    ),
                    "severity": "Info",
                    "verified": True,
                    "source": "supplychain",
                    "evidence_type": "info",
                }
            )
        return results

    # ------------------------------------------------------------------ utils
    @staticmethod
    def _parse_lock(data: Dict[str, Any]) -> List[Tuple[str, str]]:
        packages: List[Tuple[str, str]] = []
        seen = set()
        for key in ("packages", "packages-dev"):
            for item in data.get(key) or []:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or "").strip()
                version = str(item.get("version") or "").strip().lstrip("vV")
                if not name or not version or name in seen:
                    continue
                if version.startswith("dev-"):
                    continue
                seen.add(name)
                packages.append((name, version))
                if len(packages) >= 100:
                    return packages
        return packages

    def _cached_osv(
        self,
        lock_hash: str,
        queries: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        cache_name = f"composer_{lock_hash}.json"
        path = self.cache_dir / cache_name
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if time.time() - float(payload.get("_cached_at", 0)) <= 24 * 60 * 60:
                return payload.get("data")
        except (OSError, ValueError):
            pass
        if self.offline:
            return None
        try:
            response = self.osv_session.post(
                OSV_BATCH_URL,
                json={"queries": queries},
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            self.logger.debug("OSV batch indisponível: %s", exc)
            return None
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps({"_cached_at": time.time(), "data": data}, ensure_ascii=False),
                encoding="utf-8",
            )
            os.replace(tmp, path)
        except OSError:
            pass
        return data

    def _finding_from_osv(
        self,
        package: str,
        version: str,
        vulnerability: Dict[str, Any],
        lock_url: str,
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(vulnerability, dict):
            return None
        osv_id = str(vulnerability.get("id") or "")
        summary = str(vulnerability.get("summary") or vulnerability.get("details") or "")
        aliases = [str(alias) for alias in vulnerability.get("aliases") or []]
        cve = next((alias for alias in aliases if _CVE_RE.fullmatch(alias)), None)
        cve = cve.upper() if cve else None
        database_specific = vulnerability.get("database_specific") or {}
        severity = normalize_severity(str(database_specific.get("severity") or "Medium"))
        fixed = self._fixed_versions(vulnerability, package)
        references = [OSV_VULN_URL.format(osv_id)] if osv_id else []
        if cve:
            references.append(NVD_URL.format(cve))
        for reference in vulnerability.get("references") or []:
            url = str(reference.get("url") or "").strip()
            if url and url not in references:
                references.append(url)

        title = f"{package} {version}: {summary}".strip()
        if cve and cve not in title:
            title = f"{cve}: {title}"
        return {
            "title": title[:300],
            "description": str(
                vulnerability.get("details") or summary or "Dependência vulnerável."
            ),
            "severity": severity,
            "confidence": "high",
            "exploitability": "medium",
            "cve": cve,
            "cwe": (database_specific.get("cwe_ids") or [None])[0],
            "url": lock_url,
            "evidence": (
                f"composer.lock expõe {package} {version}; o OSV {osv_id} "
                "indica que esta versão está afetada. Isto é uma correspondência "
                "de versão de dependência, não prova de explorabilidade."
            ),
            "remediation": (
                f"Atualizar {package} para uma versão corrigida"
                + (f": {', '.join(fixed)}" if fixed else " indicada pelo advisory")
                + "."
            ),
            "references": references[:12],
            "verified": False,
            "source": "OSV/composer",
            "evidence_type": "version",
            "fixed_versions": fixed,
            "validation_status": "manual",
            "validation": {
                "status": "manual",
                "method": "manual",
                "reason": (
                    "Dependência de terceiros: confirmar se o componente é usado, "
                    "se a versão do lock corresponde ao deploy e se o advisory se aplica."
                ),
                "requirements": ["dependency review", "manual validation"],
            },
            "metadata": {
                "package": package,
                "installed_version": version,
                "osv_id": osv_id,
                "aliases": aliases,
                "lockfile": "composer.lock",
            },
        }

    @staticmethod
    def _fixed_versions(vulnerability: Dict[str, Any], package: str) -> List[str]:
        fixed: List[str] = []
        for affected in vulnerability.get("affected") or []:
            if (affected.get("package") or {}).get("name") != package:
                continue
            for version_range in affected.get("ranges") or []:
                for event in version_range.get("events") or []:
                    value = event.get("fixed") if isinstance(event, dict) else None
                    if value:
                        cleaned = str(value).lstrip("vV")
                        if cleaned not in fixed:
                            fixed.append(cleaned)
        return fixed
