#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Authenticated Moodle configuration audit.

Generic HTTP scanners can only guess at Moodle's internal security posture.
With a test account (ideally an administrator account) the scanner can read
Moodle's own security overview and phpinfo page and report concrete, observed
configuration problems.

Everything in this module is read-only.  It is disabled unless the scan has an
authenticated session and the user explicitly allowed active modules.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from modules.http import SecureSession, build_session

_STATUS_MAP = {
    "critical": "Critical",
    "error": "High",
    "warning": "Medium",
    "unknown": "Low",
}
_BAD_STATUSES = {"critical", "error", "warning", "unknown"}


class MoodleConfigTester:
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
        session: Optional[SecureSession] = None,
        authenticated: bool = False,
        deep: bool = False,
        max_tests: int = 20,
        **_: Any,
    ) -> None:
        self.target_url = target_url.rstrip("/") + "/"
        self.logger = logger or logging.getLogger("MoodleConfigTester")
        self.timeout = timeout
        self.authenticated = bool(authenticated)
        self.deep = deep
        self.max_tests = max(1, max_tests)
        self.session = session or build_session(
            verify_ssl=verify_ssl,
            timeout=timeout,
            user_agent=user_agent,
            proxy=proxy,
            cookies=cookies,
        )
        self.checked_security = False
        self.checked_phpinfo = False

    def run_tests(self) -> Dict[str, List[Dict[str, Any]]]:
        results: Dict[str, List[Dict[str, Any]]] = {"vulnerabilities": [], "info": []}
        if not self.authenticated:
            results["info"].append(
                {
                    "title": "Auditoria de configuração não executada",
                    "description": (
                        "É necessário autenticar com --username/--password ou --cookies "
                        "e usar --authorized para ler o relatório de segurança do Moodle."
                    ),
                    "severity": "Info",
                    "verified": True,
                    "source": "config",
                    "evidence_type": "info",
                }
            )
            return results

        self._check_security_report(results)
        self._check_phpinfo(results)
        if not results["vulnerabilities"]:
            if not self.checked_security and not self.checked_phpinfo:
                title = "Auditoria de configuração sem acesso"
                description = (
                    "A conta autenticada não conseguiu ler o relatório de segurança "
                    "nem o phpinfo; não é possível afirmar que a configuração está correta."
                )
            else:
                title = "Sem problemas de configuração confirmados"
                description = (
                    "As páginas de configuração acessíveis não revelaram problemas "
                    "que pudessem ser confirmados com os checks automáticos."
                )
            results["info"].append(
                {
                    "title": title,
                    "description": description,
                    "severity": "Info",
                    "verified": True,
                    "source": "config",
                    "evidence_type": "info",
                }
            )
        return results

    # ------------------------------------------------------------------ helpers
    def _get(self, url: str):
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except Exception as exc:
            self.logger.debug("Config request failed for %s: %s", url, exc)
            return None

    def _finding(
        self,
        *,
        title: str,
        description: str,
        severity: str,
        evidence: str,
        url: str,
        remediation: str,
        cwe: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "title": title,
            "description": description,
            "severity": severity,
            "confidence": "high",
            "evidence": evidence,
            "url": url,
            "remediation": remediation,
            "cwe": cwe,
            "verified": True,
            "source": "config",
            "evidence_type": "active",
        }

    def _check_security_report(self, results: Dict[str, List[Dict[str, Any]]]) -> None:
        url = self.target_url + "report/security/index.php"
        response = self._get(url)
        if response is None or response.status_code != 200:
            return
        final_url = (response.url or "").lower()
        body = response.text or ""
        if "/login/" in final_url or "logintoken" in body.lower():
            results["info"].append(
                {
                    "title": "Relatório de segurança inacessível",
                    "description": "A conta autenticada não tem acesso ao relatório de segurança.",
                    "severity": "Info",
                    "verified": True,
                    "source": "config",
                    "evidence_type": "info",
                }
            )
            return

        self.checked_security = True
        rows = self._parse_security_rows(body)
        if not rows:
            badge_counts = self._badge_counts(body)
            bad = {
                status: count
                for status, count in badge_counts.items()
                if status in _BAD_STATUSES and count
            }
            if bad:
                evidence = ", ".join(f"{status}={count}" for status, count in sorted(bad.items()))
                results["vulnerabilities"].append(
                    self._finding(
                        title="Relatório de segurança do Moodle reporta problemas",
                        description=(
                            "O relatório de segurança do Moodle contém estados de "
                            "aviso/erro, mas a tabela não pôde ser associada a cada check."
                        ),
                        severity="Medium",
                        evidence=f"Badges encontrados: {evidence}",
                        url=url,
                        remediation=(
                            "Abrir report/security/index.php com um administrador e "
                            "corrigir cada check com estado Warning/Error/Critical."
                        ),
                        cwe="CWE-16",
                    )
                )
            else:
                results["info"].append(
                    {
                        "title": "Relatório de segurança lido",
                        "description": (
                            "O relatório foi acessível, mas a tabela não pôde ser "
                            "interpretada automaticamente (versão/HTML diferente)."
                        ),
                        "severity": "Info",
                        "verified": True,
                        "source": "config",
                        "evidence_type": "info",
                    }
                )
            return

        findings = 0
        for row in rows[: self.max_tests]:
            status = str(row.get("status") or "").lower()
            if status not in _BAD_STATUSES:
                continue
            findings += 1
            name = str(row.get("name") or "Moodle security check")
            summary = str(row.get("summary") or "").strip()
            results["vulnerabilities"].append(
                self._finding(
                    title=f"Security check do Moodle: {name}",
                    description=summary or f"O check '{name}' não está em estado OK.",
                    severity=_STATUS_MAP.get(status, "Medium"),
                    evidence=(
                        f"GET {url}\nCheck: {name}\nEstado: {status}\n"
                        f"Resumo: {summary[:500]}"
                    ),
                    url=url,
                    remediation=(
                        "Seguir a ação indicada no relatório de segurança do Moodle "
                        "e confirmar a configuração com um administrador."
                    ),
                    cwe="CWE-16",
                )
            )
        results["info"].append(
            {
                "title": "Relatório de segurança do Moodle",
                "description": (
                    f"{len(rows)} checks lidos; {findings} com estado de aviso/erro. "
                    "Apenas estados não-OK são reportados como findings."
                ),
                "severity": "Info",
                "verified": True,
                "source": "config",
                "evidence_type": "info",
            }
        )

    @staticmethod
    def _parse_security_rows(html: str) -> List[Dict[str, str]]:
        soup = BeautifulSoup(html or "", "html.parser")
        rows: List[Dict[str, str]] = []
        for table in soup.find_all("table"):
            classes = " ".join(table.get("class") or [])
            if "checktable" not in classes and "security" not in classes:
                continue
            for tr in table.find_all("tr"):
                cells = tr.find_all(["td", "th"])
                if len(cells) < 2:
                    continue
                name = ""
                link = tr.find("a", href=re.compile(r"detail="))
                if link is not None:
                    name = link.get_text(" ", strip=True)
                if not name:
                    name = cells[1].get_text(" ", strip=True)
                if not name or name.lower() in {"more info", "status", "check"}:
                    continue
                status = ""
                for badge in tr.find_all(class_=re.compile("badge")):
                    text = badge.get_text(" ", strip=True)
                    if text:
                        status = text
                        break
                if not status:
                    image = tr.find("img")
                    if image is not None:
                        status = str(image.get("alt") or "")
                if not status:
                    continue
                summary = ""
                if len(cells) >= 3:
                    summary = cells[2].get_text(" ", strip=True)
                rows.append(
                    {
                        "name": name,
                        "status": status,
                        "summary": summary[:1000],
                    }
                )
        return rows

    @staticmethod
    def _badge_counts(html: str) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for match in re.finditer(
            r"badge\s+bg-(danger|warning|success|info|secondary)[^>]*>\s*([^<]+)",
            html or "",
            re.IGNORECASE,
        ):
            color = match.group(1).lower()
            text = match.group(2).strip().lower()
            status = {
                "danger": "error",
                "warning": "warning",
                "success": "ok",
                "info": "info",
                "secondary": "unknown",
            }.get(color, text)
            counts[status] = counts.get(status, 0) + 1
        return counts

    def _check_phpinfo(self, results: Dict[str, List[Dict[str, Any]]]) -> None:
        url = self.target_url + "admin/phpinfo.php"
        response = self._get(url)
        if response is None or response.status_code != 200:
            return
        body = response.text or ""
        lowered = body.lower()
        if "/login/" in (response.url or "").lower() and "phpinfo" not in lowered:
            return
        if "php version" not in lowered and "phpinfo()" not in lowered:
            return

        self.checked_phpinfo = True
        results["info"].append(
            {
                "title": "phpinfo de administração acessível",
                "description": (
                    "A conta autenticada consegue ler admin/phpinfo.php. "
                    "Isto é útil para auditoria, mas confirma que a página não está "
                    "bloqueada para administradores."
                ),
                "severity": "Info",
                "verified": True,
                "source": "config",
                "evidence_type": "passive",
                "url": url,
            }
        )

        settings = self._parse_phpinfo_settings(body)
        if settings.get("display_errors", "").lower() in {"on", "1", "true"}:
            results["vulnerabilities"].append(
                self._finding(
                    title="display_errors ativo em produção",
                    description=(
                        "O PHP está configurado para mostrar erros. Isto pode revelar "
                        "caminhos, SQL e detalhes internos em respostas de erro."
                    ),
                    severity="Medium",
                    evidence=f"phpinfo: display_errors={settings.get('display_errors')}",
                    url=url,
                    remediation="Definir display_errors=Off no php.ini de produção.",
                    cwe="CWE-209",
                )
            )
        if settings.get("allow_url_include", "").lower() in {"on", "1", "true"}:
            results["vulnerabilities"].append(
                self._finding(
                    title="allow_url_include ativo",
                    description=(
                        "O PHP permite incluir URLs remotas. Isto amplia o impacto "
                        "de uma falha de inclusão de ficheiros."
                    ),
                    severity="High",
                    evidence=f"phpinfo: allow_url_include={settings.get('allow_url_include')}",
                    url=url,
                    remediation="Definir allow_url_include=Off no php.ini.",
                    cwe="CWE-98",
                )
            )
        if settings.get("expose_php", "").lower() in {"on", "1", "true"}:
            results["vulnerabilities"].append(
                self._finding(
                    title="expose_php ativo",
                    description="O header X-Powered-By revela a versão de PHP.",
                    severity="Low",
                    evidence=f"phpinfo: expose_php={settings.get('expose_php')}",
                    url=url,
                    remediation="Definir expose_php=Off no php.ini.",
                    cwe="CWE-200",
                )
            )
        is_https = urlparse(self.target_url).scheme == "https"
        if is_https and settings.get("session.cookie_secure", "").lower() in {"off", "0", ""}:
            results["vulnerabilities"].append(
                self._finding(
                    title="session.cookie_secure desativado",
                    description="O cookie de sessão PHP pode ser enviado por HTTP.",
                    severity="Medium",
                    evidence=(
                        "phpinfo: session.cookie_secure="
                        f"{settings.get('session.cookie_secure')}"
                    ),
                    url=url,
                    remediation="Definir session.cookie_secure=On no php.ini e forçar HTTPS.",
                    cwe="CWE-614",
                )
            )
        if settings.get("session.cookie_httponly", "").lower() in {"off", "0", ""}:
            results["vulnerabilities"].append(
                self._finding(
                    title="session.cookie_httponly desativado",
                    description="O cookie de sessão PHP pode ser lido por JavaScript.",
                    severity="Medium",
                    evidence=(
                        "phpinfo: session.cookie_httponly="
                        f"{settings.get('session.cookie_httponly')}"
                    ),
                    url=url,
                    remediation="Definir session.cookie_httponly=On no php.ini.",
                    cwe="CWE-1004",
                )
            )
        if settings.get("session.use_strict_mode", "").lower() in {"off", "0", ""}:
            results["vulnerabilities"].append(
                self._finding(
                    title="session.use_strict_mode desativado",
                    description="O PHP pode aceitar IDs de sessão não gerados pelo servidor.",
                    severity="Low",
                    evidence=(
                        "phpinfo: session.use_strict_mode="
                        f"{settings.get('session.use_strict_mode')}"
                    ),
                    url=url,
                    remediation="Definir session.use_strict_mode=1 no php.ini.",
                    cwe="CWE-384",
                )
            )

    @staticmethod
    def _parse_phpinfo_settings(html: str) -> Dict[str, str]:
        settings: Dict[str, str] = {}
        soup = BeautifulSoup(html or "", "html.parser")
        for tr in soup.find_all("tr"):
            cells = tr.find_all(["td", "th"])
            if len(cells) < 2:
                continue
            key = cells[0].get_text(" ", strip=True)
            value = cells[1].get_text(" ", strip=True)
            if key and value:
                settings[key] = value
        return settings
