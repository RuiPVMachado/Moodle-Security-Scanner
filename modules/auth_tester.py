#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Authentication checks with explicit confirmation and safe defaults.

Only checks that can be proven from the response are reported as
vulnerabilities.  Credential guessing is opt-in (``--test-default-credentials``)
because it can lock accounts.  SQL injection, OAuth2 bypasses and other CVEs
are handled by the version-aware CVE module instead of being guessed here.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from bs4 import BeautifulSoup

from modules.http import SecureSession, build_session

_DEFAULT_CREDENTIALS = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "moodle"),
)


class MoodleAuthTester:
    def __init__(
        self,
        target_url: str,
        logger: Optional[logging.Logger] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 30,
        proxy: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        delay: float = 0,
        user_agent: Optional[str] = None,
        verify_ssl: bool = True,
        session: Optional[SecureSession] = None,
        test_default_credentials: bool = False,
        deep: bool = False,
        max_tests: int = 20,
        **_: Any,
    ) -> None:
        self.target_url = target_url.rstrip("/") + "/"
        self.username = username
        self.password = password
        self.timeout = timeout
        self.test_default_credentials = test_default_credentials
        self.deep = deep
        self.max_tests = max(1, max_tests)
        self.version_info: Dict[str, Any] = {}
        self.logger = logger or logging.getLogger("MoodleAuthTester")
        self.session = session or build_session(
            verify_ssl=verify_ssl,
            timeout=timeout,
            user_agent=user_agent,
            proxy=proxy,
            cookies=cookies,
        )
        self._login_attempts: Dict[str, int] = {}

    def set_version_info(self, version_info: Dict[str, Any]) -> None:
        self.version_info = version_info or {}

    def run_tests(self) -> Dict[str, List[Dict[str, Any]]]:
        results: Dict[str, List[Dict[str, Any]]] = {"vulnerabilities": [], "info": []}
        login_url = self.target_url + "login/index.php"
        response = self._get(login_url)
        if response is None or response.status_code != 200:
            results["info"].append(self._info("Página de login inacessível", login_url))
            return results

        self._check_login_form(response.text, login_url, results)

        if self.username and self.password:
            # Validate the credentials themselves, not a pre-existing cookie.
            self.session.cookies.clear()
            if self._login(self.username, self.password):
                results["info"].append(
                    {
                        "title": "Autenticação com as credenciais fornecidas",
                        "description": "As credenciais fornecidas são válidas.",
                        "severity": "Info",
                        "verified": True,
                        "source": "auth",
                        "evidence_type": "info",
                        "url": login_url,
                    }
                )
                self._check_admin_access(results)
            else:
                results["info"].append(
                    self._info(
                        "Credenciais fornecidas rejeitadas",
                        login_url,
                        "A autenticação com o utilizador fornecido falhou.",
                    )
                )

        if self.test_default_credentials:
            self._test_default_credentials(results, login_url)

        if self.deep:
            self._test_host_header_bypass(results)

        if not results["vulnerabilities"]:
            results["info"].append(
                self._info(
                    "Sem problemas de autenticação confirmados",
                    login_url,
                    "Não foram encontrados problemas de autenticação que pudessem ser confirmados.",
                )
            )
        return results

    # ------------------------------------------------------------------ helpers
    def _get(self, url: str):
        try:
            return self.session.get(url, timeout=self.timeout)
        except Exception as exc:
            self.logger.debug("Erro em %s: %s", url, exc)
            return None

    @staticmethod
    def _info(title: str, url: str, description: str = "") -> Dict[str, Any]:
        return {
            "title": title,
            "description": description or title,
            "severity": "Info",
            "url": url,
            "verified": True,
            "source": "auth",
            "evidence_type": "info",
        }

    def _check_login_form(
        self,
        html: str,
        login_url: str,
        results: Dict[str, List[Dict[str, Any]]],
    ) -> None:
        soup = BeautifulSoup(html or "", "html.parser")
        form = soup.find("form")
        if form is None:
            return
        has_username = form.find("input", {"name": "username"}) is not None
        has_password = form.find("input", {"name": "password"}) is not None
        if not (has_username and has_password):
            return
        token = form.find("input", {"name": "logintoken"})
        if token is None:
            results["vulnerabilities"].append(
                {
                    "title": "Formulário de login sem token CSRF",
                    "description": (
                        "O formulário de autenticação não inclui o campo logintoken. "
                        "Isto permite cross-site request forgery contra o login."
                    ),
                    "severity": "High",
                    "confidence": "high",
                    "evidence": "Formulário de login sem input[name=logintoken].",
                    "url": login_url,
                    "remediation": "Atualizar Moodle e confirmar a proteção CSRF do formulário.",
                    "cwe": "CWE-352",
                    "verified": True,
                    "source": "auth",
                    "evidence_type": "active",
                }
            )

    def _login(self, username: str, password: str) -> bool:
        if self._login_attempts.get(username, 0) >= 3:
            return False
        self._login_attempts[username] = self._login_attempts.get(username, 0) + 1

        login_url = self.target_url + "login/index.php"
        response = self._get(login_url)
        if response is None or response.status_code != 200:
            return False

        soup = BeautifulSoup(response.text or "", "html.parser")
        token_input = soup.find("input", {"name": "logintoken"})
        token = token_input.get("value", "") if token_input else ""

        try:
            result = self.session.post(
                login_url,
                data={
                    "username": username,
                    "password": password,
                    "logintoken": token,
                },
                timeout=self.timeout,
            )
        except Exception as exc:
            self.logger.debug("Erro no POST de login: %s", exc)
            return False

        body = (result.text or "").lower()
        if "loginerrors" in body or "invalid login" in body:
            return False
        return (
            "/my/" in result.url.lower()
            or "dashboard" in body
            or "my courses" in body
        )

    def _check_admin_access(self, results: Dict[str, List[Dict[str, Any]]]) -> None:
        response = self._get(self.target_url + "admin/index.php")
        if response is None or response.status_code != 200:
            return
        if "site administration" in (response.text or "").lower():
            results["info"].append(
                {
                    "title": "A conta autenticada tem acesso de administração",
                    "description": (
                        "A conta fornecida consegue aceder a Site administration. "
                        "Isto é esperado para um administrador, mas aumenta o impacto "
                        "de qualquer compromisso dessa conta."
                    ),
                    "severity": "Info",
                    "url": self.target_url + "admin/index.php",
                    "verified": True,
                    "source": "auth",
                    "evidence_type": "info",
                }
            )

    def _test_default_credentials(
        self,
        results: Dict[str, List[Dict[str, Any]]],
        login_url: str,
    ) -> None:
        # Start from a clean, unauthenticated state.
        self.session.cookies.clear()
        for username, password in _DEFAULT_CREDENTIALS:
            if self._login_attempts.get(username, 0) >= 3:
                continue
            if self._login(username, password):
                results["vulnerabilities"].append(
                    {
                        "title": "Credenciais padrão válidas",
                        "description": (
                            "O Moodle aceitou credenciais padrão/common. "
                            "Qualquer pessoa com acesso à rede pode autenticar-se."
                        ),
                        "severity": "Critical",
                        "confidence": "high",
                        "evidence": f"Login efetuado com {username}:{password}.",
                        "url": login_url,
                        "remediation": (
                            "Alterar imediatamente a password, ativar MFA e impor "
                            "uma política de passwords forte."
                        ),
                        "cwe": "CWE-521",
                        "verified": True,
                        "source": "auth",
                        "evidence_type": "active",
                    }
                )
                return

    def _test_host_header_bypass(self, results: Dict[str, List[Dict[str, Any]]]) -> None:
        url = self.target_url + "admin/index.php"
        try:
            response = self.session.get(
                url,
                headers={"Host": "localhost", "X-Forwarded-Host": "localhost"},
                timeout=self.timeout,
            )
        except Exception as exc:
            self.logger.debug("Erro no teste Host header: %s", exc)
            return
        if response.status_code == 200 and "site administration" in (response.text or "").lower():
            results["vulnerabilities"].append(
                {
                    "title": "Bypass de autenticação por Host header",
                    "description": (
                        "O acesso a Site administration foi possível com Host manipulado."
                    ),
                    "severity": "Critical",
                    "confidence": "high",
                    "evidence": (
                        "GET /admin/index.php com Host: localhost devolveu "
                        "Site administration."
                    ),
                    "url": url,
                    "remediation": "Validar Host no servidor web e atualizar Moodle.",
                    "cwe": "CWE-290",
                    "verified": True,
                    "source": "auth",
                    "evidence_type": "active",
                }
            )
