#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Session-fixation check. Cookie flags are covered by the passive module."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from bs4 import BeautifulSoup

from modules.http import SecureSession, build_session


class MoodleSessionTester:
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
        deep: bool = False,
        **_: Any,
    ) -> None:
        self.target_url = target_url.rstrip("/") + "/"
        self.username = username
        self.password = password
        self.timeout = timeout
        self.version_info: Dict[str, Any] = {}
        self.logger = logger or logging.getLogger("MoodleSessionTester")
        self.session = session or build_session(
            verify_ssl=verify_ssl,
            timeout=timeout,
            user_agent=user_agent,
            proxy=proxy,
            cookies=cookies,
        )

    def set_version_info(self, version_info: Dict[str, Any]) -> None:
        self.version_info = version_info or {}

    def run_tests(self) -> Dict[str, List[Dict[str, Any]]]:
        results: Dict[str, List[Dict[str, Any]]] = {"vulnerabilities": [], "info": []}
        if not (self.username and self.password):
            results["info"].append(
                {
                    "title": "Session fixation não testada",
                    "description": (
                        "É necessário --username/--password para testar a regeneração "
                        "do cookie de sessão no login."
                    ),
                    "severity": "Info",
                    "verified": True,
                    "source": "session",
                    "evidence_type": "info",
                }
            )
            return results

        login_url = self.target_url + "login/index.php"
        # Start from an unauthenticated state so the comparison is meaningful.
        self.session.cookies.clear()
        try:
            response = self.session.get(login_url, timeout=self.timeout)
        except Exception as exc:
            self.logger.debug("Erro ao obter login: %s", exc)
            return results
        if response.status_code != 200:
            return results

        before = {
            cookie.name: cookie.value
            for cookie in self.session.cookies
            if "MoodleSession" in cookie.name
        }
        if not before:
            results["info"].append(
                {
                    "title": "Session fixation não aplicável",
                    "description": "O servidor não definiu MoodleSession antes do login.",
                    "severity": "Info",
                    "verified": True,
                    "source": "session",
                    "evidence_type": "info",
                }
            )
            return results

        soup = BeautifulSoup(response.text or "", "html.parser")
        token_input = soup.find("input", {"name": "logintoken"})
        token = token_input.get("value", "") if token_input else ""
        try:
            login = self.session.post(
                login_url,
                data={
                    "username": self.username,
                    "password": self.password,
                    "logintoken": token,
                },
                timeout=self.timeout,
            )
        except Exception as exc:
            self.logger.debug("Erro no login: %s", exc)
            return results

        body = (login.text or "").lower()
        if "loginerrors" in body or "invalid login" in body:
            results["info"].append(
                {
                    "title": "Session fixation não confirmada",
                    "description": "O login com as credenciais fornecidas falhou.",
                    "severity": "Info",
                    "verified": True,
                    "source": "session",
                    "evidence_type": "info",
                }
            )
            return results

        after = {
            cookie.name: cookie.value
            for cookie in self.session.cookies
            if "MoodleSession" in cookie.name
        }
        shared = set(before) & set(after)
        if shared and all(before[name] == after[name] for name in shared):
            results["vulnerabilities"].append(
                {
                    "title": "Session fixation no login",
                    "description": (
                        "O cookie MoodleSession não muda após autenticação. "
                        "Um atacante que fixe o cookie antes do login pode reutilizar "
                        "a sessão autenticada."
                    ),
                    "severity": "High",
                    "confidence": "high",
                    "evidence": "MoodleSession igual antes e depois do login.",
                    "url": login_url,
                    "remediation": "Atualizar Moodle e confirmar session_regenerate_id no login.",
                    "cwe": "CWE-384",
                    "verified": True,
                    "source": "session",
                    "evidence_type": "active",
                }
            )
        return results
