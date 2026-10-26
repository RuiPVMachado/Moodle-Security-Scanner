#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Moodle web-service checks with strict, data-based confirmation.

A 200 response from an API endpoint is not a vulnerability.  Each check
below either observes real data that should require authentication, a
database/PHP debug error, or a successfully issued token.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.parse
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree

from modules.http import SecureSession, build_session

_ENDPOINTS = (
    "webservice/rest/server.php",
    "webservice/soap/server.php",
    "webservice/xmlrpc/server.php",
    "login/token.php",
    "lib/ajax/service.php",
    "lib/ajax/service-nologin.php",
    "admin/tool/mobile/launch.php",
    "auth/oauth2/login.php",
    "mod/lti/auth.php",
)

_DEBUG_RE = re.compile(
    r"(?:Fatal error|Uncaught\s|Stack trace|PHP Error|SQL syntax|Debug info)",
    re.IGNORECASE,
)


class MoodleAPITester:
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
        deep: bool = False,
        max_tests: int = 30,
        **_: Any,
    ) -> None:
        self.target_url = target_url.rstrip("/") + "/"
        self.timeout = timeout
        self.deep = deep
        self.max_tests = max(1, max_tests)
        self.version_info: Dict[str, Any] = {}
        self.logger = logger or logging.getLogger("MoodleAPITester")
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
        discovered = self.discover_api_endpoints()
        if discovered:
            results["info"].append(
                {
                    "title": "Endpoints de API encontrados",
                    "description": ", ".join(discovered[:12]),
                    "severity": "Info",
                    "verified": True,
                    "source": "api",
                    "evidence_type": "info",
                }
            )

        self._test_unauthenticated_webservice(results)
        self._test_token_endpoint(results)
        self._test_ajax_nologin(results)
        self._test_xmlrpc(results)
        self._test_info_disclosure(results)
        self._test_admin_webservice_page(results)
        self._test_cors(results)
        self._test_open_redirect(results)
        return results

    # --------------------------------------------------------------- discovery
    def discover_api_endpoints(self) -> List[str]:
        found: List[str] = []
        for endpoint in _ENDPOINTS[: self.max_tests]:
            url = self.target_url + endpoint
            try:
                response = self.session.get(url, timeout=self.timeout)
            except Exception:
                continue
            if response.status_code not in (404, 403):
                found.append(f"/{endpoint} ({response.status_code})")
        return found

    # ------------------------------------------------------------------- tests
    def _test_unauthenticated_webservice(
        self,
        results: Dict[str, List[Dict[str, Any]]],
    ) -> None:
        url = self.target_url + "webservice/rest/server.php"
        try:
            response = self.session.get(
                url,
                params={
                    "wsfunction": "core_course_get_courses",
                    "moodlewsrestformat": "json",
                },
                timeout=self.timeout,
            )
        except Exception:
            return
        data = self._json(response)
        if isinstance(data, list) and data and all(isinstance(item, dict) for item in data):
            if any("shortname" in item or "fullname" in item for item in data[:5]):
                results["vulnerabilities"].append(
                    {
                        "title": "Web service sem autenticação devolve cursos",
                        "description": (
                            "O endpoint REST devolveu dados de cursos sem token. "
                            "Isto expõe informação que devia exigir autenticação."
                        ),
                        "severity": "High",
                        "confidence": "high",
                        "evidence": json.dumps(data[:2], ensure_ascii=False)[:800],
                        "url": url,
                        "remediation": (
                            "Exigir token em todos os serviços externos e rever as "
                            "funções autorizadas para acesso anónimo."
                        ),
                        "cwe": "CWE-306",
                        "verified": True,
                        "source": "api",
                        "evidence_type": "active",
                    }
                )

    def _test_token_endpoint(self, results: Dict[str, List[Dict[str, Any]]]) -> None:
        url = self.target_url + "login/token.php"
        try:
            response = self.session.get(
                url,
                params={
                    "username": "mss_nonexistent_" + "a1b2c3",
                    "password": "mss_invalid_password_9f8e7d",
                    "service": "moodle_mobile_app",
                },
                timeout=self.timeout,
            )
        except Exception:
            return
        data = self._json(response)
        if isinstance(data, dict) and data.get("token"):
            results["vulnerabilities"].append(
                {
                    "title": "Token API emitido para credenciais inválidas",
                    "description": (
                        "O endpoint /login/token.php devolveu um token para um utilizador "
                        "inexistente. Qualquer pessoa pode obter acesso à API."
                    ),
                    "severity": "Critical",
                    "confidence": "high",
                    "evidence": "Resposta contém um campo token não vazio.",
                    "url": url,
                    "remediation": "Atualizar Moodle e rever a configuração do serviço móvel.",
                    "cwe": "CWE-287",
                    "verified": True,
                    "source": "api",
                    "evidence_type": "active",
                }
            )

    def _test_ajax_nologin(self, results: Dict[str, List[Dict[str, Any]]]) -> None:
        url = self.target_url + "lib/ajax/service-nologin.php"
        payload = [
            {
                "index": 0,
                "methodname": "core_course_get_courses",
                "args": {},
            }
        ]
        try:
            response = self.session.post(url, json=payload, timeout=self.timeout)
        except Exception:
            return
        data = self._json(response)
        if not isinstance(data, list) or not data:
            return
        first = data[0] if isinstance(data[0], dict) else {}
        content = first.get("data")
        if isinstance(content, list) and content:
            if any(
                isinstance(item, dict) and ("shortname" in item or "fullname" in item)
                for item in content[:5]
            ):
                results["vulnerabilities"].append(
                    {
                        "title": "AJAX service-nologin devolve dados autenticados",
                        "description": (
                            "O endpoint destinado a funções sem login devolveu cursos, "
                            "o que indica uma configuração ou permissão excessiva."
                        ),
                        "severity": "High",
                        "confidence": "high",
                        "evidence": json.dumps(content[:2], ensure_ascii=False)[:800],
                        "url": url,
                        "remediation": "Rever as funções permitidas em service-nologin.php.",
                        "cwe": "CWE-306",
                        "verified": True,
                        "source": "api",
                        "evidence_type": "active",
                    }
                )

    def _test_xmlrpc(self, results: Dict[str, List[Dict[str, Any]]]) -> None:
        url = self.target_url + "webservice/xmlrpc/server.php"
        payload = (
            '<?xml version="1.0"?>'
            "<methodCall><methodName>system.listMethods</methodName>"
            "<params></params></methodCall>"
        )
        try:
            response = self.session.post(
                url,
                data=payload,
                headers={"Content-Type": "text/xml"},
                timeout=self.timeout,
            )
        except Exception:
            return
        if response.status_code != 200 or "<methodResponse>" not in (response.text or ""):
            return
        if "<value>system." not in (response.text or ""):
            return
        results["info"].append(
            {
                "title": "XML-RPC ativo",
                "description": (
                    "O endpoint XML-RPC responde a system.listMethods. "
                    "É informação de reconhecimento, não uma falha por si só."
                ),
                "severity": "Info",
                "evidence": self._xml_methods(response.text or ""),
                "url": url,
                "verified": True,
                "source": "api",
                "evidence_type": "passive",
            }
        )

    def _test_info_disclosure(self, results: Dict[str, List[Dict[str, Any]]]) -> None:
        url = self.target_url + "webservice/rest/server.php"
        try:
            response = self.session.get(
                url,
                params={"wsfunction": "core_course_get_contents", "moodlewsrestformat": "json"},
                timeout=self.timeout,
            )
        except Exception:
            return
        body = response.text or ""
        if response.status_code == 200 and _DEBUG_RE.search(body):
            match = _DEBUG_RE.search(body)
            results["vulnerabilities"].append(
                {
                    "title": "Debug/erro interno exposto pela API",
                    "description": "A resposta da API contém detalhes internos de PHP/BD.",
                    "severity": "Medium",
                    "confidence": "medium",
                    "evidence": body[max(0, match.start() - 100) : match.start() + 400]
                    if match
                    else body[:500],
                    "url": url,
                    "remediation": "Desativar display_errors e Moodle debugging em produção.",
                    "cwe": "CWE-209",
                    "verified": True,
                    "source": "api",
                    "evidence_type": "passive",
                }
            )

    def _test_admin_webservice_page(self, results: Dict[str, List[Dict[str, Any]]]) -> None:
        url = self.target_url + "admin/webservice/service.php"
        try:
            response = self.session.get(url, timeout=self.timeout)
        except Exception:
            return
        if response.status_code != 200:
            return
        body = (response.text or "").lower()
        if "/login/" in (response.url or "").lower() or "logintoken" in body:
            return
        if "external services" in body and ("add service" in body or "webservice" in body):
            results["vulnerabilities"].append(
                {
                    "title": "Página de administração de web services exposta",
                    "description": (
                        "A configuração de serviços externos está acessível "
                        "sem autenticação."
                    ),
                    "severity": "Critical",
                    "confidence": "high",
                    "evidence": (
                        "GET /admin/webservice/service.php devolveu a página "
                        "de configuração sem login."
                    ),
                    "url": url,
                    "remediation": "Exigir autenticação e capacidade moodle/site:config.",
                    "cwe": "CWE-306",
                    "verified": True,
                    "source": "api",
                    "evidence_type": "active",
                }
            )

    def _test_cors(self, results: Dict[str, List[Dict[str, Any]]]) -> None:
        origin = "https://mss-cors.example"
        endpoints = (
            "webservice/rest/server.php",
            "login/token.php",
            "lib/ajax/service.php",
            "lib/ajax/service-nologin.php",
        )
        for endpoint in endpoints:
            url = self.target_url + endpoint
            try:
                response = self.session.get(
                    url,
                    headers={"Origin": origin, "Sec-Fetch-Mode": "cors"},
                    timeout=self.timeout,
                )
            except Exception:
                continue
            if response.status_code == 404:
                continue
            allow_origin = (response.headers.get("Access-Control-Allow-Origin") or "").strip()
            allow_credentials = (
                response.headers.get("Access-Control-Allow-Credentials") or ""
            ).strip().lower()
            if not allow_origin:
                continue
            reflected = allow_origin == origin
            wildcard_with_credentials = allow_origin == "*" and allow_credentials == "true"
            if not (reflected or wildcard_with_credentials):
                continue
            severity = "High" if allow_credentials == "true" else "Medium"
            results["vulnerabilities"].append(
                {
                    "title": "CORS permissivo em endpoint Moodle",
                    "description": (
                        "O endpoint reflete uma Origin arbitrária"
                        + (" e permite credenciais" if allow_credentials == "true" else "")
                        + ". Isto pode permitir que um site externo leia respostas autenticadas."
                    ),
                    "severity": severity,
                    "confidence": "high",
                    "evidence": (
                        f"GET {url}\nOrigin: {origin}\n"
                        f"Access-Control-Allow-Origin: {allow_origin}\n"
                        f"Access-Control-Allow-Credentials: {allow_credentials or '(ausente)'}"
                    ),
                    "url": url,
                    "remediation": (
                        "Não refletir Origin arbitrária; usar uma allowlist de origens "
                        "e não combinar wildcard com credenciais."
                    ),
                    "cwe": "CWE-942",
                    "verified": True,
                    "source": "api",
                    "evidence_type": "passive",
                }
            )

    def _test_open_redirect(self, results: Dict[str, List[Dict[str, Any]]]) -> None:
        external = "https://mss-open-redirect.example/"
        external_host = "mss-open-redirect.example"
        probes = (
            ("login/index.php", {"wantsurl": external}),
            ("auth/oauth2/login.php", {"wantsurl": external, "id": 1}),
        )
        for path, params in probes:
            url = self.target_url + path
            try:
                response = self.session.get(
                    url,
                    params=params,
                    allow_redirects=False,
                    timeout=self.timeout,
                )
            except Exception:
                continue
            if response.status_code not in (301, 302, 303, 307, 308):
                continue
            location = response.headers.get("Location") or ""
            target = urllib.parse.urljoin(url, location)
            if urllib.parse.urlparse(target).netloc.lower() != external_host:
                continue
            results["vulnerabilities"].append(
                {
                    "title": "Open redirect no login",
                    "description": (
                        "O parâmetro wantsurl redireciona para um domínio externo "
                        "sem validação, o que pode ser usado em phishing."
                    ),
                    "severity": "Medium",
                    "confidence": "high",
                    "evidence": f"GET {url} -> {location}",
                    "url": url,
                    "remediation": "Validar wantsurl contra uma allowlist de paths internos.",
                    "cwe": "CWE-601",
                    "verified": True,
                    "source": "api",
                    "evidence_type": "active",
                }
            )

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _json(response) -> Optional[Any]:
        if response is None:
            return None
        try:
            return response.json()
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _xml_methods(body: str) -> str:
        try:
            root = ElementTree.fromstring(body)
            values = [value.text for value in root.findall(".//value") if value.text]
            return ", ".join(values[:8])
        except Exception:
            return "system.listMethods respondeu com sucesso."
