#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Conservative reflected-XSS detection.

The scanner does not send ``alert(1)``.  It sends a unique, inert custom tag
(``<msscanary...>``) and reports a finding only when the exact raw tag is
reflected back by the server.  That proves missing HTML encoding without
executing JavaScript and without relying on context heuristics.
"""

from __future__ import annotations

import html as html_module
import logging
import random
import string
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional, Tuple

from bs4 import BeautifulSoup

from modules.discovery import replace_query_param
from modules.http import SecureSession, build_session

_DISCOVERY_PATHS = (
    "",
    "search/index.php",
    "course/search.php",
    "mod/forum/search.php",
    "user/index.php",
    "tag/search.php",
    "calendar/view.php",
    "login/forgot_password.php",
)

_SKIP_FIELDS = {
    "password",
    "submit",
    "cancel",
    "reset",
    "login",
    "logintoken",
    "sesskey",
    "id",
    "action",
    "returnurl",
    "wantsurl",
}


def _random_token(length: int = 8) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))


class MoodleXSSTester:
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
        max_tests: int = 40,
        **_: Any,
    ) -> None:
        self.target_url = target_url.rstrip("/") + "/"
        self.timeout = timeout
        self.deep = deep
        self.max_tests = max(1, max_tests if deep else min(max_tests, 40))
        self.version_info: Dict[str, Any] = {}
        self.logger = logger or logging.getLogger("MoodleXSSTester")
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
        targets = self._discover_targets()
        if not targets:
            results["info"].append(
                self._info(
                    "Sem pontos de reflexão XSS descobertos",
                    "Não foram encontrados formulários ou parâmetros de URL testáveis.",
                )
            )
            return results

        tested = 0
        for url, method, parameter, extra in targets:
            if tested >= self.max_tests:
                break
            tested += 1
            finding = self._test_parameter(url, method, parameter, extra)
            if finding:
                results["vulnerabilities"].append(finding)

        results["info"].append(
            self._info(
                "XSS refletido: resumo",
                f"Testados {tested} parâmetros com canários de HTML. "
                "XSS armazenado e DOM não são afirmados sem autenticação/browser.",
            )
        )
        return results

    # --------------------------------------------------------------- discovery
    def _discover_targets(self) -> List[Tuple[str, str, str, Dict[str, str]]]:
        targets: List[Tuple[str, str, str, Dict[str, str]]] = []
        seen = set()

        for path in _DISCOVERY_PATHS:
            url = self.target_url + path
            response = self._get(url)
            if response is None or response.status_code != 200:
                continue
            if self._is_login_wall(response):
                continue

            for form in self._extract_forms(response.text or "", response.url):
                for parameter in form["parameters"]:
                    key = self._target_key(form["action"], form["method"], parameter)
                    if key in seen:
                        continue
                    seen.add(key)
                    targets.append(
                        (
                            form["action"],
                            form["method"],
                            parameter,
                            form["data"],
                        )
                    )

            for link_url, parameter in self._extract_link_parameters(
                response.text or "",
                response.url,
            ):
                key = self._target_key(link_url, "get", parameter)
                if key in seen:
                    continue
                seen.add(key)
                targets.append((link_url, "get", parameter, {}))

        return targets

    def _extract_forms(
        self,
        html: str,
        base_url: str,
    ) -> Iterable[Dict[str, Any]]:
        soup = BeautifulSoup(html or "", "html.parser")
        for form in soup.find_all("form"):
            action = urllib.parse.urljoin(base_url, form.get("action") or base_url)
            target_netloc = urllib.parse.urlparse(self.target_url).netloc
            if urllib.parse.urlparse(action).netloc != target_netloc:
                continue
            method = str(form.get("method") or "get").lower()
            data: Dict[str, str] = {}
            parameters: List[str] = []
            for field in form.find_all(["input", "textarea", "select"]):
                name = field.get("name")
                if not name:
                    continue
                field_type = str(field.get("type") or "text").lower()
                if field.name == "textarea":
                    value = field.text or ""
                elif field.name == "select":
                    option = field.find("option", selected=True) or field.find("option")
                    value = option.get("value", "") if option else ""
                elif field_type in {"checkbox", "radio"}:
                    if not field.has_attr("checked"):
                        continue
                    value = field.get("value", "on")
                else:
                    value = field.get("value", "")
                data[name] = value
                if field_type in {"text", "search", "email", "url", "tel", "textarea"}:
                    if name.lower() not in _SKIP_FIELDS:
                        parameters.append(name)
            if parameters:
                yield {
                    "action": action,
                    "method": method if method in {"get", "post"} else "get",
                    "parameters": parameters[:8],
                    "data": data,
                }

    def _extract_link_parameters(
        self,
        html: str,
        base_url: str,
    ) -> Iterable[Tuple[str, str]]:
        soup = BeautifulSoup(html or "", "html.parser")
        origin = urllib.parse.urlparse(self.target_url).netloc
        for link in soup.find_all("a", href=True):
            href = urllib.parse.urljoin(base_url, link["href"])
            parsed = urllib.parse.urlparse(href)
            if parsed.netloc != origin or not parsed.query:
                continue
            for parameter, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
                if parameter.lower() in _SKIP_FIELDS:
                    continue
                yield href, parameter

    # -------------------------------------------------------------------- test
    def _test_parameter(
        self,
        url: str,
        method: str,
        parameter: str,
        extra: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        control = "msscanary" + _random_token()
        control_response = self._send(url, method, parameter, control, extra)
        if control_response is None:
            return None
        if not self._is_html_response(control_response):
            return None
        if control not in (control_response.text or ""):
            return None

        payloads = ["<mss" + _random_token() + ">"]
        if self.deep:
            payloads.append('"><mss' + _random_token() + ">")
            payloads.append("'><mss" + _random_token() + ">")

        confirmed = []
        for payload in payloads:
            response = self._send(url, method, parameter, payload, extra)
            if response is None or not self._is_html_response(response):
                continue
            body = response.text or ""
            if payload in body and html_module.escape(payload) not in body:
                confirmed.append(payload)

        if not confirmed:
            return None

        finding_url = (
            replace_query_param(url, parameter, confirmed[0])
            if method == "get"
            else url
        )
        evidence = (
            f"O parâmetro '{parameter}' refletiu o canário HTML sem encoding.\n"
            f"URL: {finding_url}\nMétodo: {method.upper()}\n"
            f"Payloads refletidos: {', '.join(confirmed)}"
        )
        return {
            "title": "Reflected HTML injection (potencial XSS)",
            "description": (
                f"O parâmetro '{parameter}' é refletido sem escape de '<' e '>'. "
                "Isto permite injetar HTML; a execução de JavaScript depende do "
                "contexto e deve ser confirmada manualmente num browser."
            ),
            "severity": "Medium",
            "confidence": "high" if len(confirmed) >= 2 else "medium",
            "evidence": evidence,
            "payload": confirmed[0],
            "url": finding_url,
            "remediation": (
                "Aplicar output encoding contextual (s(), html_writer, mustache) "
                "e validar a entrada. Confirmar o contexto exato antes de classificar "
                "como XSS executável."
            ),
            "cwe": "CWE-79",
            "verified": True,
            "source": "active",
            "evidence_type": "active",
            "metadata": {"parameter": parameter, "method": method.upper()},
        }

    def _send(
        self,
        url: str,
        method: str,
        parameter: str,
        value: str,
        extra: Dict[str, str],
    ):
        try:
            if method == "post":
                data = dict(extra)
                data[parameter] = value
                return self.session.post(url, data=data, timeout=self.timeout)
            return self.session.get(
                replace_query_param(url, parameter, value),
                timeout=self.timeout,
            )
        except Exception as exc:
            self.logger.debug("Erro XSS em %s (%s): %s", url, parameter, exc)
            return None

    def _get(self, url: str):
        try:
            return self.session.get(url, timeout=self.timeout)
        except Exception:
            return None

    @staticmethod
    def _is_html_response(response) -> bool:
        content_type = (response.headers.get("Content-Type") or "").lower()
        return not content_type or "html" in content_type or "xml" in content_type

    @staticmethod
    def _target_key(url: str, method: str, parameter: str):
        return (urllib.parse.urlsplit(url).path, method, parameter)

    @staticmethod
    def _is_login_wall(response) -> bool:
        final = (response.url or "").lower()
        body = (response.text or "").lower()
        if "/login/" in final and "loginerrors" not in body:
            return True
        return "logintoken" in body and "dashboard" not in body and "my courses" not in body

    @staticmethod
    def _info(title: str, description: str) -> Dict[str, Any]:
        return {
            "title": title,
            "description": description,
            "severity": "Info",
            "verified": True,
            "source": "active",
            "evidence_type": "info",
        }
