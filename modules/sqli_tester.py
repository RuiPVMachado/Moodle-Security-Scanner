#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""SQL-injection checks based on differential database errors.

The old module treated any changed HTML or any ``SLEEP(5)`` timeout as a
critical SQL injection.  Both were unreliable.  This version reports only
when two different payloads produce database error strings that are absent
from two benign control requests.  Time-based checks are opt-in (``--deep``)
and require a reproducible delay.
"""

from __future__ import annotations

import logging
import re
import statistics
import time
from typing import Any, Dict, List, Optional, Set

from modules.discovery import (
    discover_parameter_targets,
    replace_query_param,
    send_parameter,
)

_ERROR_PATTERNS = (
    r"You have an error in your SQL syntax",
    r"Warning\s*:\s*mysqli",
    r"Warning\s*:\s*mysql",
    r"MySQL result index",
    r"supplied argument is not a valid MySQL",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"SQLSTATE\[[0-9A-Z]+\]",
    r"PostgreSQL query failed",
    r"pg_query\(\)",
    r"SQLite3::",
    r"sqlite3\.OperationalError",
    r"ORA-[0-9]{4,5}",
    r"Microsoft OLE DB Provider for SQL Server",
    r"ODBC SQL Server Driver",
    r"DBD::mysql",
    r"syntax error at or near",
)

_ERROR_RE = re.compile("|".join(f"(?:{pattern})" for pattern in _ERROR_PATTERNS), re.IGNORECASE)

_PAYLOADS = (
    "'",
    '"',
    "1'",
    "1' AND 1=1-- ",
    "1' AND 1=2-- ",
    "1 OR 1=1",
    "' OR '1'='1",
    "1)",
    "1' ORDER BY 1-- ",
)

_TIME_PAYLOADS = (
    "1' AND SLEEP(2)-- ",
    "1 AND SLEEP(2)-- ",
    "1;SELECT pg_sleep(2)-- ",
    "1' WAITFOR DELAY '0:0:2'-- ",
)


class MoodleSQLITester:
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
        deep: bool = False,
        max_tests: int = 20,
        **_: Any,
    ) -> None:
        self.target_url = target_url.rstrip("/") + "/"
        self.timeout = timeout
        self.deep = deep
        self.max_tests = max(1, max_tests if deep else min(max_tests, 30))
        self.version_info: Dict[str, Any] = {}
        self.logger = logger or logging.getLogger("MoodleSQLITester")
        if session is None:
            from modules.http import build_session

            session = build_session(
                verify_ssl=verify_ssl,
                timeout=timeout,
                user_agent=user_agent,
                proxy=proxy,
                cookies=cookies,
            )
        self.session = session

    def set_version_info(self, version_info: Dict[str, Any]) -> None:
        self.version_info = version_info or {}

    def run_tests(self) -> Dict[str, List[Dict[str, Any]]]:
        results: Dict[str, List[Dict[str, Any]]] = {"vulnerabilities": [], "info": []}
        targets = discover_parameter_targets(
            self.session,
            self.target_url,
            timeout=self.timeout,
            logger=self.logger,
            include_hidden_ids=True,
        )
        if not targets:
            results["info"].append(
                self._info(
                    "SQLi: sem parâmetros descobertos",
                    "Nenhum formulário ou link testável foi encontrado.",
                )
            )
            return results

        tested = 0
        reported = set()
        for target in targets[: self.max_tests]:
            tested += 1
            finding = self._test_error_based(target)
            if finding:
                key = (target["url"], target["parameter"])
                if key not in reported:
                    results["vulnerabilities"].append(finding)
                    reported.add(key)

        if self.deep:
            for target in targets[: min(6, self.max_tests)]:
                finding = self._test_time_based(target)
                if finding:
                    key = (target["url"], target["parameter"])
                    if key not in reported:
                        results["vulnerabilities"].append(finding)
                        reported.add(key)

        results["info"].append(
            self._info(
                "SQLi: resumo",
                f"Testados {tested} parâmetros com controlos e payloads diferenciais. "
                f"Modo deep={'sim' if self.deep else 'não'}.",
            )
        )
        return results

    # ------------------------------------------------------------------ tests
    def _test_error_based(self, target: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        baseline = send_parameter(self.session, target, "1", timeout=self.timeout)
        control = send_parameter(self.session, target, "2", timeout=self.timeout)
        if baseline is None or control is None:
            return None
        baseline_errors = self._db_errors(baseline.text or "")
        control_errors = self._db_errors(control.text or "")

        hits: List[tuple] = []
        for payload in _PAYLOADS:
            response = send_parameter(self.session, target, payload, timeout=self.timeout)
            if response is None:
                continue
            errors = self._db_errors(response.text or "") - baseline_errors - control_errors
            if errors:
                hits.append((payload, sorted(errors)[0], response))
                if len(hits) >= 2:
                    break

        if len(hits) < 2:
            return None

        payload, signature, response = hits[0]
        finding_url = (
            replace_query_param(target["url"], target["parameter"], payload)
            if target["method"] == "get"
            else target["url"]
        )
        evidence = (
            f"Parâmetro '{target['parameter']}' em {finding_url} "
            f"({target['method'].upper()}).\n"
            f"Payloads que produziram erros de BD: {', '.join(hit[0] for hit in hits)}.\n"
            f"Assinatura: {signature}\n"
            f"Excerto: {self._snippet(response.text or '', signature)}"
        )
        return {
            "title": "SQL injection provável (error-based)",
            "description": (
                "Dois payloads diferentes produziram mensagens de erro de base de dados "
                "que não aparecem nas respostas de controlo. Isto indica que a entrada "
                "está a chegar à camada SQL sem parametrização."
            ),
            "severity": "High",
            "confidence": "high",
            "evidence": evidence,
            "payload": payload,
            "url": finding_url,
            "remediation": (
                "Usar queries parametrizadas/ORM, validar tipos e remover mensagens de "
                "erro de BD das respostas de produção."
            ),
            "cwe": "CWE-89",
            "verified": True,
            "source": "active",
            "evidence_type": "active",
            "metadata": {"parameter": target["parameter"], "method": target["method"].upper()},
        }

    def _test_time_based(self, target: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        baselines = []
        for value in ("1", "2"):
            started = time.monotonic()
            response = send_parameter(self.session, target, value, timeout=self.timeout)
            if response is None:
                return None
            baselines.append(time.monotonic() - started)
        baseline = statistics.median(baselines)

        for payload in _TIME_PAYLOADS:
            durations: List[float] = []
            for _ in range(2):
                started = time.monotonic()
                response = send_parameter(self.session, target, payload, timeout=self.timeout)
                if response is None:
                    durations = []
                    break
                durations.append(time.monotonic() - started)
            if len(durations) == 2 and all(duration > baseline + 1.5 for duration in durations):
                finding_url = (
                    replace_query_param(target["url"], target["parameter"], payload)
                    if target["method"] == "get"
                    else target["url"]
                )
                return {
                    "title": "SQL injection provável (time-based)",
                    "description": (
                        "O mesmo payload produziu um atraso reprodutível em duas "
                        "medições, acima do baseline e dos controlos."
                    ),
                    "severity": "High",
                    "confidence": "high",
                    "evidence": (
                        f"Parâmetro '{target['parameter']}' em {finding_url}.\n"
                        f"Baseline mediano: {baseline:.2f}s; "
                        f"payload: {durations[0]:.2f}s / {durations[1]:.2f}s.\n"
                        f"Payload: {payload}"
                    ),
                    "payload": payload,
                    "url": finding_url,
                    "remediation": "Usar queries parametrizadas/ORM e validar tipos.",
                    "cwe": "CWE-89",
                    "verified": True,
                    "source": "active",
                    "evidence_type": "active",
                    "metadata": {
                        "parameter": target["parameter"],
                        "method": target["method"].upper(),
                    },
                }
        return None

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def _db_errors(text: str) -> Set[str]:
        return {match.group(0).lower() for match in _ERROR_RE.finditer(text or "")}

    @staticmethod
    def _snippet(text: str, signature: str, radius: int = 220) -> str:
        index = (text or "").lower().find(signature.lower())
        if index < 0:
            return (text or "")[:radius]
        start = max(0, index - radius)
        end = min(len(text), index + len(signature) + radius)
        return re.sub(r"\s+", " ", text[start:end]).strip()

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
