#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""RCE coverage without destructive or fabricated checks.

The previous implementation reported Critical RCE when a login/404 page
contained generic words such as "book" or "question".  It also attempted
authentication bypasses and question-creation exploits.  Those actions are
not acceptable for a scanner and produced false positives.

Known RCEs are handled by the version-aware CVE module (OSV), while
exposed diagnostics/backups are handled by the passive module.  This module
exists as an explicit, honest coverage marker.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional


class MoodleRCETester:
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
        **_: Any,
    ) -> None:
        self.target_url = target_url
        self.logger = logger or logging.getLogger("MoodleRCETester")
        self.version_info: Dict[str, Any] = {}
        self.deep = deep

    def set_version_info(self, version_info: Dict[str, Any]) -> None:
        self.version_info = version_info or {}

    def run_tests(self) -> Dict[str, List[Dict[str, Any]]]:
        version = self.version_info.get("version") or "desconhecida"
        return {
            "vulnerabilities": [],
            "info": [
                {
                    "title": "Testes RCE ativos desativados por segurança",
                    "description": (
                        f"Versão detetada: {version}. Os CVEs de RCE conhecidos são "
                        "verificados por versão no módulo cve; ficheiros de diagnóstico, "
                        "backups de config.php e source disclosure são verificados no "
                        "módulo passive. Não são enviados payloads que alterem o Moodle "
                        "nem tentativas de bypass de autenticação."
                    ),
                    "severity": "Info",
                    "verified": True,
                    "source": "rce",
                    "evidence_type": "info",
                }
            ],
        }
