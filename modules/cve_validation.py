#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Safe, read-only CVE validation for a small set of Moodle advisories.

A version match answers "is this release in the affected range?".  It does
not answer "does the vulnerable code path actually behave as described on
this deployment?".  This module adds a conservative validation layer:

* only read-only requests are sent;
* no SQL/command payloads, file uploads, question creation or restore;
* a positive result means the vulnerable *behaviour* was observed, not that
  full exploitation succeeded;
* everything without a safe validator is explicitly marked ``manual`` and the
  reason is included in the report.

The first validator targets CVE-2025-26533 (SQL injection in the course search
module list filter).  It sends a non-existent module name; vulnerable Moodle
tries to use it as a table name and returns a database read exception, while
patched Moodle returns an empty result.
"""

from __future__ import annotations

import logging
import random
import re
import string
from typing import Any, Dict, Optional

_SAFE_VALIDATORS = {"CVE-2025-26533"}

_DB_ERROR_PATTERNS = (
    "dmlreadexception",
    "dml_read_exception",
    "doesn't exist",
    "does not exist",
    "unknown table",
    "sql syntax",
    "debug info",
    "error code:",
    "invalid table name",
)


def _token(length: int = 8) -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(length))


def default_validation(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Return an honest validation state for a version-based finding."""

    cve = str(finding.get("cve") or "").upper()
    summary = str(finding.get("title") or finding.get("description") or "").lower()

    if cve in _SAFE_VALIDATORS:
        return {
            "status": "available",
            "method": "safe-active",
            "reason": "Existe um check seguro read-only; usar --validate-cves --authorized.",
            "requirements": ["authorized"],
            "reference": "https://moodle.org/mod/forum/discuss.php?d=466150",
        }

    if any(word in summary for word in ("remote code execution", "code injection", "rce")):
        reason = (
            "Requer conta autenticada com capacidade de criar/editar conteúdo e "
            "uma ação que altera dados (pergunta calculada, upload, restore). "
            "Um scanner não deve executar isto automaticamente."
        )
    elif "sql injection" in summary:
        reason = (
            "O módulo sqli pode detetar SQLi genérico, mas a atribuição a este "
            "CVE exige o endpoint/parâmetro exato da MSA/commit."
        )
    elif "cross-site scripting" in summary or "xss" in summary:
        reason = (
            "XSS armazenado/contextual exige browser e conta; o módulo xss só "
            "confirma reflexão HTML inerte."
        )
    elif any(
        word in summary
        for word in ("local file inclusion", "arbitrary file read", "path traversal")
    ):
        reason = (
            "Requer upload/restore ou um endpoint específico; o módulo lfi só "
            "testa parâmetros genéricos."
        )
    elif any(
        word in summary
        for word in ("authentication bypass", "idor", "csrf", "access control", "authorization")
    ):
        reason = "Requer contas e lógica de negócio; validação manual."
    elif "denial of service" in summary or "dos" in summary:
        reason = "Testar DoS é intrusivo; não é automatizado."
    else:
        reason = "Sem validador seguro; confirmar manualmente com a MSA/commit."

    return {
        "status": "manual",
        "method": "manual",
        "reason": reason,
        "requirements": ["manual review", "Moodle MSA/commit"],
        "reference": "",
    }


def validate_finding(
    finding: Dict[str, Any],
    session,
    target_url: str,
    *,
    timeout: float = 30.0,
    logger: Optional[logging.Logger] = None,
) -> Dict[str, Any]:
    """Run the safe validator for this CVE, if one exists."""

    cve = str(finding.get("cve") or "").upper()
    if cve not in _SAFE_VALIDATORS:
        return default_validation(finding)
    if session is None:
        return {
            "status": "not-observed",
            "method": None,
            "reason": "Sem sessão HTTP para o alvo.",
            "requirements": ["authorized", "target session"],
            "reference": "",
        }

    try:
        if cve == "CVE-2025-26533":
            return _validate_cve_2025_26533(session, target_url, timeout, logger)
    except Exception as exc:
        if logger:
            logger.debug("Validação de %s falhou: %s", cve, exc)
        return {
            "status": "not-observed",
            "method": "safe-active",
            "reason": f"O check seguro falhou: {exc}",
            "requirements": ["authorized"],
            "reference": "",
        }

    return default_validation(finding)


def _validate_cve_2025_26533(
    session,
    target_url: str,
    timeout: float,
    logger: Optional[logging.Logger],
) -> Dict[str, Any]:
    """Check the vulnerable modulelist table lookup without injecting SQL."""

    probe = "mssprobe" + _token()
    url = target_url.rstrip("/") + "/course/search.php"
    response = session.get(
        url,
        params={"modulelist": probe},
        timeout=timeout,
    )
    if response is None:
        return {
            "status": "not-observed",
            "method": "safe-active",
            "reason": "Sem resposta do course search.",
            "requirements": ["authorized"],
            "reference": "",
        }

    body = response.text or ""
    lowered = body.lower()
    final_url = (getattr(response, "url", "") or "").lower()

    if "/login/" in final_url or (
        "logintoken" in lowered and not any(pattern in lowered for pattern in _DB_ERROR_PATTERNS)
    ):
        return {
            "status": "not-observed",
            "method": "safe-active",
            "reason": (
                "O course search exige autenticação; repetir com credenciais "
                "autorizadas para confirmar."
            ),
            "requirements": ["authenticated session"],
            "reference": "https://moodle.org/mod/forum/discuss.php?d=466150",
        }

    has_db_error = any(pattern in lowered for pattern in _DB_ERROR_PATTERNS)
    probe_in_error = probe in body
    if has_db_error and (probe_in_error or response.status_code >= 500):
        snippet = _snippet(body, probe) if probe_in_error else body[:500]
        return {
            "status": "confirmed",
            "method": "safe-active",
            "reason": (
                "A versão afetada tentou usar o nome de módulo inexistente como "
                "tabela e devolveu um erro de leitura de BD. O comportamento "
                "vulnerável foi observado sem injetar SQL."
            ),
            "evidence": snippet,
            "url": response.url,
            "requirements": ["authorized"],
            "reference": "https://moodle.org/mod/forum/discuss.php?d=466150",
        }

    return {
        "status": "not-confirmed",
        "method": "safe-active",
        "reason": (
            "O pedido completou sem o erro de tabela. Pode estar corrigido, "
            "ter backport, ou o fluxo estar bloqueado; não prova que está seguro."
        ),
        "url": getattr(response, "url", url),
        "requirements": ["authorized"],
        "reference": "https://moodle.org/mod/forum/discuss.php?d=466150",
    }


def _snippet(text: str, probe: str, radius: int = 240) -> str:
    index = (text or "").lower().find(probe.lower())
    if index < 0:
        return (text or "")[:radius]
    start = max(0, index - radius)
    end = min(len(text), index + len(probe) + radius)
    return re.sub(r"\s+", " ", text[start:end]).strip()
