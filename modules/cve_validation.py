#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Safe, read-only CVE validation with an explicit per-CVE registry.

A version match answers "is this release in the affected range?".  It does not
answer "does the vulnerable code path actually behave as described on this
deployment?".  This module adds a conservative validation layer:

* only read-only or bounded requests are sent;
* no SQL/command payloads, file uploads, question creation or restore;
* a positive result means the vulnerable *behaviour* was observed, not that
  full exploitation succeeded;
* everything without a safe validator is explicitly marked ``manual`` or
  ``out-of-scope`` and the reason is included in the report.
"""

from __future__ import annotations

import logging
import random
import re
import string
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional
from urllib.parse import urljoin, urlparse

_SAFE_VALIDATORS = {
    "CVE-2025-26533",
    "CVE-2025-62396",
    "CVE-2025-62399",
    "CVE-2025-67852",
    "CVE-2025-67853",
    "CVE-2025-67855",
}

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

_ERROR_DISCLOSURE_PATTERNS = (
    "index of /",
    "directory listing",
    "stack trace",
    "fatal error",
    "debug info",
    "moodle exception",
    "exception -",
    "php warning",
)

_RATE_LIMIT_PATTERNS = (
    "too many",
    "rate limit",
    "ratelimit",
    "try again later",
    "account locked",
    "captcha",
    "recaptcha",
)


@dataclass(frozen=True)
class ValidatorSpec:
    cve: str
    status: str
    method: str
    reason: str
    requirements: tuple[str, ...]
    reference: str = ""


def _spec(
    cve: str,
    status: str,
    method: str,
    reason: str,
    requirements: tuple[str, ...],
    reference: str = "",
) -> ValidatorSpec:
    return ValidatorSpec(cve, status, method, reason, requirements, reference)


_SPECS: Dict[str, ValidatorSpec] = {
    "CVE-2025-26533": _spec(
        "CVE-2025-26533",
        "available",
        "safe-active",
        "Verifica o erro de tabela no course search sem injetar SQL.",
        ("authorized",),
        "https://moodle.org/mod/forum/discuss.php?d=466150",
    ),
    "CVE-2025-67852": _spec(
        "CVE-2025-67852",
        "available",
        "safe-active",
        "Verifica se o fluxo OAuth aceita um wantsurl externo sem redirecionar.",
        ("authorized",),
        "https://moodle.org/mod/forum/discuss.php?d=471302",
    ),
    "CVE-2025-62396": _spec(
        "CVE-2025-62396",
        "available",
        "safe-active",
        "Procura directory listing/erro interno no router sem headers de diagnóstico.",
        ("authorized",),
        "https://moodle.org/mod/forum/discuss.php?d=470385",
    ),
    "CVE-2025-67855": _spec(
        "CVE-2025-67855",
        "available",
        "safe-active",
        "Envia um canário de URL para o returnurl do policy tool e procura reflexão insegura.",
        ("authorized",),
        "https://moodle.org/mod/forum/discuss.php?d=471305",
    ),
    "CVE-2025-62399": _spec(
        "CVE-2025-62399",
        "available",
        "safe-active",
        "Faz 6 tentativas com um utilizador inexistente em login/token.php "
        "e observa se existe throttling.",
        ("authorized",),
        "https://moodle.org/mod/forum/discuss.php?d=470388",
    ),
    "CVE-2025-67853": _spec(
        "CVE-2025-67853",
        "available",
        "safe-active",
        "Faz 6 pedidos de reposição para um email .invalid e observa se existe throttling.",
        ("authorized",),
        "https://moodle.org/mod/forum/discuss.php?d=471303",
    ),
    "CVE-2025-62398": _spec(
        "CVE-2025-62398",
        "manual",
        "manual",
        "MFA bypass exige contas, configuração de MFA e um fluxo autenticado.",
        ("test account", "manual review"),
        "https://moodle.org/mod/forum/discuss.php?d=470387",
    ),
    "CVE-2025-62400": _spec(
        "CVE-2025-62400",
        "manual",
        "manual",
        "Exige um utilizador com permissão para criar eventos mas não para ver grupos ocultos.",
        ("test account", "manual review"),
        "https://moodle.org/mod/forum/discuss.php?d=470389",
    ),
    "CVE-2025-62394": _spec(
        "CVE-2025-62394",
        "manual",
        "manual",
        "Exige inscrições, utilizadores suspensos e notificações de quiz.",
        ("test account", "manual review"),
        "https://moodle.org/mod/forum/discuss.php?d=470383",
    ),
    "CVE-2025-67857": _spec(
        "CVE-2025-67857",
        "manual",
        "manual",
        "Exige uma submissão anónima de assignment e inspeção dos URLs gerados.",
        ("test account", "manual review"),
        "https://moodle.org/mod/forum/discuss.php?d=471307",
    ),
    "CVE-2025-67848": _spec(
        "CVE-2025-67848",
        "manual",
        "manual",
        "Exige um utilizador suspenso e o fluxo LTI Provider; é um bypass de autenticação.",
        ("test account", "manual review"),
        "https://moodle.org/mod/forum/discuss.php?d=471298",
    ),
    "CVE-2025-67856": _spec(
        "CVE-2025-67856",
        "manual",
        "manual",
        "Exige papéis, badges e verificação de autorização; não é seguro automatizar.",
        ("test account", "manual review"),
        "https://moodle.org/mod/forum/discuss.php?d=471306",
    ),
    "CVE-2025-62401": _spec(
        "CVE-2025-62401",
        "manual",
        "manual",
        "Exige uma atividade cronometrada e alteração de estado; validação manual.",
        ("test account", "manual review"),
        "https://moodle.org/mod/forum/discuss.php?d=470390",
    ),
    "CVE-2025-67849": _spec(
        "CVE-2025-67849",
        "manual",
        "manual",
        "XSS armazenado em respostas de IA; exige browser, conta e interação.",
        ("test account", "browser", "manual review"),
        "https://moodle.org/mod/forum/discuss.php?d=471299",
    ),
    "CVE-2025-67850": _spec(
        "CVE-2025-67850",
        "manual",
        "manual",
        "XSS no editor de fórmulas; exige conteúdo, browser e confirmação de execução.",
        ("test account", "browser", "manual review"),
        "https://moodle.org/mod/forum/discuss.php?d=471300",
    ),
    "CVE-2025-67851": _spec(
        "CVE-2025-67851",
        "manual",
        "manual",
        "Formula injection em exportação; exige criar dados e abrir o ficheiro "
        "numa folha de cálculo.",
        ("test account", "spreadsheet", "manual review"),
        "https://moodle.org/mod/forum/discuss.php?d=471301",
    ),
    "CVE-2025-67847": _spec(
        "CVE-2025-67847",
        "out-of-scope",
        "manual",
        "Execução de código via restore; não deve ser automatizada por um scanner.",
        ("isolated lab", "explicit approval"),
        "https://moodle.org/mod/forum/discuss.php?d=471297",
    ),
    "CVE-2026-26045": _spec(
        "CVE-2026-26045",
        "out-of-scope",
        "manual",
        "RCE via ficheiro de backup; exploração destrutiva, fora do âmbito do scanner.",
        ("isolated lab", "explicit approval"),
        "https://moodle.org/mod/forum/discuss.php?d=473314",
    ),
    "CVE-2026-26047": _spec(
        "CVE-2026-26047",
        "out-of-scope",
        "manual",
        "DoS no editor TeX; testar consume recursos e não é automatizado.",
        ("explicit approval",),
        "https://moodle.org/mod/forum/discuss.php?d=473316",
    ),
}


def _token(length: int = 8) -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(length))


def _base_result(spec: Optional[ValidatorSpec]) -> Dict[str, Any]:
    if spec is not None:
        return {
            "status": spec.status,
            "method": spec.method,
            "reason": spec.reason,
            "requirements": list(spec.requirements),
            "reference": spec.reference,
        }
    return {
        "status": "manual",
        "method": "manual",
        "reason": "Sem validador seguro; confirmar manualmente com a MSA/commit.",
        "requirements": ["manual review", "Moodle MSA/commit"],
        "reference": "",
    }


def default_validation(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Return an honest validation state for a version-based finding."""

    cve = str(finding.get("cve") or "").upper()
    if cve in _SPECS:
        return _base_result(_SPECS[cve])

    summary = str(finding.get("title") or finding.get("description") or "").lower()
    if str(finding.get("source") or "").upper() == "MSA":
        metadata = finding.get("metadata") or {}
        return {
            "status": "manual",
            "method": "manual",
            "reason": (
                "MSA com CVE Pending (ou sem CVE). Confirmar o advisory/commit; "
                "não existe um validador seguro específico."
            ),
            "requirements": ["manual review", "Moodle MSA/commit"],
            "reference": (finding.get("references") or [""])[0],
            "msa_id": metadata.get("msa_id"),
        }

    if re.search(r"\b(?:rce|remote code execution|code injection)\b", summary):
        reason = (
            "Requer conta autenticada com capacidade de criar/editar conteúdo e "
            "uma ação que altera dados (pergunta calculada, upload, restore). "
            "Um scanner não deve executar isto automaticamente."
        )
        status = "manual"
    elif "sql injection" in summary:
        reason = (
            "O módulo sqli pode detetar SQLi genérico, mas a atribuição a este "
            "CVE exige o endpoint/parâmetro exato da MSA/commit."
        )
        status = "manual"
    elif "cross-site scripting" in summary or re.search(r"\bxss\b", summary):
        reason = (
            "XSS armazenado/contextual exige browser e conta; o módulo xss só "
            "confirma reflexão HTML inerte."
        )
        status = "manual"
    elif any(
        word in summary
        for word in ("local file inclusion", "arbitrary file read", "path traversal")
    ):
        reason = (
            "Requer upload/restore ou um endpoint específico; o módulo lfi só "
            "testa parâmetros genéricos."
        )
        status = "manual"
    elif any(
        word in summary
        for word in ("authentication bypass", "idor", "csrf", "access control", "authorization")
    ):
        reason = "Requer contas e lógica de negócio; validação manual."
        status = "manual"
    elif re.search(r"\b(?:denial of service|dos)\b", summary):
        reason = "Testar DoS é intrusivo; não é automatizado."
        status = "out-of-scope"
    else:
        reason = "Sem validador seguro; confirmar manualmente com a MSA/commit."
        status = "manual"

    return {
        "status": status,
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
    spec = _SPECS.get(cve)
    if cve not in _SAFE_VALIDATORS or spec is None or spec.status != "available":
        return default_validation(finding)
    if session is None:
        return {
            "status": "not-observed",
            "method": spec.method,
            "reason": "Sem sessão HTTP para o alvo.",
            "requirements": list(spec.requirements) + ["target session"],
            "reference": spec.reference,
        }

    validators: Dict[str, Callable[..., Dict[str, Any]]] = {
        "CVE-2025-26533": _validate_cve_2025_26533,
        "CVE-2025-67852": _validate_cve_2025_67852,
        "CVE-2025-62396": _validate_cve_2025_62396,
        "CVE-2025-67855": _validate_cve_2025_67855,
        "CVE-2025-62399": _validate_cve_2025_62399,
        "CVE-2025-67853": _validate_cve_2025_67853,
    }
    validator = validators.get(cve)
    if validator is None:
        return default_validation(finding)

    try:
        return validator(session, target_url, timeout, logger)
    except Exception as exc:
        if logger:
            logger.debug("Validação de %s falhou: %s", cve, exc)
        return {
            "status": "not-observed",
            "method": spec.method,
            "reason": f"O check seguro falhou: {exc}",
            "requirements": list(spec.requirements),
            "reference": spec.reference,
        }


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
        return _not_observed("Sem resposta do course search.", "CVE-2025-26533")

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


def _validate_cve_2025_67852(
    session,
    target_url: str,
    timeout: float,
    logger: Optional[logging.Logger],
) -> Dict[str, Any]:
    """Check whether the OAuth login flow reflects an external wantsurl."""

    external = "https://mss-open-redirect.example/"
    url = target_url.rstrip("/") + "/auth/oauth2/login.php"
    response = session.get(
        url,
        params={"wantsurl": external, "id": 1},
        allow_redirects=False,
        timeout=timeout,
    )
    if response is None:
        return _not_observed("Sem resposta do endpoint OAuth.", "CVE-2025-67852")

    location = response.headers.get("Location") or ""
    target = urljoin(getattr(response, "url", url), location)
    if response.status_code in (301, 302, 303, 307, 308):
        if urlparse(target).hostname == "mss-open-redirect.example":
            return {
                "status": "confirmed",
                "method": "safe-active",
                "reason": (
                    "O endpoint OAuth aceitou um wantsurl externo e respondeu com "
                    "um redirecionamento para esse host."
                ),
                "evidence": f"HTTP {response.status_code}\nLocation: {location}",
                "url": getattr(response, "url", url),
                "requirements": ["authorized"],
                "reference": "https://moodle.org/mod/forum/discuss.php?d=471302",
            }
        return _not_confirmed(
            "O endpoint respondeu com redirect, mas não para o host externo de teste.",
            "CVE-2025-67852",
            getattr(response, "url", url),
        )

    return _not_confirmed(
        "O endpoint não devolveu um redirecionamento externo. Pode faltar um "
        "issuer OAuth configurado ou o fluxo estar corrigido.",
        "CVE-2025-67852",
        getattr(response, "url", url),
    )


def _validate_cve_2025_62396(
    session,
    target_url: str,
    timeout: float,
    logger: Optional[logging.Logger],
) -> Dict[str, Any]:
    """Look for router error details/directory listing without changing state."""

    headers = {"Accept": "text/html,application/xhtml+xml"}
    probes = ("r.php", "r.php/")
    for probe in probes:
        url = target_url.rstrip("/") + "/" + probe
        response = session.get(url, headers=headers, allow_redirects=False, timeout=timeout)
        if response is None:
            continue
        body = (response.text or "").lower()
        if any(pattern in body for pattern in _ERROR_DISCLOSURE_PATTERNS):
            return {
                "status": "confirmed",
                "method": "safe-active",
                "reason": (
                    "O router devolveu detalhes internos/directory listing numa "
                    "resposta de erro, sem headers de diagnóstico configurados."
                ),
                "evidence": _snippet(response.text or "", "error", 240),
                "url": getattr(response, "url", url),
                "requirements": ["authorized"],
                "reference": "https://moodle.org/mod/forum/discuss.php?d=470385",
            }
        if response.status_code >= 500:
            return _not_observed(
                "O router devolveu um erro 5xx sem detalhes; não é possível confirmar.",
                "CVE-2025-62396",
            )
    return _not_confirmed(
        "O router não expôs directory listing nem detalhes internos nas probes seguras.",
        "CVE-2025-62396",
        target_url.rstrip("/") + "/r.php",
    )


def _validate_cve_2025_67855(
    session,
    target_url: str,
    timeout: float,
    logger: Optional[logging.Logger],
) -> Dict[str, Any]:
    """Send a javascript-like canary to the policy tool return URL."""

    token = _token()
    payload = f"javascript:msscanary{token}//"
    probes = (
        ("admin/tool/policy/viewall.php", {"returnurl": payload}),
        ("admin/tool/policy/view.php", {"policyid": 1, "returnurl": payload}),
    )
    for path, params in probes:
        url = target_url.rstrip("/") + "/" + path
        response = session.get(url, params=params, allow_redirects=False, timeout=timeout)
        if response is None or response.status_code != 200:
            continue
        body = response.text or ""
        if payload in body or (
            f"msscanary{token}" in body and "javascript:" in body.lower()
        ):
            return {
                "status": "confirmed",
                "method": "safe-active",
                "reason": (
                    "O returnurl do policy tool refletiu um URL javascript: sem "
                    "sanitização. Confirmação de execução JavaScript exige browser."
                ),
                "evidence": _snippet(body, f"msscanary{token}", 240),
                "url": getattr(response, "url", url),
                "requirements": ["authorized"],
                "reference": "https://moodle.org/mod/forum/discuss.php?d=471305",
            }
    return _not_confirmed(
        "O canário não foi refletido pelo policy tool; pode estar corrigido ou "
        "o endpoint/fluxo exato não estar disponível.",
        "CVE-2025-67855",
        target_url.rstrip("/") + "/admin/tool/policy/viewall.php",
    )


def _validate_cve_2025_62399(
    session,
    target_url: str,
    timeout: float,
    logger: Optional[logging.Logger],
) -> Dict[str, Any]:
    return _validate_rate_limit(
        session,
        target_url,
        timeout,
        logger,
        cve="CVE-2025-62399",
        endpoint="login/token.php",
        mode="token",
        reference="https://moodle.org/mod/forum/discuss.php?d=470388",
    )


def _validate_cve_2025_67853(
    session,
    target_url: str,
    timeout: float,
    logger: Optional[logging.Logger],
) -> Dict[str, Any]:
    return _validate_rate_limit(
        session,
        target_url,
        timeout,
        logger,
        cve="CVE-2025-67853",
        endpoint="login/forgot_password.php",
        mode="forgot",
        reference="https://moodle.org/mod/forum/discuss.php?d=471303",
    )


def _validate_rate_limit(
    session,
    target_url: str,
    timeout: float,
    logger: Optional[logging.Logger],
    *,
    cve: str,
    endpoint: str,
    mode: str,
    reference: str,
) -> Dict[str, Any]:
    """Bounded probe using a non-existent identity; never targets real accounts."""

    token = _token(10)
    username = f"mss_nonexistent_{token}"
    attempts = 6
    statuses = []
    bodies = []
    for _ in range(attempts):
        url = target_url.rstrip("/") + "/" + endpoint
        if mode == "token":
            response = session.get(
                url,
                params={
                    "username": username,
                    "password": f"mss_invalid_{token}",
                    "service": "moodle_mobile_app",
                },
                allow_redirects=False,
                timeout=timeout,
            )
        else:
            response = session.post(
                url,
                data={"username": username, "email": f"{username}@example.invalid"},
                allow_redirects=False,
                timeout=timeout,
            )
        if response is None:
            return _not_observed("Sem resposta do endpoint de autenticação.", cve)
        body = (response.text or "").lower()
        bodies.append(body[:400])
        statuses.append(response.status_code)
        if response.status_code == 429 or any(
            pattern in body for pattern in _RATE_LIMIT_PATTERNS
        ):
            return {
                "status": "not-confirmed",
                "method": "safe-active",
                "reason": (
                    "O endpoint apresentou um sinal de rate limiting/captcha "
                    f"durante {len(statuses)} tentativas com uma identidade inexistente."
                ),
                "evidence": f"HTTP: {statuses[-1]}\n{_snippet(response.text or '', 'rate', 200)}",
                "url": url,
                "requirements": ["authorized"],
                "reference": reference,
            }
        if response.status_code in (401, 403, 404):
            return _not_observed(
                f"O endpoint devolveu HTTP {response.status_code} durante a probe.",
                cve,
            )
        if response.status_code >= 500:
            return _not_observed(
                f"O endpoint devolveu HTTP {response.status_code} durante a probe.",
                cve,
            )
        if any(
            marker in body
            for marker in (
                "invalid sesskey",
                "session expired",
                "required parameter",
                "missingparam",
                "invalid parameter",
            )
        ):
            return _not_observed(
                "O endpoint rejeitou a probe antes de testar autenticação/email "
                "(sesskey ou parâmetro em falta).",
                cve,
            )

    return {
        "status": "confirmed",
        "method": "safe-active",
        "reason": (
            f"Foram aceites {attempts} tentativas inválidas com um utilizador "
            "inexistente sem sinal de rate limiting. Isto confirma a ausência de "
            "throttling observável, não uma exploração de contas reais."
        ),
        "evidence": f"HTTP: {statuses}\nÚltima resposta: {bodies[-1][:240]}",
        "url": target_url.rstrip("/") + "/" + endpoint,
        "requirements": ["authorized"],
        "reference": reference,
    }


def _not_observed(reason: str, cve: str) -> Dict[str, Any]:
    spec = _SPECS.get(cve)
    return {
        "status": "not-observed",
        "method": spec.method if spec else "safe-active",
        "reason": reason,
        "requirements": list(spec.requirements) if spec else ["authorized"],
        "reference": spec.reference if spec else "",
    }


def _not_confirmed(reason: str, cve: str, url: str) -> Dict[str, Any]:
    spec = _SPECS.get(cve)
    return {
        "status": "not-confirmed",
        "method": spec.method if spec else "safe-active",
        "reason": reason,
        "url": url,
        "requirements": list(spec.requirements) if spec else ["authorized"],
        "reference": spec.reference if spec else "",
    }


def _snippet(text: str, needle: str, radius: int = 240) -> str:
    index = (text or "").lower().find(needle.lower())
    if index < 0:
        return (text or "")[:radius]
    start = max(0, index - radius)
    end = min(len(text), index + len(needle) + radius)
    return re.sub(r"\s+", " ", text[start:end]).strip()
