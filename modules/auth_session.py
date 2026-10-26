#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared Moodle login helper.

A scanner that accepts ``--username``/``--password`` must authenticate once and
reuse the resulting session for every module.  Historically each module built
its own unauthenticated session, so only the ``auth`` and ``session`` modules
ever saw authenticated pages.  This helper centralises the login flow and
returns the cookies needed to build authenticated sessions elsewhere.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from bs4 import BeautifulSoup

from modules.http import SecureSession, build_session


@dataclass
class MoodleAuthResult:
    success: bool
    message: str
    cookies: Dict[str, str] = field(default_factory=dict)
    login_url: str = ""
    username: Optional[str] = None
    admin_access: bool = False
    status_code: Optional[int] = None
    final_url: str = ""


def _session_cookies(session: SecureSession) -> Dict[str, str]:
    return {cookie.name: cookie.value for cookie in session.cookies}


def login_to_moodle(
    session: SecureSession,
    target_url: str,
    username: str,
    password: str,
    *,
    timeout: float = 30.0,
    logger: Optional[logging.Logger] = None,
    check_admin: bool = True,
) -> MoodleAuthResult:
    """Authenticate against Moodle and return reusable cookies.

    The caller owns ``session`` and should pass a fresh session.  No password is
    logged, and requests use the session's own timeout/retry/rate-limit policy.
    """

    log = logger or logging.getLogger("MoodleAuthSession")
    login_url = target_url.rstrip("/") + "/login/index.php"

    try:
        response = session.get(login_url, timeout=timeout)
    except Exception as exc:  # requests exceptions are handled by callers normally
        log.debug("Login page request failed: %s", exc)
        return MoodleAuthResult(False, f"Login page request failed: {exc}", login_url=login_url)

    if response is None or response.status_code >= 400:
        return MoodleAuthResult(
            False,
            "Login page is not reachable.",
            login_url=login_url,
            status_code=getattr(response, "status_code", None),
        )

    soup = BeautifulSoup(response.text or "", "html.parser")
    token_input = soup.find("input", {"name": "logintoken"})
    token = str(token_input.get("value", "") or "") if token_input else ""

    try:
        result = session.post(
            login_url,
            data={
                "username": username,
                "password": password,
                "logintoken": token,
            },
            timeout=timeout,
        )
    except Exception as exc:
        log.debug("Login POST failed: %s", exc)
        return MoodleAuthResult(False, f"Login request failed: {exc}", login_url=login_url)

    if result is None:
        return MoodleAuthResult(False, "Login request returned no response.", login_url=login_url)

    body = (result.text or "").lower()
    final_url = (result.url or "").lower()
    cookies = _session_cookies(session)

    failed = "loginerrors" in body or "invalid login" in body or "login failed" in body
    success = not failed and (
        "/my/" in final_url
        or "dashboard" in body
        or "my courses" in body
        or ("logout" in body and "login/index.php" not in final_url)
    )

    if not success:
        return MoodleAuthResult(
            False,
            "The supplied credentials were rejected.",
            cookies=cookies,
            login_url=login_url,
            username=username,
            status_code=result.status_code,
            final_url=result.url or login_url,
        )

    admin_access = False
    if check_admin:
        try:
            admin = session.get(target_url.rstrip("/") + "/admin/index.php", timeout=timeout)
            if admin is not None and admin.status_code == 200:
                admin_body = (admin.text or "").lower()
                admin_final = (admin.url or "").lower()
                admin_access = "/login/" not in admin_final and "site administration" in admin_body
        except Exception as exc:
            log.debug("Admin access check failed: %s", exc)

    return MoodleAuthResult(
        True,
        "Authenticated successfully.",
        cookies=cookies,
        login_url=login_url,
        username=username,
        admin_access=admin_access,
        status_code=result.status_code,
        final_url=result.url or login_url,
    )


def authenticated_session(
    *,
    target_url: str,
    username: str,
    password: str,
    timeout: float = 30.0,
    proxy: Optional[str] = None,
    user_agent: Optional[str] = None,
    verify_ssl: bool = True,
    max_response_bytes: int = 2_000_000,
    rate_limiter: Any = None,
    logger: Optional[logging.Logger] = None,
) -> tuple[SecureSession, MoodleAuthResult]:
    """Create a session, log in, and return both the session and result."""

    session = build_session(
        verify_ssl=verify_ssl,
        timeout=timeout,
        user_agent=user_agent,
        proxy=proxy,
        max_response_bytes=max_response_bytes,
        rate_limiter=rate_limiter,
        retries=2,
    )
    result = login_to_moodle(
        session,
        target_url,
        username,
        password,
        timeout=timeout,
        logger=logger,
    )
    return session, result
