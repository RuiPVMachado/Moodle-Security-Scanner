#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Small, conservative parameter discovery used by injection testers.

Only same-origin forms and links are considered.  The caller decides which
parameters are safe to test; this module never sends payloads itself.
"""

from __future__ import annotations

import logging
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from bs4 import BeautifulSoup

DEFAULT_DISCOVERY_PATHS = (
    "",
    "my/",
    "my/courses.php",
    "course/view.php",
    "course/index.php",
    "user/index.php",
    "user/profile.php",
    "mod/forum/index.php",
    "mod/forum/view.php",
    "mod/forum/discuss.php",
    "mod/quiz/view.php",
    "calendar/view.php",
    "search/index.php",
    "tag/search.php",
)

SKIP_FIELDS = {
    "sesskey",
    "logintoken",
    "password",
    "submit",
    "cancel",
    "reset",
    "login",
    "action",
    "returnurl",
    "wantsurl",
    "email",
}


def _origin(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _same_origin(url: str, base_url: str) -> bool:
    return _origin(url) == _origin(base_url)


def _target_key(url: str, method: str, parameter: str) -> Tuple[str, str, str]:
    parsed = urllib.parse.urlsplit(url)
    return (parsed.path, method, parameter)


def extract_forms(
    html: str,
    base_url: str,
    target_url: str,
    *,
    include_hidden_ids: bool = False,
) -> Iterable[Dict[str, Any]]:
    soup = BeautifulSoup(html or "", "html.parser")
    for form in soup.find_all("form"):
        action = urllib.parse.urljoin(base_url, form.get("action") or base_url)
        if not _same_origin(action, target_url):
            continue
        method = str(form.get("method") or "get").lower()
        method = method if method in {"get", "post"} else "get"
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

            if field_type in {"text", "search", "url", "tel", "number", "textarea"}:
                if name.lower() not in SKIP_FIELDS:
                    parameters.append(name)
            elif include_hidden_ids and field_type == "hidden" and name.lower().endswith("id"):
                parameters.append(name)

        if not parameters:
            continue
        # Never send injection payloads to a login/session form.  Those
        # requests can create failed-login lockouts and are not a valid SQLi
        # target for an unauthenticated scanner.
        if "/login/" in urllib.parse.urlparse(action).path.lower():
            continue
        if any(name in data for name in ("password", "logintoken")):
            continue
        yield {
            "url": action,
            "method": method,
            "parameters": parameters[:10],
            "data": data,
        }


def extract_link_parameters(
    html: str,
    base_url: str,
    target_url: str,
) -> Iterable[Tuple[str, str]]:
    soup = BeautifulSoup(html or "", "html.parser")
    for link in soup.find_all("a", href=True):
        href = urllib.parse.urljoin(base_url, link["href"])
        if not _same_origin(href, target_url):
            continue
        parsed = urllib.parse.urlparse(href)
        if not parsed.query:
            continue
        for parameter, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
            if parameter.lower() in SKIP_FIELDS:
                continue
            yield href, parameter


_CRAWL_SKIP_PATH_TOKENS = (
    "logout",
    "signout",
    "login",
    "delete",
    "remove",
    "edit",
    "upload",
    "import",
    "export",
    "restore",
    "backup",
    "admin",
    "webservice",
    "token",
    "grade",
    "enrol",
    "confirm",
    "subscribe",
    "unsubscribe",
    "post",
    "reply",
    "submit",
    "save",
    "update",
)
_CRAWL_SKIP_QUERY_TOKENS = (
    "sesskey",
    "logout",
    "delete",
    "remove",
    "edit",
    "action=edit",
    "action=delete",
    "confirm",
    "cancel",
)
_STATIC_SUFFIXES = (
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
)


def _safe_crawl_url(url: str, target_url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    if _origin(url) != _origin(target_url):
        return False
    path = parsed.path.lower()
    if not path or path.endswith(_STATIC_SUFFIXES):
        return False
    if any(token in path for token in _CRAWL_SKIP_PATH_TOKENS):
        return False
    query = parsed.query.lower()
    if any(token in query for token in _CRAWL_SKIP_QUERY_TOKENS):
        return False
    return True


def _crawl_candidates(html: str, base_url: str, target_url: str) -> Iterable[str]:
    soup = BeautifulSoup(html or "", "html.parser")
    for link in soup.find_all("a", href=True):
        href = urllib.parse.urljoin(base_url, link["href"])
        if _safe_crawl_url(href, target_url):
            yield href


def discover_crawl_urls(
    session,
    target_url: str,
    *,
    seeds: Sequence[str],
    max_pages: int = 5,
    timeout: float = 30.0,
    logger: Optional[logging.Logger] = None,
) -> List[str]:
    """Conservatively walk same-origin links from authenticated pages.

    State-changing links (logout, delete, edit, enrol, backup, etc.) are
    skipped.  This is used only by active modules after ``--authorized``.
    """

    if max_pages <= 0:
        return []
    queue = list(seeds[:8])
    seen = set()
    extra: List[str] = []
    while queue and len(extra) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            response = session.get(url, timeout=timeout)
        except Exception as exc:
            if logger:
                logger.debug("Crawl request failed for %s: %s", url, exc)
            continue
        if response.status_code != 200:
            continue
        final = (response.url or "").lower()
        body = (response.text or "").lower()
        if "/login/" in final and "loginerrors" not in body:
            continue
        for candidate in _crawl_candidates(response.text or "", response.url, target_url):
            if candidate in seen:
                continue
            if candidate not in extra:
                extra.append(candidate)
            queue.append(candidate)
            if len(extra) >= max_pages:
                break
    return extra


def discover_parameter_targets(
    session,
    target_url: str,
    *,
    timeout: float = 30.0,
    paths: Sequence[str] = DEFAULT_DISCOVERY_PATHS,
    logger: Optional[logging.Logger] = None,
    include_hidden_ids: bool = False,
    skip_login_walls: bool = True,
    crawl_pages: int = 0,
) -> List[Dict[str, Any]]:
    targets: List[Dict[str, Any]] = []
    seen = set()

    seed_urls = [target_url.rstrip("/") + "/" + path.lstrip("/") for path in paths]
    urls = list(seed_urls)
    if crawl_pages > 0:
        urls.extend(
            discover_crawl_urls(
                session,
                target_url,
                seeds=seed_urls,
                max_pages=crawl_pages,
                timeout=timeout,
                logger=logger,
            )
        )

    for url in urls:
        try:
            response = session.get(url, timeout=timeout)
        except Exception as exc:
            if logger:
                logger.debug("Descoberta falhou em %s: %s", url, exc)
            continue
        if response.status_code != 200:
            continue
        final = (response.url or "").lower()
        body = (response.text or "").lower()
        if skip_login_walls and "/login/" in final and "loginerrors" not in body:
            continue

        for form in extract_forms(
            response.text or "",
            response.url,
            target_url,
            include_hidden_ids=include_hidden_ids,
        ):
            for parameter in form["parameters"]:
                key = _target_key(form["url"], form["method"], parameter)
                if key in seen:
                    continue
                seen.add(key)
                targets.append(
                    {
                        "url": form["url"],
                        "method": form["method"],
                        "parameter": parameter,
                        "data": form["data"],
                    }
                )

        for link_url, parameter in extract_link_parameters(
            response.text or "",
            response.url,
            target_url,
        ):
            key = _target_key(link_url, "get", parameter)
            if key in seen:
                continue
            seen.add(key)
            targets.append(
                {
                    "url": link_url,
                    "method": "get",
                    "parameter": parameter,
                    "data": {},
                }
            )

    return targets


def replace_query_param(url: str, parameter: str, value: str) -> str:
    """Replace (or add) one query parameter without creating duplicates."""

    parts = urllib.parse.urlsplit(url)
    query = [
        (key, item)
        for key, item in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        if key != parameter
    ]
    query.append((parameter, value))
    return urllib.parse.urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            urllib.parse.urlencode(query, doseq=True),
            parts.fragment,
        )
    )


def send_parameter(
    session,
    target: Dict[str, Any],
    value: str,
    *,
    timeout: float = 30.0,
):
    try:
        if target["method"] == "post":
            data = dict(target.get("data") or {})
            data[target["parameter"]] = value
            return session.post(target["url"], data=data, timeout=timeout)
        return session.get(
            replace_query_param(target["url"], target["parameter"], value),
            timeout=timeout,
        )
    except Exception:
        return None
