#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared HTTP layer with rate limiting, retries and bounded responses.

The scanner talks to hostile systems.  Every request must therefore have a
hard timeout, a bounded response body and a predictable retry policy.  This
module keeps those guarantees in one place instead of duplicating them in
every tester.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, TypeVar
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_USER_AGENT = (
    "MoodleSecurityScanner/2.1 (+https://github.com/RuiPVMachado/Moodle-Security-Scanner)"
)

DEFAULT_ACCEPT = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,"
    "image/avif,image/webp,*/*;q=0.8"
)

T = TypeVar("T")


class RateLimiter:
    """Simple thread-safe minimum-interval limiter shared by all sessions."""

    def __init__(self, min_interval: float = 0.0) -> None:
        self.min_interval = max(0.0, float(min_interval or 0.0))
        self._lock = threading.Lock()
        self._next_at = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            delay = self._next_at - now
            if delay > 0:
                time.sleep(delay)
            self._next_at = time.monotonic() + self.min_interval


class RequestBudget:
    """Thread-safe global request counter shared by every module.

    ``0`` means unlimited.  When the budget is exhausted, ``acquire`` raises
    :class:`RequestBudgetExceeded`, which callers treat like a network failure.
    """

    def __init__(self, max_requests: int = 0) -> None:
        self.max_requests = max(0, int(max_requests or 0))
        self._lock = threading.Lock()
        self._count = 0

    @property
    def used(self) -> int:
        with self._lock:
            return self._count

    def acquire(self) -> None:
        if self.max_requests <= 0:
            with self._lock:
                self._count += 1
            return
        with self._lock:
            if self._count >= self.max_requests:
                raise RequestBudgetExceeded(
                    f"Request budget exhausted ({self.max_requests} requests)."
                )
            self._count += 1


class RequestBudgetExceeded(requests.RequestException):
    """Raised when the global scan request budget is exhausted."""


def _host_key(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def _same_site_redirect(current_url: str, next_url: str) -> bool:
    """Allow same-host redirects and the common http -> https upgrade."""

    current = urlparse(current_url)
    nxt = urlparse(next_url)
    if _host_key(current_url) != _host_key(next_url):
        return False
    if current.scheme == nxt.scheme:
        return True
    if current.scheme == "http" and nxt.scheme == "https":
        return (current.port or 80) == 80 and (nxt.port or 443) == 443
    return False


class SecureSession(requests.Session):
    """requests.Session with safe defaults and bounded response bodies."""

    def __init__(
        self,
        *,
        verify_ssl: bool = True,
        timeout: float = 30.0,
        user_agent: Optional[str] = None,
        proxy: Optional[str] = None,
        max_response_bytes: int = 2_000_000,
        rate_limiter: Optional[RateLimiter] = None,
        retries: int = 2,
        extra_headers: Optional[Dict[str, str]] = None,
        same_origin_redirects: bool = True,
        max_redirects: int = 6,
        request_budget: Optional[RequestBudget] = None,
    ) -> None:
        super().__init__()
        self.verify_ssl = bool(verify_ssl)
        self.timeout = float(timeout)
        self.max_response_bytes = max(1024, int(max_response_bytes))
        self.rate_limiter = rate_limiter or RateLimiter(0)
        self.same_origin_redirects = bool(same_origin_redirects)
        self.max_redirects = max(0, int(max_redirects))
        self.request_budget = request_budget
        self.truncated_responses = 0

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        if proxy:
            self.proxies = {"http": proxy, "https": proxy}

        retry = Retry(
            total=max(0, int(retries)),
            connect=max(0, int(retries)),
            read=0,
            status=max(0, int(retries)),
            backoff_factor=0.3,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=10,
            pool_maxsize=20,
            pool_block=False,
        )
        self.mount("http://", adapter)
        self.mount("https://", adapter)

        self.headers.update(
            {
                "User-Agent": user_agent or DEFAULT_USER_AGENT,
                "Accept": DEFAULT_ACCEPT,
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Cache-Control": "no-cache",
            }
        )
        if extra_headers:
            self.headers.update(extra_headers)

    def _request_once(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        if self.request_budget is not None:
            self.request_budget.acquire()
        self.rate_limiter.wait()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_ssl)

        # Download at most max_response_bytes.  A malicious target can return
        # gigabytes; requests would otherwise buffer all of it in memory.
        kwargs.setdefault("stream", True)
        response = super().request(method, url, **kwargs)
        try:
            if method.upper() != "HEAD" and kwargs.get("stream", True):
                raw = response.raw.read(self.max_response_bytes + 1, decode_content=True)
                if len(raw) > self.max_response_bytes:
                    raw = raw[: self.max_response_bytes]
                    self.truncated_responses += 1
                    response.headers["X-MSS-Truncated"] = "1"
                response._content = raw
                response._content_consumed = True
                response.raw.close()
        finally:
            response.close()
        return response

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        allow_redirects = bool(kwargs.pop("allow_redirects", True))
        kwargs.setdefault("stream", True)
        current_method = method
        current_url = url
        request_kwargs = dict(kwargs)

        response: Optional[requests.Response] = None
        for _ in range(self.max_redirects + 1):
            response = self._request_once(
                current_method,
                current_url,
                allow_redirects=False,
                **request_kwargs,
            )
            if not allow_redirects or response.status_code not in (301, 302, 303, 307, 308):
                return response

            location = response.headers.get("Location")
            if not location:
                return response
            next_url = urljoin(current_url, location)
            if self.same_origin_redirects and not _same_site_redirect(current_url, next_url):
                return response
            if response.status_code in (301, 302, 303) and current_method.upper() != "HEAD":
                current_method = "GET"
                request_kwargs.pop("data", None)
                request_kwargs.pop("json", None)
                request_kwargs.pop("files", None)
                request_kwargs.pop("params", None)
            current_url = next_url
        assert response is not None
        return response

    def get_text(
        self,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        timeout: Optional[float] = None,
    ) -> Optional[str]:
        try:
            response = self.get(
                url,
                params=params,
                headers=headers,
                allow_redirects=allow_redirects,
                timeout=timeout or self.timeout,
            )
            return response.text
        except requests.RequestException:
            return None

    def get_json(
        self,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Optional[Any]:
        try:
            response = self.get(
                url,
                params=params,
                headers=headers,
                timeout=timeout or self.timeout,
            )
            return response.json()
        except (requests.RequestException, ValueError):
            return None


def build_session(
    *,
    verify_ssl: bool = True,
    timeout: float = 30.0,
    user_agent: Optional[str] = None,
    proxy: Optional[str] = None,
    cookies: Optional[Dict[str, str]] = None,
    max_response_bytes: int = 2_000_000,
    rate_limiter: Optional[RateLimiter] = None,
    retries: int = 2,
    same_origin_redirects: bool = True,
    request_budget: Optional[RequestBudget] = None,
) -> SecureSession:
    session = SecureSession(
        verify_ssl=verify_ssl,
        timeout=timeout,
        user_agent=user_agent,
        proxy=proxy,
        max_response_bytes=max_response_bytes,
        rate_limiter=rate_limiter,
        retries=retries,
        same_origin_redirects=same_origin_redirects,
        request_budget=request_budget,
    )
    if cookies:
        session.cookies.update(cookies)
    return session


def parallel_map(
    func: Callable[[T], Any],
    items: Sequence[T],
    *,
    workers: int = 8,
    logger: Optional[logging.Logger] = None,
    label: str = "task",
) -> List[Any]:
    """Run independent checks concurrently while preserving result order.

    Exceptions are isolated per item: one broken endpoint must not abort the
    whole module.  Results that raised are replaced with ``None``.
    """

    if workers <= 1 or len(items) <= 1:
        return [func(item) for item in items]

    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: List[Any] = [None] * len(items)
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(items)))) as pool:
        futures = {pool.submit(func, item): index for index, item in enumerate(items)}
        for future in as_completed(futures):
            index = futures[future]
            try:
                results[index] = future.result()
            except Exception as exc:  # pragma: no cover - defensive isolation
                if logger:
                    logger.debug("%s failed for item %r: %s", label, items[index], exc)
    return results


def jitter(seconds: float = 0.2) -> None:
    """Small random delay, used only for evasive tests when explicitly asked."""

    if seconds > 0:
        time.sleep(random.uniform(0, seconds))
