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

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_USER_AGENT = (
    "MoodleSecurityScanner/2.0 (+https://github.com/RuiPVMachado/Moodle-Security-Scanner)"
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
    ) -> None:
        super().__init__()
        self.verify_ssl = bool(verify_ssl)
        self.timeout = float(timeout)
        self.max_response_bytes = max(1024, int(max_response_bytes))
        self.rate_limiter = rate_limiter or RateLimiter(0)
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

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        self.rate_limiter.wait()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_ssl)
        kwargs.setdefault("allow_redirects", True)

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
) -> SecureSession:
    session = SecureSession(
        verify_ssl=verify_ssl,
        timeout=timeout,
        user_agent=user_agent,
        proxy=proxy,
        max_response_bytes=max_response_bytes,
        rate_limiter=rate_limiter,
        retries=retries,
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
