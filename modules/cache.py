#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Small JSON cache with bounded, filesystem-safe names.

Long names (for example an EPSS query containing forty CVE identifiers) can
exceed Windows path limits.  Every cache name is therefore sanitised and, when
necessary, shortened with a stable SHA-256 suffix.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Optional, Tuple


def cache_filename(name: str, *, max_length: int = 120) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", name)
    if not safe:
        safe = "cache"
    if len(safe) <= max_length:
        return safe
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]
    stem = safe[: max(8, max_length - len(digest) - 6)]
    return f"{stem}_{digest}.json"


class JsonCache:
    """TTL cache with stale fallback for offline/failed fetches."""

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        *,
        ttl: int = 24 * 60 * 60,
        offline: bool = False,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.cache_dir = Path(cache_dir) if cache_dir else (
            Path(__file__).resolve().parent.parent / "data" / "cache"
        )
        self.ttl = max(0, int(ttl))
        self.offline = offline
        self.logger = logger or logging.getLogger("MoodleJsonCache")
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            self.cache_dir = Path(tempfile.gettempdir()) / "mss-cache"
            try:
                self.cache_dir.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass

    def path(self, name: str) -> Path:
        return self.cache_dir / cache_filename(name)

    def read(self, name: str) -> Tuple[Optional[Any], bool, Optional[float]]:
        path = self.path(name)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None, False, None
        try:
            cached_at = float(payload.get("_cached_at", 0))
        except (TypeError, ValueError):
            cached_at = 0.0
        age = max(0.0, time.time() - cached_at)
        return payload.get("data"), age <= self.ttl, age

    def write(self, name: str, data: Any) -> None:
        path = self.path(name)
        payload = {"_cached_at": time.time(), "data": data}
        try:
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, path)
        except OSError as exc:
            self.logger.debug("Could not write cache %s: %s", path, exc)

    def get(self, name: str, loader: Callable[[], Optional[Any]]) -> Optional[Any]:
        data, fresh, age = self.read(name)
        if fresh and data is not None:
            return data
        if self.offline:
            if data is not None:
                self.logger.debug("Using stale cache %s (age %.0fs)", name, age or 0)
            return data
        try:
            loaded = loader()
        except Exception as exc:
            self.logger.warning("Online source unavailable (%s); using cache if present.", exc)
            return data
        if loaded is None:
            return data
        self.write(name, loaded)
        return loaded
