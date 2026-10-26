#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Moodle version detection with evidence and confidence levels.

The old detector guessed versions from logo file sizes and from arbitrary
words on the page.  That produced confident but wrong answers.  This version
only trusts sources that are tied to the Moodle codebase:

* ``M.cfg.wwwroot`` (reliable base URL, also fixes target normalisation)
* the mobile-app link ``download.moodle.org/mobile?version=YYYYMMDDNN``
* ``M.cfg.release`` / a generator meta tag (when present)
* ``lib/upgrade.txt`` (branch only; it is frozen at 4.4 for Moodle 4.5+)

Exact releases are mapped through ``data/moodle_version_map.json`` generated
from the official Moodle git tags.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from bs4 import BeautifulSoup, Comment

from modules.http import SecureSession, build_session

_VERSION_MAP: Optional[Dict[str, Dict[str, str]]] = None

_MOBILE_RE = re.compile(r"download\.moodle\.org/mobile\?version=(\d{8,12})", re.IGNORECASE)
_MCFG_RE = re.compile(r"M\.cfg\s*=\s*", re.IGNORECASE)
_RELEASE_RE = re.compile(r"^\d+\.\d+(?:\.\d+)?(?:[+-].*)?$")


def load_version_map() -> Dict[str, Dict[str, str]]:
    global _VERSION_MAP
    if _VERSION_MAP is None:
        path = Path(__file__).resolve().parent.parent / "data" / "moodle_version_map.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            _VERSION_MAP = data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            _VERSION_MAP = {}
    return _VERSION_MAP


def extract_m_cfg(html: str) -> Dict[str, Any]:
    """Return the ``M.cfg`` object embedded in a Moodle page, if present."""

    match = _MCFG_RE.search(html or "")
    if not match:
        return {}
    start = html.find("{", match.end())
    if start < 0:
        return {}
    try:
        value, _ = json.JSONDecoder().raw_decode(html[start:])
    except (ValueError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


class MoodleVersionDetector:
    """Detect the Moodle release and the real web root of an installation."""

    def __init__(
        self,
        target_url: str,
        logger: Optional[logging.Logger] = None,
        timeout: float = 30,
        proxy: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        delay: float = 0,
        user_agent: Optional[str] = None,
        verify_ssl: bool = True,
        session: Optional[SecureSession] = None,
        max_response_bytes: int = 2_000_000,
    ) -> None:
        self.target_url = (target_url or "").strip()
        self.timeout = timeout
        self.proxy = proxy
        self.cookies = cookies or {}
        self.delay = delay
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl
        self.max_response_bytes = max_response_bytes
        self.version_map = load_version_map()

        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger("MoodleVersionDetector")
            if not self.logger.handlers:
                self.logger.setLevel(logging.INFO)
                handler = logging.StreamHandler()
                handler.setFormatter(
                    logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
                )
                self.logger.addHandler(handler)

        self.session = session or build_session(
            verify_ssl=verify_ssl,
            timeout=timeout,
            user_agent=user_agent,
            proxy=proxy,
            cookies=cookies,
            max_response_bytes=max_response_bytes,
        )

    def detect_version(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {}
        homepage = self._get(self.target_url)
        html = homepage.text if homepage is not None else ""

        if homepage is not None:
            cfg = extract_m_cfg(html)
            if cfg:
                wwwroot = str(cfg.get("wwwroot") or "").strip()
                if wwwroot.startswith(("http://", "https://")):
                    info["wwwroot"] = wwwroot.rstrip("/") + "/"
                for key in ("theme", "jsrev", "langrev", "themerev"):
                    if cfg.get(key) not in (None, ""):
                        info[key] = cfg[key]
                info["is_moodle"] = True

                release = str(cfg.get("release") or cfg.get("version") or "").strip()
                if release and _RELEASE_RE.match(release):
                    info["version"] = release.split("+")[0].strip()
                    info["version_source"] = "m_cfg"
                    info["version_confidence"] = "high"
                    info["is_moodle"] = True

            if "version" not in info:
                mobile = _MOBILE_RE.search(html)
                if mobile:
                    numeric = mobile.group(1)
                    info["numeric_version"] = numeric
                    mapped = self.version_map.get(numeric)
                    if mapped:
                        info["version"] = mapped.get("release")
                        info["branch"] = mapped.get("branch")
                        info["version_source"] = "mobile_link"
                        info["version_confidence"] = "high"
                        info["version_evidence"] = (
                            "O link oficial da app móvel contém o valor numérico "
                            f"$CFG->version = {numeric}, mapeado para "
                            f"Moodle {mapped.get('release')} ({mapped.get('tag')})."
                        )
                        info["is_moodle"] = True
                    else:
                        info["version_source"] = "mobile_link"
                        info["version_confidence"] = "low"
                        info["version_evidence"] = (
                            "Foi encontrado o valor numérico de versão "
                            f"{numeric}, mas ele não está no mapa offline de releases."
                        )
                        info["is_moodle"] = True

            if "version" not in info:
                meta_version = self._detect_from_meta(html)
                if meta_version:
                    info.update(meta_version)

            if "version" not in info:
                comment_version = self._detect_from_comments(html)
                if comment_version:
                    info.update(comment_version)

        # Rebase all subsequent requests on the authentic Moodle root.
        base = (info.get("wwwroot") or self.target_url).rstrip("/")
        self.target_url = base + "/"

        if "version" not in info and "version_branch" not in info:
            upgrade = self._detect_from_upgrade_file()
            if upgrade:
                info.update(upgrade)

        if not info.get("is_moodle"):
            info["is_moodle"] = self._looks_like_moodle(html)

        if info.get("version"):
            self.logger.info(
                "Moodle %s detetado (%s, confiança %s)",
                info["version"],
                info.get("version_source", "unknown"),
                info.get("version_confidence", "unknown"),
            )
        elif info.get("version_branch"):
            self.logger.info(
                "Branch Moodle %s detetada; a versão exata não foi exposta.",
                info["version_branch"],
            )
        else:
            self.logger.warning("Não foi possível determinar a versão exata do Moodle.")

        return info

    def _get(self, url: str):
        try:
            return self.session.get(url, timeout=self.timeout)
        except Exception as exc:  # requests errors are already handled by the session
            self.logger.debug("Erro ao pedir %s: %s", url, exc)
            return None

    def _detect_from_meta(self, html: str) -> Dict[str, Any]:
        if not html:
            return {}
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return {}
        for meta in soup.find_all("meta"):
            name = str(meta.get("name") or "").lower()
            if "generator" not in name:
                continue
            content = str(meta.get("content") or "")
            if "moodle" not in content.lower():
                continue
            match = re.search(r"(\d+\.\d+(?:\.\d+)?)", content)
            if match:
                return {
                    "version": match.group(1),
                    "version_source": "meta_generator",
                    "version_confidence": "high",
                    "is_moodle": True,
                    "version_evidence": content,
                }
        return {}

    def _detect_from_comments(self, html: str) -> Dict[str, Any]:
        if not html:
            return {}
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return {}
        for comment in soup.find_all(string=lambda value: isinstance(value, Comment)):
            text = str(comment)
            if "moodle" not in text.lower():
                continue
            match = re.search(
                r"(?:version|release)\s*:?\s*(\d+\.\d+(?:\.\d+)?)", text, re.IGNORECASE
            )
            if match:
                return {
                    "version": match.group(1),
                    "version_source": "html_comment",
                    "version_confidence": "medium",
                    "is_moodle": True,
                    "version_evidence": text.strip()[:300],
                }
        return {}

    def _detect_from_upgrade_file(self) -> Dict[str, Any]:
        url = self.target_url + "lib/upgrade.txt"
        response = self._get(url)
        if response is None or response.status_code != 200:
            return {}
        text = response.text or ""

        # Moodle 4.5+ froze this file and moved notes to UPGRADING.md.
        if "4.5 Onwards" in text[:2000] or "UPGRADING.md" in text[:2000]:
            return {
                "version_branch": "4.5+",
                "version_source": "upgrade_txt",
                "version_confidence": "low",
                "is_moodle": True,
                "version_evidence": (
                    "lib/upgrade.txt contém o marcador '4.5 Onwards'; "
                    "a versão exata não é revelada por este ficheiro."
                ),
            }

        headings = re.findall(r"^=+\s*(\d+\.\d+(?:\.\d+)?)\s*=+", text, re.MULTILINE)
        if not headings:
            return {}
        # upgrade.txt lists developer branch sections; it does not prove the
        # installed patch. Never turn its first heading into an exact version.
        branch = ".".join(headings[0].split(".")[:2])
        return {
            "version_branch": branch,
            "version_source": "upgrade_txt",
            "version_confidence": "low",
            "is_moodle": True,
            "version_evidence": (
                f"lib/upgrade.txt indica a branch {branch}, mas não o patch exato."
            ),
        }

    def _looks_like_moodle(self, html: str) -> bool:
        if extract_m_cfg(html):
            return True
        lowered = (html or "").lower()
        signals = (
            "login/index.php",
            "theme/boost",
            "theme/classic",
            "moodle-core",
            "moodle.org",
        )
        return "moodle" in lowered and any(signal in lowered for signal in signals)


def normalize_moodle_base_url(url: str) -> str:
    """Best-effort normalisation used before the real wwwroot is known."""

    parsed = urlparse(url.strip())
    if not parsed.scheme:
        return "https://" + url.strip().rstrip("/") + "/"
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"
    if path.endswith("/"):
        return base + path
    return base + path + "/"
