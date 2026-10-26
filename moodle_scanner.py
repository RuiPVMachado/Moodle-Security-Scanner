#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Moodle Security Scanner 2.0.

Design goals:

* never claim a vulnerability that the scanner cannot substantiate;
* separate version-based advisories from actively confirmed behaviour;
* use authoritative, live data (OSV, NVD/KEV/EPSS) instead of a stale CVE table;
* keep requests bounded, rate-limited, retried and concurrent at module level;
* produce JSON, HTML, TXT and SARIF reports with escaped output.

The scanner is intended for authorized security testing only.
"""

from __future__ import annotations

import argparse
import ast
import html as html_lib
import inspect
import json
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

try:
    from colorama import Fore, Style, init as colorama_init
    import urllib3

    from modules import (
        MoodleAPITester,
        MoodleAuthTester,
        MoodleCVETester,
        MoodleLFITester,
        MoodlePassiveTester,
        MoodlePluginTester,
        MoodleRCETester,
        MoodleSQLITester,
        MoodleSessionTester,
        MoodleVersionDetector,
        MoodleXSSTester,
        available_modules,
    )
    from modules.http import DEFAULT_USER_AGENT, RateLimiter, build_session
    from modules.schema import (
        SEVERITY_ORDER,
        deduplicate_vulnerabilities,
        normalize_vulnerabilities,
    )
except ImportError as exc:  # pragma: no cover - dependency guard
    print(f"Error: Missing required module - {exc}")
    print("Please install required dependencies using: pip install -r requirements.txt")
    sys.exit(1)

colorama_init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SCANNER_VERSION = "2.0.0"
ACTIVE_MODULES = {"xss", "sqli", "lfi", "rce", "session"}

PROFILES = {
    "fast": ["cve", "passive", "auth", "api"],
    "balanced": ["cve", "passive", "auth", "api", "xss", "plugin", "session", "supplychain"],
    "deep": [
        "cve",
        "passive",
        "auth",
        "api",
        "xss",
        "sqli",
        "lfi",
        "rce",
        "plugin",
        "session",
        "supplychain",
    ],
    # Black-box / no credentials: only what can be tested from the outside.
    "external": ["cve", "passive", "api", "xss", "sqli", "lfi", "plugin", "supplychain"],
}


def _e(value: Any) -> str:
    """Escape untrusted data for HTML reports."""

    return html_lib.escape(str(value if value is not None else ""), quote=True)


def _safe_href(value: Any) -> str:
    text = str(value or "").strip()
    parsed = urlparse(text)
    return text if parsed.scheme in {"http", "https"} else "#"


def _format_from_extension(path: Optional[str]) -> str:
    if not path:
        return "json"
    suffix = Path(path).suffix.lower()
    if suffix in {".html", ".htm"}:
        return "html"
    if suffix == ".txt":
        return "txt"
    if suffix == ".sarif":
        return "sarif"
    return "json"


def _fmt_float(value: Any, digits: int = 3) -> str:
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return "n/a"


class MoodleScanner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.output_file = args.output
        self.proxy = args.proxy
        self.timeout = float(args.timeout)
        self.delay = float(args.delay or 0)
        self.rate_limit = float(getattr(args, "rate_limit", 0) or 0)
        self.threads = max(1, int(getattr(args, "threads", 5) or 5))
        self.user_agent = getattr(args, "user_agent", None) or DEFAULT_USER_AGENT
        self.verify_ssl = not args.no_verify_ssl
        self.verbose = bool(args.verbose)
        self.quiet = bool(args.quiet)
        self.force = bool(getattr(args, "force", False))
        self.authorized = bool(getattr(args, "authorized", False))
        self.validate_cves = bool(getattr(args, "validate_cves", False))
        self.offline = bool(getattr(args, "offline", False))
        self.enrich = not bool(getattr(args, "no_enrich", False))
        self.no_active = bool(getattr(args, "no_active", False))
        self.deep = bool(getattr(args, "deep", False) or getattr(args, "profile", "balanced") == "deep")
        profile_name = getattr(args, "profile", "balanced")
        default_tests = 120 if self.deep else (60 if profile_name == "external" else 30)
        self.max_tests = int(getattr(args, "max_tests", 0) or 0) or default_tests
        self.max_response_bytes = max(1024, int(getattr(args, "max_response_bytes", 2_000_000)))
        self.username = getattr(args, "username", None)
        self.password = getattr(args, "password", None)
        self.manual_version = getattr(args, "moodle_version", None)
        self.test_default_credentials = bool(getattr(args, "test_default_credentials", False))
        self.cache_dir = Path(args.cache_dir) if getattr(args, "cache_dir", None) else None
        self.exit_code = 0

        self.logger = logging.getLogger("MoodleScanner")
        self.setup_logging()

        self.initial_url = self._normalize_url(args.target)
        self.target_url = self.initial_url
        self.modules_to_run = self._parse_modules(args.modules, getattr(args, "profile", "balanced"))
        self.cookies = self._parse_cookies(args.cookies)
        self.rate_limiter = RateLimiter(self._min_interval())

        self.results: Dict[str, Any] = {
            "scan_info": {
                "target_initial": self.initial_url,
                "target": self.target_url,
                "timestamp": datetime.now().isoformat(),
                "modules_run": [],
                "modules_failed": [],
                "scanner_version": SCANNER_VERSION,
                "profile": "deep" if self.deep else getattr(args, "profile", "balanced"),
                "authorized": self.authorized,
                "offline": self.offline,
                "status": "initializing",
            },
            "version_info": {},
            "vulnerabilities": [],
            "info": [],
            "summary": {},
            "module_results": {},
        }
        self.module_results: Dict[str, Dict[str, Any]] = {}

        self.logger.info("A iniciar scan contra %s", self.target_url)
        if not self.quiet:
            self.show_banner()

    # ------------------------------------------------------------------ setup
    def setup_logging(self) -> None:
        self.logger.handlers.clear()
        self.logger.propagate = False
        if self.verbose:
            level = logging.DEBUG
        elif self.quiet:
            level = logging.ERROR
        else:
            level = logging.INFO
        self.logger.setLevel(level)

        formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        console = logging.StreamHandler()
        console.setLevel(level)
        console.setFormatter(formatter)
        self.logger.addHandler(console)

        if self.output_file and self.output_file.endswith(".log"):
            try:
                log_dir = os.path.dirname(self.output_file)
                if log_dir and not os.path.exists(log_dir):
                    os.makedirs(log_dir)
                file_handler = logging.FileHandler(self.output_file, "w", encoding="utf-8")
                file_handler.setLevel(level)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)
            except OSError as exc:
                self.logger.error("Não foi possível criar o ficheiro de log: %s", exc)

    def _normalize_url(self, url: str) -> str:
        value = (url or "").strip()
        if not value:
            raise ValueError("O alvo não pode estar vazio.")
        if "://" not in value:
            value = "https://" + value
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"URL de alvo inválido: {url}")
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        if not base.endswith("/"):
            base += "/"
        return base

    def _parse_modules(self, modules_arg: Optional[str], profile: str) -> List[str]:
        available = set(available_modules.keys())
        requested: List[str] = []
        raw = (modules_arg or "").strip().lower()

        if raw and raw != "all":
            for item in raw.split(","):
                name = item.strip().lower()
                if not name:
                    continue
                if name in available:
                    if name not in requested:
                        requested.append(name)
                else:
                    self.logger.warning(
                        "Módulo desconhecido '%s'. Disponíveis: %s",
                        name,
                        ", ".join(sorted(available)),
                    )
        elif raw == "all" or profile == "all":
            requested = list(available_modules.keys())
        else:
            requested = list(PROFILES.get(profile, PROFILES["balanced"]))

        if self.no_active:
            requested = [name for name in requested if name not in ACTIVE_MODULES]

        if "version" in requested:
            requested.remove("version")
        requested.insert(0, "version")
        return requested

    def _parse_cookies(self, cookies_arg: Optional[str]) -> Optional[Dict[str, str]]:
        if not cookies_arg:
            return None
        value = cookies_arg.strip()
        try:
            if value.startswith("{"):
                try:
                    parsed = json.loads(value)
                except json.JSONDecodeError:
                    parsed = ast.literal_eval(value)
                if isinstance(parsed, dict):
                    return {str(key): str(item) for key, item in parsed.items()}
                raise ValueError("JSON de cookies não é um objeto")
            cookies: Dict[str, str] = {}
            for part in value.split(";"):
                if "=" in part:
                    name, cookie_value = part.strip().split("=", 1)
                    if name.strip():
                        cookies[name.strip()] = cookie_value.strip()
            return cookies or None
        except Exception as exc:
            self.logger.error("Erro a interpretar cookies: %s", exc)
            return None

    def _min_interval(self) -> float:
        intervals = []
        if self.delay > 0:
            intervals.append(self.delay)
        if self.rate_limit > 0:
            intervals.append(1.0 / self.rate_limit)
        return max(intervals) if intervals else 0.0

    def _make_session(self, cookies: Optional[Dict[str, str]] = None):
        return build_session(
            verify_ssl=self.verify_ssl,
            timeout=self.timeout,
            user_agent=self.user_agent,
            proxy=self.proxy,
            cookies=cookies if cookies is not None else self.cookies,
            max_response_bytes=self.max_response_bytes,
            rate_limiter=self.rate_limiter,
            retries=2,
        )

    # ------------------------------------------------------------------ banner
    def show_banner(self) -> None:
        banner = f"""
{Fore.CYAN}+----------------------------------------------------------+
|  {Fore.GREEN}MOODLE SECURITY SCANNER {SCANNER_VERSION}{Fore.CYAN}                          |
|  {Fore.YELLOW}Version-aware - evidence-based - no fake Criticals{Fore.CYAN}       |
+----------------------------------------------------------+{Style.RESET_ALL}
"""
        try:
            print(banner)
        except UnicodeEncodeError:
            print(f"Moodle Security Scanner {SCANNER_VERSION}")
        print(f"Target:  {Fore.GREEN}{self.initial_url}{Style.RESET_ALL}")
        print(f"Modules: {Fore.GREEN}{', '.join(self.modules_to_run)}{Style.RESET_ALL}")
        print(f"Profile: {Fore.GREEN}{'deep' if self.deep else getattr(self.args, 'profile', 'balanced')}{Style.RESET_ALL}")
        print("")

    # -------------------------------------------------------------------- run
    def detect_version(self) -> Optional[Dict[str, Any]]:
        self.logger.info("A detetar versão e webroot do Moodle...")
        session = self._make_session(cookies=self.cookies)
        detector = MoodleVersionDetector(
            target_url=self.initial_url,
            logger=self.logger,
            timeout=self.timeout,
            proxy=self.proxy,
            cookies=self.cookies,
            delay=self.delay,
            user_agent=self.user_agent,
            verify_ssl=self.verify_ssl,
            session=session,
            max_response_bytes=self.max_response_bytes,
        )
        info = detector.detect_version()
        if self.manual_version:
            manual = str(self.manual_version).strip().lstrip("vV")
            if re.fullmatch(r"\d+\.\d+(?:\.\d+)?", manual):
                info["version"] = manual
                info["version_source"] = "manual"
                info["version_confidence"] = "high"
                info["is_moodle"] = True
                self.logger.info("Versão fornecida manualmente: Moodle %s", manual)
            else:
                self.logger.warning(
                    "Valor de --moodle-version inválido: %s (use X.Y ou X.Y.Z)",
                    self.manual_version,
                )
        if info.get("wwwroot"):
            self.target_url = str(info["wwwroot"]).rstrip("/") + "/"
            if self.target_url != self.initial_url:
                self.logger.info("Webroot real do Moodle: %s", self.target_url)

        self.results["version_info"] = info
        self.results["scan_info"]["target"] = self.target_url

        if not info.get("is_moodle"):
            message = (
                "O alvo não parece ser Moodle (M.cfg/wwwroot/login Moodle não encontrados). "
                "Use --force apenas se tiver a certeza."
            )
            if not self.force:
                self.logger.error(message)
                self.results["scan_info"]["status"] = "aborted"
                return None
            self.logger.warning(message)

        if not info.get("version") and not info.get("version_branch"):
            self.logger.warning(
                "Versão exata não detetada. A correspondência de CVEs será ignorada."
            )
        return info

    def _warn_authorization(self) -> None:
        if self.validate_cves and not self.authorized:
            self.logger.warning(
                "--validate-cves pedido sem --authorized; nenhum check ativo "
                "de CVE será enviado."
            )
        active = sorted(set(self.modules_to_run) & ACTIVE_MODULES)
        if active and not self.authorized:
            self.logger.warning(
                "Testes ativos (%s) sem --authorized. Use apenas em sistemas que "
                "tem autorização para testar.",
                ", ".join(active),
            )
            self.results["info"].append(
                {
                    "title": "Testes ativos executados sem --authorized",
                    "description": (
                        "Foram executados módulos ativos sem a flag --authorized. "
                        "Confirme que existe autorização escrita para este alvo."
                    ),
                    "severity": "Info",
                    "verified": True,
                    "source": "scanner",
                    "evidence_type": "info",
                }
            )

    def run(self) -> Dict[str, Any]:
        start = time.time()
        self.results["scan_info"]["status"] = "running"
        try:
            version_info = self.detect_version()
            if version_info is None:
                self.results["scan_info"]["duration_seconds"] = round(time.time() - start, 2)
                return self.results

            self._warn_authorization()
            modules = [name for name in self.modules_to_run if name != "version"]

            if "cve" in modules:
                self._merge_module_result(*self._collect_module("cve", version_info))
                modules.remove("cve")

            if modules:
                workers = max(1, min(self.threads, len(modules)))
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = {
                        pool.submit(self._collect_module, name, version_info): name
                        for name in modules
                    }
                    for future in as_completed(futures):
                        name = futures[future]
                        try:
                            self._merge_module_result(*future.result())
                        except Exception as exc:  # pragma: no cover - defensive
                            self.logger.error("Módulo %s falhou: %s", name, exc)
                            self._merge_module_result(
                                name,
                                [],
                                [self._module_error_info(name, str(exc))],
                                str(exc),
                            )

            self.results["vulnerabilities"] = deduplicate_vulnerabilities(
                self.results["vulnerabilities"]
            )
            self.results["info"] = self._dedupe_info(self.results["info"])
            self.generate_summary()
            self.results["scan_info"]["duration_seconds"] = round(time.time() - start, 2)
            self.results["scan_info"]["status"] = (
                "partial" if self.results["scan_info"].get("modules_failed") else "complete"
            )

            if self.output_file and not self.output_file.endswith(".log"):
                self.save_results()

            self.print_summary()
            self._apply_fail_on()
            return self.results

        except KeyboardInterrupt:
            self.logger.warning("Scan interrompido pelo utilizador.")
            self.results["scan_info"]["status"] = "partial"
            self.results["scan_info"]["duration_seconds"] = round(time.time() - start, 2)
            if self.output_file and not self.output_file.endswith(".log"):
                self.save_results(partial=True)
            self.print_summary()
            return self.results

    def _collect_module(
        self,
        module_name: str,
        version_info: Dict[str, Any],
    ) -> Tuple[str, List[Dict[str, Any]], List[Dict[str, Any]], Optional[str]]:
        module_class = available_modules.get(module_name)
        if module_class is None:
            return module_name, [], [self._module_error_info(module_name, "Módulo desconhecido")], "unknown"

        session = self._make_session(cookies=self.cookies)
        kwargs: Dict[str, Any] = {
            "target_url": self.target_url,
            "logger": self.logger,
            "timeout": self.timeout,
            "proxy": self.proxy,
            "cookies": self.cookies,
            "delay": self.delay,
            "user_agent": self.user_agent,
            "verify_ssl": self.verify_ssl,
            "session": session,
            "deep": self.deep,
            "max_tests": self.max_tests,
            "username": self.username,
            "password": self.password,
            "test_default_credentials": self.test_default_credentials,
            "offline": self.offline,
            "cache_dir": str(self.cache_dir) if self.cache_dir else None,
            "enrich": self.enrich,
            "validate_cves": self.validate_cves,
            "authorized": self.authorized,
            "max_response_bytes": self.max_response_bytes,
        }
        accepted = inspect.signature(module_class).parameters
        filtered = {key: value for key, value in kwargs.items() if key in accepted}

        try:
            module = module_class(**filtered)
            if hasattr(module, "set_version_info"):
                module.set_version_info(version_info)
            self.logger.info("A executar módulo %s...", module_name)
            raw_results = module.run_tests() or {}
            if not isinstance(raw_results, dict):
                raise TypeError("run_tests() não devolveu um dicionário")

            vulnerabilities = normalize_vulnerabilities(
                raw_results.get("vulnerabilities", []),
                module_name,
                self.target_url,
            )
            info = [
                self._normalize_info(item, module_name)
                for item in raw_results.get("info", [])
            ]
            self.logger.info(
                "Módulo %s: %s findings, %s observações.",
                module_name,
                len(vulnerabilities),
                len(info),
            )
            return module_name, vulnerabilities, info, None
        except Exception as exc:
            self.logger.error("Erro no módulo %s: %s", module_name, exc)
            if self.verbose:
                self.logger.exception(exc)
            return module_name, [], [self._module_error_info(module_name, str(exc))], str(exc)

    def _merge_module_result(
        self,
        module_name: str,
        vulnerabilities: List[Dict[str, Any]],
        info: List[Dict[str, Any]],
        error: Optional[str],
    ) -> None:
        self.results["vulnerabilities"].extend(vulnerabilities)
        self.results["info"].extend(info)
        self.module_results[module_name] = {
            "vulnerabilities": len(vulnerabilities),
            "info": len(info),
            "error": error,
        }
        self.results["module_results"] = self.module_results
        if error:
            self.results["scan_info"].setdefault("modules_failed", []).append(module_name)
        else:
            self.results["scan_info"].setdefault("modules_run", []).append(module_name)

    @staticmethod
    def _module_error_info(module_name: str, message: str) -> Dict[str, Any]:
        return {
            "title": f"Módulo {module_name} não concluído",
            "description": f"O módulo falhou: {message}",
            "severity": "Info",
            "verified": False,
            "source": "scanner",
            "evidence_type": "info",
        }

    @staticmethod
    def _normalize_info(item: Any, module_name: str) -> Dict[str, Any]:
        if isinstance(item, str):
            item = {"title": item, "description": item}
        if not isinstance(item, dict):
            item = {"title": str(item), "description": str(item)}
        return {
            "title": str(item.get("title") or "Observação"),
            "description": str(item.get("description") or ""),
            "severity": "Info",
            "url": item.get("url"),
            "verified": bool(item.get("verified", False)),
            "source": str(item.get("source") or module_name),
            "evidence": str(item.get("evidence") or ""),
            "evidence_type": str(item.get("evidence_type") or "info"),
        }

    @staticmethod
    def _dedupe_info(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        output = []
        for item in items:
            key = (str(item.get("title") or "").lower(), str(item.get("url") or ""))
            if key in seen:
                continue
            seen.add(key)
            output.append(item)
        return output

    # ---------------------------------------------------------------- summary
    def generate_summary(self) -> None:
        vulnerabilities = self.results["vulnerabilities"]
        summary: Dict[str, Any] = {
            "total_vulnerabilities": len(vulnerabilities),
            "verified_findings": 0,
            "version_based_findings": 0,
            "heuristic_findings": 0,
            "severity_counts": {name: 0 for name in SEVERITY_ORDER},
            "verified_severity_counts": {name: 0 for name in SEVERITY_ORDER},
            "confidence_counts": {"high": 0, "medium": 0, "low": 0},
            "exploitability_counts": {"high": 0, "medium": 0, "low": 0},
            "source_counts": {},
            "validation_counts": {},
            "vulnerabilities_by_module": {},
            "average_risk_score": 0,
            "top_vulnerabilities": [],
        }

        for vuln in vulnerabilities:
            severity = str(vuln.get("severity") or "Info")
            summary["severity_counts"][severity] = summary["severity_counts"].get(severity, 0) + 1
            if vuln.get("verified"):
                summary["verified_findings"] += 1
                summary["verified_severity_counts"][severity] = (
                    summary["verified_severity_counts"].get(severity, 0) + 1
                )
            if vuln.get("evidence_type") == "version" or str(vuln.get("source")).upper() in {"OSV", "MSA"}:
                summary["version_based_findings"] += 1
            if vuln.get("evidence_type") == "heuristic":
                summary["heuristic_findings"] += 1

            confidence = str(vuln.get("confidence") or "low")
            summary["confidence_counts"][confidence] = summary["confidence_counts"].get(confidence, 0) + 1
            exploitability = str(vuln.get("exploitability") or "medium")
            summary["exploitability_counts"][exploitability] = (
                summary["exploitability_counts"].get(exploitability, 0) + 1
            )
            source = str(vuln.get("source") or "unknown")
            summary["source_counts"][source] = summary["source_counts"].get(source, 0) + 1
            validation_status = str(vuln.get("validation_status") or "not-run")
            summary["validation_counts"][validation_status] = (
                summary["validation_counts"].get(validation_status, 0) + 1
            )

        for module in self.modules_to_run:
            summary["vulnerabilities_by_module"][module] = 0
        for vuln in vulnerabilities:
            module = str(vuln.get("module") or "unknown")
            if module in summary["vulnerabilities_by_module"]:
                summary["vulnerabilities_by_module"][module] += 1

        if vulnerabilities:
            summary["average_risk_score"] = round(
                sum(int(vuln.get("risk_score") or 0) for vuln in vulnerabilities)
                / len(vulnerabilities),
                2,
            )
            summary["top_vulnerabilities"] = [
                {
                    "title": vuln.get("title"),
                    "severity": vuln.get("severity"),
                    "module": vuln.get("module"),
                    "confidence": vuln.get("confidence"),
                    "exploitability": vuln.get("exploitability"),
                    "risk_score": vuln.get("risk_score"),
                    "cve": vuln.get("cve"),
                    "verified": vuln.get("verified"),
                    "source": vuln.get("source"),
                    "cvss_score": vuln.get("cvss_score"),
                    "kev": vuln.get("kev"),
                    "validation_status": vuln.get("validation_status"),
                }
                for vuln in vulnerabilities[:10]
            ]

        summary["info_count"] = len(self.results["info"])
        self.results["summary"] = summary

    def print_summary(self) -> None:
        if self.quiet:
            return
        summary = self.results.get("summary") or {}
        version_info = self.results.get("version_info") or {}
        print("\n" + "=" * 64)
        print(f"Scan Summary: {self.results['scan_info'].get('target')}")
        print("=" * 64)
        version = version_info.get("version") or version_info.get("version_branch") or "Desconhecida"
        confidence = version_info.get("version_confidence", "n/a")
        print(f"Moodle: {Fore.CYAN}{version}{Style.RESET_ALL} (confiança: {confidence})")
        print(f"Status: {self.results['scan_info'].get('status')}")
        print(f"Duração: {self.results['scan_info'].get('duration_seconds', 0)}s")
        print("")
        print(f"Findings: {Fore.YELLOW}{summary.get('total_vulnerabilities', 0)}{Style.RESET_ALL} "
              f"(confirmados: {summary.get('verified_findings', 0)}, "
              f"por versão: {summary.get('version_based_findings', 0)}, "
              f"potenciais: {summary.get('heuristic_findings', 0)})")
        validation_counts = summary.get("validation_counts", {})
        if validation_counts:
            print(
                "Validação de CVEs: "
                + ", ".join(f"{name}={count}" for name, count in sorted(validation_counts.items()))
            )

        severity_counts = summary.get("severity_counts", {})
        for name, color in (
            ("Critical", Fore.RED),
            ("High", Fore.LIGHTRED_EX),
            ("Medium", Fore.YELLOW),
            ("Low", Fore.BLUE),
            ("Info", Fore.GREEN),
        ):
            count = severity_counts.get(name, 0)
            if count:
                print(f"  {color}{name}: {count}{Style.RESET_ALL}")

        top = summary.get("top_vulnerabilities", [])
        if top:
            print("\nTop findings:")
            for index, vuln in enumerate(top[:5], 1):
                badge = "VERIFIED" if vuln.get("verified") else str(vuln.get("source") or "VERSION")
                print(
                    f"  {index}. [{vuln.get('severity')}] {vuln.get('title')} "
                    f"({badge}, risk {vuln.get('risk_score')})"
                )

        if summary.get("info_count"):
            print(f"\nObservações/info: {summary.get('info_count')}")
        if self.output_file and not self.output_file.endswith(".log"):
            print(f"\nRelatório: {Fore.GREEN}{self.output_file}{Style.RESET_ALL}")
        print("=" * 64)

    # ---------------------------------------------------------------- reports
    def save_results(self, partial: bool = False) -> None:
        if not self.output_file:
            return
        try:
            directory = os.path.dirname(self.output_file)
            if directory and not os.path.exists(directory):
                os.makedirs(directory)

            output_format = getattr(self.args, "format", None) or _format_from_extension(self.output_file)
            if output_format == "json":
                self._save_json(self.output_file)
            elif output_format == "html":
                self._save_html(self.output_file)
            elif output_format == "txt":
                self._save_text(self.output_file)
            elif output_format == "sarif":
                self._save_sarif(self.output_file)
            else:
                self._save_json(self.output_file)
            self.logger.info("Resultados guardados em %s (%s).", self.output_file, output_format)
        except Exception as exc:
            self.logger.error("Erro ao guardar resultados: %s", exc)

    def _save_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(self.results, handle, indent=2, ensure_ascii=False, default=str)
            handle.write("\n")

    def _save_html(self, path: str) -> None:
        summary = self.results.get("summary", {})
        version_info = self.results.get("version_info", {})
        vulnerabilities = self.results.get("vulnerabilities", [])
        info_items = self.results.get("info", [])

        css = """
        :root { --bg:#0f172a; --card:#1e293b; --text:#e2e8f0; --muted:#94a3b8; --line:#334155; }
        * { box-sizing: border-box; }
        body { margin:0; padding:24px; font-family: system-ui, -apple-system, Segoe UI, sans-serif;
               background:var(--bg); color:var(--text); line-height:1.5; }
        .wrap { max-width: 1100px; margin: 0 auto; }
        h1,h2,h3 { line-height:1.2; }
        .muted { color:var(--muted); }
        .card { background:var(--card); border:1px solid var(--line); border-radius:10px;
                padding:18px; margin:14px 0; }
        .finding { border-left:5px solid var(--line); }
        .finding.critical { border-left-color:#ef4444; }
        .finding.high { border-left-color:#f97316; }
        .finding.medium { border-left-color:#eab308; }
        .finding.low { border-left-color:#38bdf8; }
        .finding.info { border-left-color:#22c55e; }
        .badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:12px;
                 background:#334155; color:#e2e8f0; margin-right:6px; }
        .badge.verified { background:#14532d; color:#bbf7d0; }
        .badge.version { background:#1e3a8a; color:#bfdbfe; }
        .badge.potential { background:#78350f; color:#fde68a; }
        table { width:100%; border-collapse:collapse; margin:10px 0; }
        th,td { border:1px solid var(--line); padding:8px; text-align:left; vertical-align:top; }
        th { background:#0b1220; }
        pre { background:#0b1220; border:1px solid var(--line); border-radius:6px;
              padding:10px; overflow-x:auto; white-space:pre-wrap; word-break:break-word; }
        a { color:#93c5fd; }
        code { background:#0b1220; padding:1px 4px; border-radius:4px; }
        .footer { margin-top:30px; color:var(--muted); font-size:12px; }
        """
        parts = [
            "<!DOCTYPE html>",
            "<html lang='pt'><head><meta charset='utf-8'>",
            "<meta name='viewport' content='width=device-width, initial-scale=1'>",
            f"<title>Moodle Security Scan - {_e(self.target_url)}</title>",
            f"<style>{css}</style></head><body><div class='wrap'>",
            "<h1>Moodle Security Scan Report</h1>",
            "<div class='card'>",
            f"<p><strong>Target:</strong> {_e(self.target_url)}</p>",
            f"<p><strong>Data:</strong> {_e(self.results['scan_info'].get('timestamp'))}</p>",
            f"<p><strong>Scanner:</strong> {_e(SCANNER_VERSION)}</p>",
            f"<p><strong>Status:</strong> {_e(self.results['scan_info'].get('status'))}</p>",
            f"<p><strong>Moodle:</strong> {_e(version_info.get('version') or version_info.get('version_branch') or 'Desconhecida')}"
            f" (fonte: {_e(version_info.get('version_source', 'n/a'))}, "
            f"confiança: {_e(version_info.get('version_confidence', 'n/a'))})</p>",
            f"<p><strong>Módulos:</strong> {_e(', '.join(self.results['scan_info'].get('modules_run', [])))}</p>",
            "</div>",
        ]

        parts.append("<div class='card'><h2>Resumo</h2><table>")
        parts.append("<tr><th>Métrica</th><th>Valor</th></tr>")
        rows = [
            ("Total de findings", summary.get("total_vulnerabilities", 0)),
            ("Confirmados ativamente", summary.get("verified_findings", 0)),
            ("Baseados em versão (OSV)", summary.get("version_based_findings", 0)),
            ("Potenciais/heurísticos", summary.get("heuristic_findings", 0)),
            ("Average risk score", summary.get("average_risk_score", 0)),
            ("Observações/info", summary.get("info_count", 0)),
        ]
        for label, value in rows:
            parts.append(f"<tr><td>{_e(label)}</td><td>{_e(value)}</td></tr>")
        parts.append("</table>")
        parts.append("<h3>Por severidade</h3><table><tr><th>Severidade</th><th>Total</th><th>Confirmados</th></tr>")
        for name in ("Critical", "High", "Medium", "Low", "Info"):
            parts.append(
                f"<tr><td>{_e(name)}</td><td>{_e(summary.get('severity_counts', {}).get(name, 0))}</td>"
                f"<td>{_e(summary.get('verified_severity_counts', {}).get(name, 0))}</td></tr>"
            )
        parts.append("</table></div>")

        parts.append("<h2>Findings</h2>")
        if not vulnerabilities:
            parts.append("<div class='card'>Não foram encontrados findings.</div>")
        for index, vuln in enumerate(vulnerabilities, 1):
            severity = str(vuln.get("severity") or "Info").lower()
            badge = "verified" if vuln.get("verified") else (
                "version" if vuln.get("evidence_type") == "version" else "potential"
            )
            badge_label = {"verified": "CONFIRMADO", "version": "VERSÃO", "potential": "POTENCIAL"}[badge]
            parts.append(f"<article class='card finding {_e(severity)}'>")
            parts.append(
                f"<h3>{index}. {_e(vuln.get('title'))} "
                f"<span class='badge {badge}'>{badge_label}</span>"
                f"<span class='badge'>{_e(vuln.get('severity'))}</span></h3>"
            )
            parts.append(
                f"<p class='muted'>Módulo: {_e(vuln.get('module'))} | "
                f"Confiança: {_e(vuln.get('confidence'))} | "
                f"Explorabilidade: {_e(vuln.get('exploitability'))} | "
                f"Risk: {_e(vuln.get('risk_score'))}</p>"
            )
            parts.append(f"<p>{_e(vuln.get('description'))}</p>")
            if vuln.get("url"):
                parts.append(
                    f"<p><strong>URL:</strong> <a href='{_e(_safe_href(vuln.get('url')))}' rel='noreferrer'>"
                    f"{_e(vuln.get('url'))}</a></p>"
                )
            for label, key in (("CVE", "cve"), ("CWE", "cwe")):
                if vuln.get(key):
                    parts.append(f"<p><strong>{label}:</strong> {_e(vuln.get(key))}</p>")
            if vuln.get("cvss_score") is not None:
                parts.append(f"<p><strong>CVSS:</strong> {_e(vuln.get('cvss_score'))} {_e(vuln.get('cvss_vector') or '')}</p>")
            if vuln.get("epss") is not None:
                parts.append(f"<p><strong>EPSS:</strong> {_e(_fmt_float(vuln.get('epss')))}</p>")
            if vuln.get("kev"):
                parts.append("<p><strong>KEV:</strong> Sim (CISA Known Exploited)</p>")
            if vuln.get("fixed_versions"):
                parts.append(f"<p><strong>Corrigido em:</strong> {_e(', '.join(vuln.get('fixed_versions')))}</p>")
            validation = vuln.get("validation")
            if isinstance(validation, dict) and validation:
                parts.append(
                    f"<p><strong>Validação:</strong> {_e(validation.get('status'))} "
                    f"— {_e(validation.get('reason'))}</p>"
                )
                if validation.get("reference"):
                    reference = validation.get("reference")
                    parts.append(
                        f"<p><strong>Referência de validação:</strong> "
                        f"<a href='{_e(_safe_href(reference))}' rel='noreferrer'>"
                        f"{_e(reference)}</a></p>"
                    )
                if validation.get("evidence"):
                    parts.append(
                        f"<h4>Evidência de validação</h4>"
                        f"<pre>{_e(validation.get('evidence'))}</pre>"
                    )
            if vuln.get("evidence"):
                parts.append(f"<h4>Evidência</h4><pre>{_e(vuln.get('evidence'))}</pre>")
            if vuln.get("payload"):
                parts.append(f"<h4>Payload</h4><pre>{_e(vuln.get('payload'))}</pre>")
            if vuln.get("remediation"):
                parts.append(f"<h4>Remediação</h4><p>{_e(vuln.get('remediation'))}</p>")
            references = vuln.get("references") or []
            if references:
                parts.append("<h4>Referências</h4><ul>")
                for reference in references:
                    parts.append(
                        f"<li><a href='{_e(_safe_href(reference))}' rel='noreferrer'>{_e(reference)}</a></li>"
                    )
                parts.append("</ul>")
            parts.append("</article>")

        if info_items:
            parts.append("<h2>Observações</h2><div class='card'><ul>")
            for item in info_items:
                parts.append(
                    f"<li><strong>{_e(item.get('title'))}</strong>: {_e(item.get('description'))}</li>"
                )
            parts.append("</ul></div>")

        parts.append(
            "<div class='footer'><p>Findings marcados como VERSÃO são correspondências "
            "de versão (OSV), não prova de explorabilidade. Confirme o build e os "
            "patches aplicados antes de remediar.</p>"
            "<p>Gerado por Moodle Security Scanner 2.0.</p></div>"
        )
        parts.append("</div></body></html>")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(parts) + "\n")

    def _save_text(self, path: str) -> None:
        summary = self.results.get("summary", {})
        version_info = self.results.get("version_info", {})
        vulnerabilities = self.results.get("vulnerabilities", [])
        info_items = self.results.get("info", [])

        lines = [
            "=" * 80,
            "MOODLE SECURITY SCAN REPORT",
            "=" * 80,
            f"Target: {self.target_url}",
            f"Data: {self.results['scan_info'].get('timestamp')}",
            f"Scanner: {SCANNER_VERSION}",
            f"Status: {self.results['scan_info'].get('status')}",
            f"Moodle: {version_info.get('version') or version_info.get('version_branch') or 'Desconhecida'}",
            f"Fonte da versão: {version_info.get('version_source', 'n/a')}",
            f"Confiança da versão: {version_info.get('version_confidence', 'n/a')}",
            f"Módulos: {', '.join(self.results['scan_info'].get('modules_run', []))}",
            "",
            "RESUMO",
            "-" * 80,
            f"Total de findings: {summary.get('total_vulnerabilities', 0)}",
            f"Confirmados: {summary.get('verified_findings', 0)}",
            f"Baseados em versão: {summary.get('version_based_findings', 0)}",
            f"Potenciais: {summary.get('heuristic_findings', 0)}",
            f"Average risk score: {summary.get('average_risk_score', 0)}",
            "",
            "Por severidade:",
        ]
        for name in ("Critical", "High", "Medium", "Low", "Info"):
            lines.append(f"  {name}: {summary.get('severity_counts', {}).get(name, 0)}")
        lines.extend(["", "FINDINGS", "=" * 80])

        if not vulnerabilities:
            lines.append("Não foram encontrados findings.")
        for index, vuln in enumerate(vulnerabilities, 1):
            lines.extend(
                [
                    f"{index}. [{vuln.get('severity')}] {vuln.get('title')}",
                    "-" * 80,
                    f"Verified: {'sim' if vuln.get('verified') else 'não'}",
                    f"Source: {vuln.get('source')}",
                    f"Evidence type: {vuln.get('evidence_type')}",
                    f"Module: {vuln.get('module')}",
                    f"Confidence: {vuln.get('confidence')}",
                    f"Exploitability: {vuln.get('exploitability')}",
                    f"Risk score: {vuln.get('risk_score')}",
                    f"Description: {vuln.get('description')}",
                ]
            )
            for label, key in (("URL", "url"), ("CVE", "cve"), ("CWE", "cwe")):
                if vuln.get(key):
                    lines.append(f"{label}: {vuln.get(key)}")
            if vuln.get("cvss_score") is not None:
                lines.append(f"CVSS: {vuln.get('cvss_score')} {vuln.get('cvss_vector') or ''}")
            if vuln.get("epss") is not None:
                lines.append(f"EPSS: {_fmt_float(vuln.get('epss'))}")
            if vuln.get("kev"):
                lines.append("KEV: sim")
            if vuln.get("fixed_versions"):
                lines.append(f"Corrigido em: {', '.join(vuln.get('fixed_versions'))}")
            validation = vuln.get("validation")
            if isinstance(validation, dict) and validation:
                lines.append(
                    f"Validação: {validation.get('status')} - {validation.get('reason')}"
                )
                if validation.get("reference"):
                    lines.append(f"Referência de validação: {validation.get('reference')}")
                if validation.get("evidence"):
                    lines.append(f"Evidência de validação: {validation.get('evidence')}")
            evidence = str(vuln.get("evidence") or "")
            if len(evidence) > 1500:
                evidence = evidence[:1500] + "\n...[truncated]"
            if evidence:
                lines.extend(["Evidence:", evidence])
            if vuln.get("payload"):
                lines.append(f"Payload: {vuln.get('payload')}")
            if vuln.get("remediation"):
                lines.append(f"Remediation: {vuln.get('remediation')}")
            if vuln.get("references"):
                lines.append("References:")
                lines.extend(f"  - {ref}" for ref in vuln.get("references"))
            lines.extend(["", "-" * 80, ""])

        if info_items:
            lines.extend(["OBSERVAÇÕES", "=" * 80])
            for item in info_items:
                lines.append(f"- {item.get('title')}: {item.get('description')}")
        lines.extend(
            [
                "",
                "Nota: findings marcados como VERSÃO são correspondências OSV, "
                "não prova de explorabilidade.",
                "Gerado por Moodle Security Scanner 2.0.",
            ]
        )
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")

    def _save_sarif(self, path: str) -> None:
        vulnerabilities = self.results.get("vulnerabilities", [])
        rules: Dict[str, Dict[str, Any]] = {}
        results = []
        level_map = {
            "Critical": "error",
            "High": "error",
            "Medium": "warning",
            "Low": "note",
            "Info": "note",
        }
        for vuln in vulnerabilities:
            rule_id = str(vuln.get("cve") or vuln.get("title") or "moodle-finding")
            rule_id = re.sub(r"[^A-Za-z0-9_.:-]+", "-", rule_id)[:120]
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": str(vuln.get("title") or rule_id)[:120],
                    "shortDescription": {"text": str(vuln.get("title") or rule_id)[:200]},
                    "fullDescription": {"text": str(vuln.get("description") or "")[:1000]},
                    "helpUri": _safe_href((vuln.get("references") or [None])[0]),
                    "properties": {
                        "severity": vuln.get("severity"),
                        "cwe": vuln.get("cwe"),
                    },
                },
            )
            results.append(
                {
                    "ruleId": rule_id,
                    "level": level_map.get(str(vuln.get("severity")), "note"),
                    "message": {"text": str(vuln.get("title") or "")},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": str(vuln.get("url") or self.target_url)
                                }
                            }
                        }
                    ],
                    "properties": {
                        "severity": vuln.get("severity"),
                        "confidence": vuln.get("confidence"),
                        "verified": bool(vuln.get("verified")),
                        "source": vuln.get("source"),
                        "evidence_type": vuln.get("evidence_type"),
                        "cve": vuln.get("cve"),
                        "cwe": vuln.get("cwe"),
                        "cvss_score": vuln.get("cvss_score"),
                        "epss": vuln.get("epss"),
                        "kev": bool(vuln.get("kev")),
                        "fixed_versions": vuln.get("fixed_versions") or [],
                        "validation_status": vuln.get("validation_status"),
                        "validation": vuln.get("validation") or {},
                    },
                }
            )

        payload = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Moodle Security Scanner",
                            "version": SCANNER_VERSION,
                            "informationUri": "https://github.com/RuiPVMachado/Moodle-Security-Scanner",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": self.results["scan_info"].get("status") == "complete",
                            "properties": {
                                "target": self.target_url,
                                "version": (self.results.get("version_info") or {}).get("version"),
                                "modules": self.results["scan_info"].get("modules_run", []),
                                "status": self.results["scan_info"].get("status"),
                            },
                        }
                    ],
                }
            ],
        }
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.write("\n")

    # ------------------------------------------------------------------ gate
    def _apply_fail_on(self) -> None:
        threshold_name = getattr(self.args, "fail_on", None)
        if not threshold_name:
            return
        threshold = SEVERITY_ORDER.get(threshold_name)
        if threshold is None:
            return
        triggered = [
            vuln
            for vuln in self.results.get("vulnerabilities", [])
            if SEVERITY_ORDER.get(str(vuln.get("severity")), 999) <= threshold
        ]
        if triggered:
            self.logger.error(
                "Fail-on %s ativado: %s findings atingiram o limiar.",
                threshold_name,
                len(triggered),
            )
            self.exit_code = 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Moodle Security Scanner - evidence-based security testing for Moodle LMS",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-t", "--target", required=True, help="Target Moodle URL")
    parser.add_argument(
        "-m",
        "--modules",
        default=None,
        help="Comma-separated modules or 'all'. Ex.: version,cve,passive,auth,xss",
    )
    parser.add_argument("-o", "--output", help="Report path (.json, .html, .txt, .sarif, .log)")
    parser.add_argument("--proxy", help="HTTP(S) proxy for target requests")
    parser.add_argument("--cookies", help="Cookie string or JSON object")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    parser.add_argument("--delay", type=float, default=0, help="Minimum delay between requests")
    parser.add_argument("--rate-limit", type=float, default=0, help="Maximum requests per second")
    parser.add_argument("--threads", type=int, default=5, help="Concurrent modules (not requests)")
    parser.add_argument("--user-agent", default=None, help="Custom User-Agent")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable TLS verification for the target")
    parser.add_argument(
        "--profile",
        choices=["fast", "balanced", "deep", "external", "all"],
        default="balanced",
        help="Module/payload profile",
    )
    parser.add_argument("--deep", action="store_true", help="Enable deeper/slower active checks")
    parser.add_argument("--authorized", action="store_true", help="Confirm written authorization for active tests")
    parser.add_argument("--no-active", action="store_true", help="Skip xss/sqli/lfi/rce/session modules")
    parser.add_argument(
        "--validate-cves",
        action="store_true",
        help="Run safe, read-only CVE validation checks where available (requires --authorized)",
    )
    parser.add_argument("--offline", action="store_true", help="Use only cached OSV/KEV/EPSS data")
    parser.add_argument("--no-enrich", action="store_true", help="Skip KEV/EPSS enrichment")
    parser.add_argument("--username", help="Username for authenticated checks")
    parser.add_argument("--password", help="Password for authenticated checks")
    parser.add_argument(
        "--test-default-credentials",
        action="store_true",
        help="Opt in to trying a very small default-credential list (can lock accounts)",
    )
    parser.add_argument("--max-tests", type=int, default=0, help="Per-module test budget (0 = profile default)")
    parser.add_argument("--max-response-bytes", type=int, default=2_000_000, help="Response body cap")
    parser.add_argument("--cache-dir", help="Cache directory for OSV/KEV/EPSS data")
    parser.add_argument(
        "--moodle-version",
        help="Override detected Moodle release for CVE matching (e.g. 4.1.11)",
    )
    parser.add_argument("--force", action="store_true", help="Scan even if the target does not look like Moodle")
    parser.add_argument(
        "--fail-on",
        choices=["Critical", "High", "Medium", "Low"],
        default=None,
        help="Exit with code 2 if a finding at/above this severity exists",
    )
    parser.add_argument("--format", choices=["json", "html", "txt", "sarif"], default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Only errors on the console")
    parser.add_argument("--version", action="version", version=f"Moodle Security Scanner {SCANNER_VERSION}")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.verbose and args.quiet:
        print("Error: Cannot use both --verbose and --quiet together")
        sys.exit(1)
    try:
        scanner = MoodleScanner(args)
    except ValueError as exc:
        print(f"Error: {exc}")
        sys.exit(1)
    scanner.run()
    if scanner.exit_code:
        sys.exit(scanner.exit_code)


if __name__ == "__main__":
    main()
