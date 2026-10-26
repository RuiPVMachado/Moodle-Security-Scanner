#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Passive security checks that do not exploit the target.

These checks are intentionally conservative: a finding is emitted only when
the response itself proves the condition (missing header, exposed backup file,
source disclosure, weak cookie attribute).  No payload is sent to Moodle
business logic.
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import time
from http.cookies import SimpleCookie
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from modules.http import SecureSession, build_session

_COMMON_COOKIE_NAMES = ("MoodleSession", "MOODLEID", "MoodleSessionTest")


class MoodlePassiveTester:
    """Header, cookie and exposed-file checks with low false-positive risk."""

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
        session: Optional[SecureSession] = None,
        max_response_bytes: int = 2_000_000,
        **_: Any,
    ) -> None:
        self.target_url = target_url.rstrip("/") + "/"
        self.logger = logger or logging.getLogger("MoodlePassiveTester")
        self.timeout = timeout
        self.session = session or build_session(
            verify_ssl=verify_ssl,
            timeout=timeout,
            user_agent=user_agent,
            proxy=proxy,
            cookies=cookies,
            max_response_bytes=max_response_bytes,
        )

    def run_tests(self) -> Dict[str, List[Dict[str, Any]]]:
        results: Dict[str, List[Dict[str, Any]]] = {"vulnerabilities": [], "info": []}
        homepage = self._get(self.target_url)
        if homepage is None:
            return results

        self._check_transport(homepage, results)
        self._check_tls(results)
        self._check_headers(homepage, results)
        self._check_cookies(homepage, results)
        self._check_admin_exposure(results)
        self._check_exposed_files(results)
        self._check_directory_listing(results)
        self._check_debug_exposure(results)
        self._check_security_txt(results)
        return results

    # ------------------------------------------------------------------ helpers
    def _get(self, url: str, *, allow_redirects: bool = True):
        try:
            return self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
            )
        except Exception as exc:
            self.logger.debug("Erro passivo em %s: %s", url, exc)
            return None

    @staticmethod
    def _finding(
        *,
        title: str,
        description: str,
        severity: str,
        evidence: str,
        remediation: str,
        url: str,
        cwe: Optional[str] = None,
        confidence: str = "high",
        references: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        return {
            "title": title,
            "description": description,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence,
            "url": url,
            "remediation": remediation,
            "cwe": cwe,
            "references": references or [],
            "verified": True,
            "source": "passive",
            "evidence_type": "passive",
        }

    # ------------------------------------------------------------------- checks
    def _check_transport(self, response, results: Dict[str, List[Dict[str, Any]]]) -> None:
        parsed = urlparse(self.target_url)
        if parsed.scheme != "https":
            results["vulnerabilities"].append(
                self._finding(
                    title="Site Moodle servido sem HTTPS",
                    description=(
                        "O alvo é acessível por HTTP. Credenciais, cookies de sessão "
                        "e conteúdo podem ser interceptados ou alterados em trânsito."
                    ),
                    severity="High",
                    evidence=f"URL base: {self.target_url}",
                    remediation=(
                        "Forçar HTTPS no servidor web, ativar $CFG->wwwroot com https:// "
                        "e configurar HSTS."
                    ),
                    url=self.target_url,
                    cwe="CWE-319",
                )
            )

    def _check_tls(self, results: Dict[str, List[Dict[str, Any]]]) -> None:
        parsed = urlparse(self.target_url)
        if parsed.scheme != "https" or not parsed.hostname:
            return
        host = parsed.hostname
        port = parsed.port or 443
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=min(self.timeout, 15)) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    certificate = tls.getpeercert()
                    version = tls.version()
        except ssl.SSLCertVerificationError as exc:
            message = str(exc)
            lowered = message.lower()
            if "expired" in lowered:
                title = "Certificado TLS expirado"
                reason = "O certificado apresentado pelo servidor expirou."
            elif "hostname mismatch" in lowered or "doesn't match" in lowered:
                title = "Certificado TLS não corresponde ao host"
                reason = "O nome no certificado não corresponde ao hostname do alvo."
            else:
                title = "Certificado TLS não confiável"
                reason = (
                    "O certificado não foi validado por uma CA confiável (self-signed, "
                    "CA privada ou cadeia incompleta)."
                )
            results["vulnerabilities"].append(
                self._finding(
                    title=title,
                    description=reason,
                    severity="High",
                    evidence=message[:700],
                    remediation=(
                        "Instalar um certificado válido de uma CA confiável, renovar "
                        "antes da expiração e servir a cadeia completa."
                    ),
                    url=self.target_url,
                    cwe="CWE-295",
                )
            )
            return
        except (socket.error, ssl.SSLError, OSError) as exc:
            self.logger.debug("TLS check falhou: %s", exc)
            return

        if version in {"TLSv1", "TLSv1.1"}:
            results["vulnerabilities"].append(
                self._finding(
                    title=f"Versão TLS antiga: {version}",
                    description="O servidor aceita uma versão TLS obsoleta.",
                    severity="Medium",
                    evidence=f"Negociação TLS: {version}",
                    remediation="Desativar TLS 1.0/1.1 e exigir TLS 1.2+.",
                    url=self.target_url,
                    cwe="CWE-326",
                )
            )

        not_after = str((certificate or {}).get("notAfter") or "")
        if not not_after:
            return
        try:
            expiry = ssl.cert_time_to_seconds(not_after)
            days = (expiry - time.time()) / 86400
        except (TypeError, ValueError):
            return
        if days < 0:
            results["vulnerabilities"].append(
                self._finding(
                    title="Certificado TLS expirado",
                    description="O certificado TLS já expirou.",
                    severity="High",
                    evidence=f"notAfter={not_after}",
                    remediation="Renovar o certificado imediatamente.",
                    url=self.target_url,
                    cwe="CWE-295",
                )
            )
        elif days < 30:
            results["vulnerabilities"].append(
                self._finding(
                    title="Certificado TLS expira em breve",
                    description="O certificado TLS expira em menos de 30 dias.",
                    severity="Medium",
                    evidence=f"notAfter={not_after} ({days:.1f} dias)",
                    remediation="Renovar o certificado e automatizar a renovação.",
                    url=self.target_url,
                    cwe="CWE-295",
                )
            )

    def _check_headers(self, response, results: Dict[str, List[Dict[str, Any]]]) -> None:
        headers = {key.lower(): value for key, value in response.headers.items()}
        https = urlparse(self.target_url).scheme == "https"

        if https and "strict-transport-security" not in headers:
            results["vulnerabilities"].append(
                self._finding(
                    title="HSTS não configurado",
                    description=(
                        "A resposta não inclui Strict-Transport-Security. Um atacante "
                        "em rede pode forçar downgrade para HTTP."
                    ),
                    severity="Medium",
                    evidence="Header Strict-Transport-Security ausente.",
                    remediation="Adicionar Strict-Transport-Security com max-age adequado.",
                    url=self.target_url,
                    cwe="CWE-319",
                )
            )

        csp = headers.get("content-security-policy", "")
        xfo = headers.get("x-frame-options", "")
        if not csp and not xfo:
            results["vulnerabilities"].append(
                self._finding(
                    title="Proteção contra clickjacking ausente",
                    description=(
                        "Não existe X-Frame-Options nem uma diretiva frame-ancestors "
                        "na Content-Security-Policy."
                    ),
                    severity="Medium",
                    evidence="X-Frame-Options ausente e CSP sem frame-ancestors.",
                    remediation=(
                        "Definir X-Frame-Options: SAMEORIGIN ou CSP frame-ancestors 'self'."
                    ),
                    url=self.target_url,
                    cwe="CWE-1021",
                )
            )

        if "x-content-type-options" not in headers:
            results["vulnerabilities"].append(
                self._finding(
                    title="X-Content-Type-Options ausente",
                    description="O browser pode fazer MIME sniffing de respostas.",
                    severity="Low",
                    evidence="Header X-Content-Type-Options ausente.",
                    remediation="Adicionar X-Content-Type-Options: nosniff.",
                    url=self.target_url,
                    cwe="CWE-693",
                )
            )

        if "referrer-policy" not in headers:
            results["info"].append(
                {
                    "title": "Referrer-Policy não definida",
                    "description": "O header Referrer-Policy não está presente.",
                    "severity": "Info",
                    "evidence": "Header Referrer-Policy ausente.",
                    "url": self.target_url,
                    "verified": True,
                    "source": "passive",
                    "evidence_type": "passive",
                }
            )

    def _check_cookies(self, response, results: Dict[str, List[Dict[str, Any]]]) -> None:
        login = self._get(self.target_url + "login/index.php")
        responses = [response] + ([login] if login is not None and login is not response else [])
        seen = set()

        for item in responses:
            for header in self._set_cookie_headers(item):
                cookie = SimpleCookie()
                try:
                    cookie.load(header)
                except Exception:
                    continue
                for name, morsel in cookie.items():
                    if not any(name.startswith(prefix) for prefix in _COMMON_COOKIE_NAMES):
                        continue
                    key = (name, header)
                    if key in seen:
                        continue
                    seen.add(key)

                    if urlparse(self.target_url).scheme == "https" and not morsel["secure"]:
                        results["vulnerabilities"].append(
                            self._finding(
                                title=f"Cookie de sessão sem Secure: {name}",
                                description=(
                                    "O cookie de sessão pode ser enviado por HTTP se o "
                                    "site permitir esse transporte."
                                ),
                                severity="Medium",
                                evidence=header[:500],
                                remediation=(
                                    "Definir $CFG->cookiesecure = true e forçar HTTPS."
                                ),
                                url=self.target_url,
                                cwe="CWE-614",
                            )
                        )
                    if not morsel["httponly"]:
                        results["vulnerabilities"].append(
                            self._finding(
                                title=f"Cookie de sessão sem HttpOnly: {name}",
                                description=(
                                    "O cookie pode ser lido por JavaScript; uma falha XSS "
                                    "passa a permitir roubo de sessão."
                                ),
                                severity="Medium",
                                evidence=header[:500],
                                remediation="Definir $CFG->cookiehttponly = true.",
                                url=self.target_url,
                                cwe="CWE-1004",
                            )
                        )
                    if not morsel["samesite"]:
                        results["vulnerabilities"].append(
                            self._finding(
                                title=f"Cookie de sessão sem SameSite: {name}",
                                description="O cookie não declara uma política SameSite.",
                                severity="Low",
                                evidence=header[:500],
                                remediation="Definir SameSite=Lax ou Strict quando possível.",
                                url=self.target_url,
                                cwe="CWE-1275",
                            )
                        )

    @staticmethod
    def _set_cookie_headers(response) -> List[str]:
        headers: List[str] = []
        raw = getattr(response, "raw", None)
        raw_headers = getattr(raw, "headers", None)
        if raw_headers is not None:
            try:
                headers.extend(raw_headers.getlist("Set-Cookie"))
            except (AttributeError, TypeError):
                value = raw_headers.get("Set-Cookie")
                if value:
                    headers.append(value)
        if not headers:
            value = response.headers.get("Set-Cookie")
            if value:
                headers.append(value)
        return [header for header in headers if header]

    def _check_admin_exposure(self, results: Dict[str, List[Dict[str, Any]]]) -> None:
        checks = (
            (
                "admin/index.php",
                ("site administration",),
                "Critical",
                "Área de administração acessível sem autenticação",
            ),
            (
                "report/security/index.php",
                ("security overview", "security checks"),
                "High",
                "Relatório de segurança acessível sem autenticação",
            ),
            (
                "admin/plugins.php",
                ("plugin overview",),
                "Medium",
                "Lista de plugins acessível sem autenticação",
            ),
        )
        for path, signatures, severity, title in checks:
            url = self.target_url + path
            response = self._get(url)
            if response is None or response.status_code != 200:
                continue
            final_url = (response.url or "").lower()
            body = (response.text or "").lower()
            if "/login/" in final_url or "logintoken" in body:
                continue
            if 'type="password"' in body or 'name="password"' in body:
                continue
            if not any(signature in body for signature in signatures):
                continue
            results["vulnerabilities"].append(
                self._finding(
                    title=title,
                    description=(
                        "Uma página administrativa do Moodle respondeu com o "
                        "conteúdo esperado sem pedir autenticação."
                    ),
                    severity=severity,
                    evidence=f"GET {url} devolveu {signatures[0]!r} sem login.",
                    remediation=(
                        "Exigir autenticação e capacidades administrativas; rever "
                        "regras do servidor web/proxy que possam contornar o login."
                    ),
                    url=url,
                    cwe="CWE-306",
                )
            )

    def _check_exposed_files(self, results: Dict[str, List[Dict[str, Any]]]) -> None:
        backups = ("config.php.bak", "config.php~", "config.php.old", "config.php.save")
        for name in backups:
            response = self._get(self.target_url + name, allow_redirects=False)
            if response is None or response.status_code != 200:
                continue
            body = response.text or ""
            if "<?php" in body and ("$CFG" in body or "dbtype" in body or "dbuser" in body):
                results["vulnerabilities"].append(
                    self._finding(
                        title="Backup de config.php exposto",
                        description=(
                            "Um ficheiro de backup da configuração do Moodle está "
                            "publicamente acessível e pode conter credenciais da base de dados."
                        ),
                        severity="Critical",
                        evidence=(
                            f"GET {self.target_url + name} devolveu código PHP "
                            "de configuração."
                        ),
                        remediation=(
                            "Remover o ficheiro do web root, rodar credenciais da base de dados "
                            "e procurar outros backups."
                        ),
                        url=self.target_url + name,
                        cwe="CWE-538",
                    )
                )

        for name in (".env", ".env.local", ".env.production"):
            response = self._get(self.target_url + name, allow_redirects=False)
            if response is None or response.status_code != 200:
                continue
            body = response.text or ""
            if any(key in body for key in ("DB_PASSWORD", "DB_USER", "APP_KEY", "MOODLE_")):
                results["vulnerabilities"].append(
                    self._finding(
                        title=f"Ficheiro de ambiente exposto: {name}",
                        description=(
                            "Um ficheiro .env está público e pode conter credenciais "
                            "da base de dados, chaves ou segredos de aplicação."
                        ),
                        severity="Critical",
                        evidence=f"GET {self.target_url + name} devolveu variáveis de ambiente.",
                        remediation=(
                            "Remover o ficheiro do web root, rodar todos os segredos "
                            "expostos e bloquear ficheiros .env no servidor web."
                        ),
                        url=self.target_url + name,
                        cwe="CWE-538",
                    )
                )

        for name in ("backup.sql", "dump.sql", "database.sql", "moodle.sql"):
            response = self._get(self.target_url + name, allow_redirects=False)
            if response is None or response.status_code != 200:
                continue
            body = (response.text or "")[:200_000]
            upper = body.upper()
            if "CREATE TABLE" in upper and "INSERT INTO" in upper:
                results["vulnerabilities"].append(
                    self._finding(
                        title=f"Dump SQL exposto: {name}",
                        description=(
                            "Um dump da base de dados está publicamente acessível. "
                            "Pode conter hashes de passwords, dados pessoais e configuração."
                        ),
                        severity="Critical",
                        evidence=f"GET {self.target_url + name} devolveu CREATE TABLE/INSERT INTO.",
                        remediation=(
                            "Remover o dump do web root, rodar credenciais e notificar "
                            "os responsáveis de proteção de dados."
                        ),
                        url=self.target_url + name,
                        cwe="CWE-538",
                    )
                )

        htpasswd = self._get(self.target_url + ".htpasswd", allow_redirects=False)
        if htpasswd is not None and htpasswd.status_code == 200:
            if re.search(r":(?:\$apr1\$|\{SHA\}|\$2[aby]\$)", htpasswd.text or ""):
                results["vulnerabilities"].append(
                    self._finding(
                        title=".htpasswd exposto",
                        description="O ficheiro de passwords HTTP está acessível e contém hashes.",
                        severity="High",
                        evidence=f"GET {self.target_url}.htpasswd devolveu hashes.",
                        remediation="Remover o ficheiro do web root e rodar as passwords.",
                        url=self.target_url + ".htpasswd",
                        cwe="CWE-538",
                    )
                )

        for name in ("error_log", "php_error.log", "debug.log"):
            response = self._get(self.target_url + name, allow_redirects=False)
            if response is None or response.status_code != 200:
                continue
            body = response.text or ""
            markers = ("PHP Fatal error", "PHP Warning", "PHP Parse error")
            if any(marker in body for marker in markers):
                results["vulnerabilities"].append(
                    self._finding(
                        title=f"Log de erros PHP exposto: {name}",
                        description=(
                            "Um log de erros está público e pode revelar "
                            "caminhos e dados internos."
                        ),
                        severity="Medium",
                        evidence=f"GET {self.target_url + name} devolveu mensagens PHP.",
                        remediation="Mover logs para fora do web root e restringir o acesso.",
                        url=self.target_url + name,
                        cwe="CWE-532",
                    )
                )

        git_head = self._get(self.target_url + ".git/HEAD", allow_redirects=False)
        if git_head is not None and git_head.status_code == 200:
            body = git_head.text or ""
            if body.startswith("ref:") or re.search(r"^[0-9a-f]{40}$", body.strip()):
                results["vulnerabilities"].append(
                    self._finding(
                        title="Repositório Git exposto",
                        description=(
                            "O diretório .git está acessível e pode permitir "
                            "reconstruir o código-fonte."
                        ),
                        severity="High",
                        evidence=(
                            f"GET {self.target_url}.git/HEAD devolveu: "
                            f"{body.strip()[:120]}"
                        ),
                        remediation=(
                            "Bloquear o acesso a /.git/ no servidor web e "
                            "remover o diretório."
                        ),
                        url=self.target_url + ".git/HEAD",
                        cwe="CWE-538",
                    )
                )

        for name in ("phpinfo.php", "info.php", "test.php"):
            response = self._get(self.target_url + name, allow_redirects=False)
            if response is None or response.status_code != 200:
                continue
            body = response.text or ""
            if (
                "PHP Version" in body
                or "phpinfo()" in body
                or "Configuration File (php.ini)" in body
            ):
                results["vulnerabilities"].append(
                    self._finding(
                        title="phpinfo() exposto",
                        description=(
                            "Uma página phpinfo revela configuração, caminhos "
                            "e módulos do PHP."
                        ),
                        severity="High",
                        evidence=(
                            f"GET {self.target_url + name} devolveu uma "
                            "página phpinfo."
                        ),
                        remediation=(
                            "Remover o ficheiro e bloquear páginas de "
                            "diagnóstico em produção."
                        ),
                        url=self.target_url + name,
                        cwe="CWE-200",
                    )
                )

        for name, signature, severity, title in (
            ("adminer.php", "Adminer", "High", "Adminer exposto"),
            ("phpmyadmin/", "phpMyAdmin", "Medium", "phpMyAdmin exposto"),
        ):
            response = self._get(self.target_url + name, allow_redirects=False)
            if response is None or response.status_code != 200:
                continue
            if signature.lower() in (response.text or "").lower():
                results["vulnerabilities"].append(
                    self._finding(
                        title=title,
                        description=(
                            "Uma ferramenta de administração de base de dados "
                            "está acessível."
                        ),
                        severity=severity,
                        evidence=f"GET {self.target_url + name} devolveu {signature}.",
                        remediation="Restringir por IP/autenticação ou remover a ferramenta.",
                        url=self.target_url + name,
                        cwe="CWE-284",
                    )
                )

        metadata_files = {
            "README.txt": "Moodle",
            "lib/upgrade.txt": "Moodle",
            "composer.lock": '"packages"',
            "admin/environment.xml": "<COMPATIBILITY_MATRIX>",
        }
        for name, signature in metadata_files.items():
            response = self._get(self.target_url + name, allow_redirects=False)
            if response is None or response.status_code != 200:
                continue
            body = response.text or ""
            if signature.lower() not in body.lower():
                continue
            results["info"].append(
                {
                    "title": f"Ficheiro de metadados exposto: {name}",
                    "description": (
                        "O ficheiro é público e pode ajudar a identificar a versão exata "
                        "ou dependências do Moodle."
                    ),
                    "severity": "Info",
                    "evidence": f"GET {self.target_url + name} devolveu conteúdo reconhecível.",
                    "url": self.target_url + name,
                    "verified": True,
                    "source": "passive",
                    "evidence_type": "passive",
                }
            )

    def _check_directory_listing(self, results: Dict[str, List[Dict[str, Any]]]) -> None:
        for path in ("lib/", "mod/", "blocks/", "theme/", "backup/", "files/", "temp/"):
            response = self._get(self.target_url + path, allow_redirects=False)
            if response is None or response.status_code != 200:
                continue
            if "Index of /" in (response.text or ""):
                results["vulnerabilities"].append(
                    self._finding(
                        title=f"Directory listing ativo em /{path}",
                        description="O servidor lista o conteúdo do diretório.",
                        severity="Medium",
                        evidence=f"GET {self.target_url + path} devolveu 'Index of /'.",
                        remediation="Desativar Options -Indexes / autoindex no servidor web.",
                        url=self.target_url + path,
                        cwe="CWE-548",
                    )
                )

    def _check_debug_exposure(self, results: Dict[str, List[Dict[str, Any]]]) -> None:
        probe = self.target_url + "mss-nonexistent-" + "a1b2c3d4"
        response = self._get(probe, allow_redirects=False)
        if response is None:
            return
        body = response.text or ""
        patterns = (
            r"Fatal error\s*:",
            r"Uncaught\s+",
            r"Stack trace\s*:",
            r"You have an error in your SQL syntax",
            r"Warning\s*:\s*mysqli",
            r"Debug info\s*:",
        )
        if not any(re.search(pattern, body, re.IGNORECASE) for pattern in patterns):
            return
        severity = "Medium" if response.status_code >= 500 else "Low"
        results["vulnerabilities"].append(
            self._finding(
                title="Mensagens de debug expostas",
                description=(
                    "A resposta de erro contém detalhes internos do PHP/Moodle. "
                    "Isto pode revelar caminhos, SQL e stack traces."
                ),
                severity=severity,
                evidence=f"HTTP {response.status_code} em {probe} com detalhes de erro.",
                remediation=(
                    "Desativar display_errors e Moodle debugging em produção; "
                    "rever o tratamento de erros."
                ),
                url=probe,
                cwe="CWE-209",
                confidence="medium",
            )
        )

    def _check_security_txt(self, results: Dict[str, List[Dict[str, Any]]]) -> None:
        for path in (".well-known/security.txt", "security.txt"):
            response = self._get(self.target_url + path, allow_redirects=False)
            if response is None or response.status_code != 200:
                continue
            if "Contact:" in (response.text or ""):
                results["info"].append(
                    {
                        "title": "security.txt encontrado",
                        "description": "O site publica um ficheiro security.txt.",
                        "severity": "Info",
                        "evidence": f"GET {self.target_url + path} devolveu Contact:.",
                        "url": self.target_url + path,
                        "verified": True,
                        "source": "passive",
                        "evidence_type": "passive",
                    }
                )
                return
