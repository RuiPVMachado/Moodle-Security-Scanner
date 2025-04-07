#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module for testing API endpoint security in Moodle
Part of the Moodle Security Scanner project
"""

import re
import requests
import logging
import time
import random
import string
import json
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
import urllib.parse

class MoodleAPITester:
    """Class for testing API endpoint security in Moodle"""
    
    def __init__(self, target_url, logger=None, timeout=30, proxy=None, cookies=None, delay=0):
        """Initialize the Moodle API tester"""
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
            self.logger = logging.getLogger("MoodleAPITester")
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
        Run all API endpoint security tests
        Returns a dictionary with results information
        """
        self.logger.info("Running API endpoint security tests...")
        
        results = {
            "vulnerabilities": [],
            "info": []
        }
        
        # Discover API endpoints
        endpoints = self.discover_api_endpoints()
        if endpoints:
            endpoints_str = ", ".join(endpoints)
            results["info"].append(f"Discovered API endpoints: {endpoints_str}")
            self.logger.info(f"Discovered {len(endpoints)} API endpoints")
        
        # Test web services API
        webservice_vuln = self.test_webservice_api()
        if webservice_vuln:
            results["vulnerabilities"].append(webservice_vuln)
        
        # Test mobile API
        mobile_vuln = self.test_mobile_api()
        if mobile_vuln:
            results["vulnerabilities"].append(mobile_vuln)
        
        # Test external services access
        ext_services_vuln = self.test_external_services()
        if ext_services_vuln:
            results["vulnerabilities"].append(ext_services_vuln)
        
        # Test token API
        token_vuln = self.test_token_api()
        if token_vuln:
            results["vulnerabilities"].append(token_vuln)
        
        # Test AJAX endpoints
        ajax_vuln = self.test_ajax_endpoints()
        if ajax_vuln:
            results["vulnerabilities"].append(ajax_vuln)
        
        # Test XML-RPC interface
        xmlrpc_vuln = self.test_xmlrpc_interface()
        if xmlrpc_vuln:
            results["vulnerabilities"].append(xmlrpc_vuln)
        
        self.logger.info(f"API endpoint security testing completed. Found {len(results['vulnerabilities'])} vulnerabilities.")
        return results
    
    def discover_api_endpoints(self):
        """
        Discover available API endpoints
        Returns a list of discovered endpoint paths
        """
        self.logger.info("Discovering API endpoints...")
        
        # Common API endpoint paths in Moodle
        common_endpoints = [
            "/webservice/rest/server.php",
            "/webservice/soap/server.php",
            "/webservice/xmlrpc/server.php",
            "/login/token.php",
            "/lib/ajax/service.php",
            "/admin/webservice/service.php",
            "/admin/webservice/service_functions.php",
            "/admin/tool/mobile/launch.php",
            "/mod/lti/auth.php",
            "/mod/lti/launch.php",
            "/auth/oauth2/login.php",
            "/auth/oauth2/issuers.php"
        ]
        
        discovered_endpoints = []
        
        for endpoint in common_endpoints:
            if self.delay > 0:
                time.sleep(self.delay)
            
            try:
                url = f"{self.target_url}{endpoint}"
                response = self.session.get(url, timeout=self.timeout)
                
                # Check if endpoint exists
                if response.status_code not in [404, 403]:
                    self.logger.info(f"Discovered endpoint: {endpoint} (Status: {response.status_code})")
                    discovered_endpoints.append(endpoint)
                    
                    # Store additional information about the endpoint
                    if "FORBIDDEN" in response.text.upper() or "ACCESS DENIED" in response.text.upper():
                        self.logger.debug(f"Endpoint {endpoint} exists but appears to be protected")
                    elif "WEBSERVICE" in response.text.upper() or "API" in response.text.upper():
                        self.logger.debug(f"Endpoint {endpoint} appears to be a web service endpoint")
            except Exception as e:
                self.logger.debug(f"Error accessing endpoint {endpoint}: {str(e)}")
        
        return discovered_endpoints
    
    def test_webservice_api(self):
        """
        Test the Moodle web services API for security issues
        """
        self.logger.info("Testing web services API...")
        
        # Check if web services API is enabled
        api_endpoints = [
            "/webservice/rest/server.php",
            "/webservice/soap/server.php",
            "/webservice/xmlrpc/server.php"
        ]
        
        webservice_enabled = False
        for endpoint in api_endpoints:
            if self.delay > 0:
                time.sleep(self.delay)
            
            try:
                url = f"{self.target_url}{endpoint}"
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    webservice_enabled = True
                    self.logger.info(f"Web services API appears to be enabled at {endpoint}")
                    break
            except Exception as e:
                self.logger.debug(f"Error accessing web services API endpoint {endpoint}: {str(e)}")
        
        if not webservice_enabled:
            self.logger.info("Web services API does not appear to be enabled")
            return None
        
        # Test for information disclosure in web services API
        info_disclosure = self.test_webservice_info_disclosure(api_endpoints)
        if info_disclosure:
            return info_disclosure
        
        # Test for unauthorized access to web services API
        unauth_access = self.test_webservice_unauthorized_access(api_endpoints)
        if unauth_access:
            return unauth_access
        
        return None
    
    def test_webservice_info_disclosure(self, api_endpoints):
        """Test for information disclosure in web services API"""
        self.logger.debug("Testing for information disclosure in web services API...")
        
        for endpoint in api_endpoints:
            if self.delay > 0:
                time.sleep(self.delay)
            
            try:
                # Test different parameter combinations that might trigger error messages
                test_params = [
                    {"wsfunction": "core_course_get_contents"},
                    {"wsfunction": "core_user_get_users"},
                    {"wstoken": "invalid", "wsfunction": "core_course_get_contents"},
                    {"moodlewsrestformat": "json"}
                ]
                
                for params in test_params:
                    url = f"{self.target_url}{endpoint}"
                    response = self.session.get(url, params=params, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        # Check for information disclosure in response
                        # Look for sensitive paths, debug information, or exception traces
                        if re.search(r"(DEBUG|EXCEPTION|STACK TRACE|PHP ERROR|SQL ERROR)", response.text, re.IGNORECASE):
                            self.logger.warning(f"Information disclosure detected in web services API: {endpoint}")
                            
                            # Extract sample of the disclosed information
                            match = re.search(r"(EXCEPTION|STACK TRACE|PHP ERROR|SQL ERROR).*?</", response.text, re.IGNORECASE | re.DOTALL)
                            evidence = match.group(0) if match else "Detailed error information disclosed"
                            
                            return {
                                "title": "Web Services API Information Disclosure",
                                "description": "The Moodle web services API is disclosing sensitive information in error messages.",
                                "severity": "Medium",
                                "evidence": evidence,
                                "endpoint": endpoint,
                                "parameters": str(params),
                                "remediation": "Configure PHP to disable displaying errors and ensure Moodle debugging is set to normal or minimal in production."
                            }
            except Exception as e:
                self.logger.debug(f"Error testing information disclosure for {endpoint}: {str(e)}")
        
        return None
    
    def test_webservice_unauthorized_access(self, api_endpoints):
        """Test for unauthorized access to web services API"""
        self.logger.debug("Testing for unauthorized access to web services API...")
        
        for endpoint in api_endpoints:
            if self.delay > 0:
                time.sleep(self.delay)
            
            try:
                # Test accessing API functions without proper authentication
                test_functions = [
                    "core_course_get_courses",
                    "core_user_get_users",
                    "core_enrol_get_enrolled_users",
                    "mod_forum_get_forum_discussions",
                    "gradereport_user_get_grade_items"
                ]
                
                for func in test_functions:
                    params = {
                        "wsfunction": func,
                        "moodlewsrestformat": "json"
                    }
                    
                    url = f"{self.target_url}{endpoint}"
                    response = self.session.get(url, params=params, timeout=self.timeout)
                    
                    # Check if we got a successful response with data
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            # Check if the response contains actual data and not just an error
                            if isinstance(data, list) and len(data) > 0 and not ("exception" in data or "error" in data):
                                self.logger.warning(f"Unauthorized access to web services API function: {func}")
                                return {
                                    "title": "Web Services API Unauthorized Access",
                                    "description": f"The Moodle web services API allows unauthorized access to functions such as {func}.",
                                    "severity": "High",
                                    "evidence": f"Successfully accessed function {func} without authentication: {response.text[:200]}...",
                                    "endpoint": endpoint,
                                    "function": func,
                                    "remediation": "Configure web services to require authentication and review function permissions in web services settings."
                                }
                        except json.JSONDecodeError:
                            # Not a JSON response, might be XML or another format
                            pass
            except Exception as e:
                self.logger.debug(f"Error testing unauthorized access for {endpoint}: {str(e)}")
        
        return None
    
    def test_mobile_api(self):
        """
        Test the Moodle Mobile API for security issues
        """
        self.logger.info("Testing Mobile API...")
        
        # Check if mobile API is enabled
        mobile_endpoints = [
            "/admin/tool/mobile/launch.php",
            "/lib/ajax/service-nologin.php",
            "/login/token.php"
        ]
        
        mobile_api_enabled = False
        for endpoint in mobile_endpoints:
            if self.delay > 0:
                time.sleep(self.delay)
            
            try:
                url = f"{self.target_url}{endpoint}"
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    mobile_api_enabled = True
                    self.logger.info(f"Mobile API appears to be enabled at {endpoint}")
                    break
            except Exception as e:
                self.logger.debug(f"Error accessing mobile API endpoint {endpoint}: {str(e)}")
        
        if not mobile_api_enabled:
            self.logger.info("Mobile API does not appear to be enabled")
            return None
        
        # Test for information disclosure in mobile API
        token_url = f"{self.target_url}/login/token.php"
        if self.delay > 0:
            time.sleep(self.delay)
        
        try:
            # Test token API with invalid parameters
            params = {
                "username": "admin",
                "password": "invalid",
                "service": "moodle_mobile_app"
            }
            
            response = self.session.get(token_url, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if "error" in data and len(data["error"]) > 50:
                        # Overly verbose error message that might disclose information
                        self.logger.warning("Information disclosure detected in mobile API token endpoint")
                        return {
                            "title": "Mobile API Information Disclosure",
                            "description": "The Moodle mobile API token endpoint is disclosing excessive information in error messages.",
                            "severity": "Medium",
                            "evidence": data["error"],
                            "endpoint": token_url,
                            "remediation": "Configure the mobile API to return generic error messages that don't disclose system information."
                        }
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            self.logger.debug(f"Error testing mobile API token endpoint: {str(e)}")
        
        return None
    
    def test_external_services(self):
        """
        Test Moodle external services configuration for security issues
        """
        self.logger.info("Testing external services configuration...")
        
        # Check external services configuration
        ext_services_url = f"{self.target_url}/admin/webservice/service.php"
        if self.delay > 0:
            time.sleep(self.delay)
        
        try:
            response = self.session.get(ext_services_url, timeout=self.timeout)
            
            if response.status_code == 200 and not "login" in response.url:
                # If we can access this page without being redirected to login, it's a security issue
                self.logger.warning("Unauthorized access to external services configuration")
                return {
                    "title": "External Services Configuration Exposed",
                    "description": "The Moodle external services configuration page is accessible without authentication.",
                    "severity": "Critical",
                    "evidence": "Successfully accessed external services configuration page without authentication",
                    "endpoint": ext_services_url,
                    "remediation": "Configure proper access controls for administration pages and ensure authentication is required."
                }
        except Exception as e:
            self.logger.debug(f"Error testing external services configuration: {str(e)}")
        
        return None
    
    def test_token_api(self):
        """
        Test the Moodle token API for security issues
        """
        self.logger.info("Testing token API...")
        
        token_url = f"{self.target_url}/login/token.php"
        if self.delay > 0:
            time.sleep(self.delay)
        
        try:
            # Test token API with different parameters
            test_params = [
                {"username": "guest", "password": "", "service": "moodle_mobile_app"},
                {"username": "admin", "password": "admin", "service": "moodle_mobile_app"},
                {"username": "admin", "password": "password", "service": "moodle_mobile_app"},
                {"username": "", "password": "", "service": "moodle_mobile_app"}
            ]
            
            for params in test_params:
                if self.delay > 0:
                    time.sleep(self.delay)
                
                response = self.session.get(token_url, params=params, timeout=self.timeout)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        
                        # Check if we got a token
                        if "token" in data and data["token"]:
                            self.logger.warning(f"Successfully obtained API token with credentials: {params['username']}:{params['password']}")
                            return {
                                "title": "Weak Authentication for API Token",
                                "description": "The Moodle token API granted a token with weak or default credentials.",
                                "severity": "Critical",
                                "evidence": f"Successfully obtained token with {params['username']}:{params['password']}",
                                "endpoint": token_url,
                                "credentials": f"{params['username']}:{params['password']}",
                                "remediation": "Change default credentials and implement a strong password policy."
                            }
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            self.logger.debug(f"Error testing token API: {str(e)}")
        
        return None
    
    def test_ajax_endpoints(self):
        """
        Test Moodle AJAX endpoints for security issues
        """
        self.logger.info("Testing AJAX endpoints...")
        
        ajax_endpoints = [
            "/lib/ajax/service.php",
            "/lib/ajax/service-nologin.php",
            "/course/rest.php"
        ]
        
        for endpoint in ajax_endpoints:
            if self.delay > 0:
                time.sleep(self.delay)
            
            try:
                url = f"{self.target_url}{endpoint}"
                
                # Test AJAX endpoint with various payload patterns
                test_payloads = [
                    [{"index": 0, "methodname": "core_course_get_courses", "args": {}}],
                    [{"index": 0, "methodname": "core_user_get_users", "args": {"criteria": [{"key": "email", "value": "%"}]}}],
                    [{"index": 0, "methodname": "core_user_get_users_by_field", "args": {"field": "email", "values": ["%"]}}]
                ]
                
                for payload in test_payloads:
                    if self.delay > 0:
                        time.sleep(self.delay)
                    
                    headers = {"Content-Type": "application/json"}
                    response = self.session.post(url, json=payload, headers=headers, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            
                            # Check if we got data that should require authentication
                            if isinstance(data, list) and len(data) > 0 and "data" in data[0] and not "exception" in data[0]:
                                self.logger.warning(f"Unauthorized access to AJAX endpoint: {endpoint}")
                                return {
                                    "title": "AJAX Endpoint Unauthorized Access",
                                    "description": f"The Moodle AJAX endpoint allows unauthorized access to functions such as {payload[0]['methodname']}.",
                                    "severity": "High",
                                    "evidence": f"Successfully accessed data via AJAX endpoint without authentication: {response.text[:200]}...",
                                    "endpoint": endpoint,
                                    "function": payload[0]['methodname'],
                                    "remediation": "Configure AJAX endpoints to require proper authentication and review function permissions."
                                }
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                self.logger.debug(f"Error testing AJAX endpoint {endpoint}: {str(e)}")
        
        return None
    
    def test_xmlrpc_interface(self):
        """
        Test Moodle XML-RPC interface for security issues
        """
        self.logger.info("Testing XML-RPC interface...")
        
        xmlrpc_url = f"{self.target_url}/webservice/xmlrpc/server.php"
        if self.delay > 0:
            time.sleep(self.delay)
        
        try:
            # Test for XML-RPC interface information disclosure
            # XML-RPC request to list methods (system.listMethods)
            xml_payload = """
            <?xml version="1.0"?>
            <methodCall>
                <methodName>system.listMethods</methodName>
                <params></params>
            </methodCall>
            """
            
            headers = {"Content-Type": "text/xml"}
            response = self.session.post(xmlrpc_url, data=xml_payload, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200 and "<methodResponse>" in response.text:
                # Check if we received method list
                if "<value>system.listMethods</value>" in response.text or "<value>system.</value>" in response.text:
                    self.logger.warning("XML-RPC interface information disclosure detected")
                    
                    # Extract some methods from the response if available
                    methods = []
                    try:
                        root = ET.fromstring(response.text)
                        for value in root.findall(".//value"):
                            if value.text and not value.text.isspace():
                                methods.append(value.text)
                    except:
                        pass
                    
                    methods_str = ", ".join(methods[:5]) + ("..." if len(methods) > 5 else "")
                    
                    return {
                        "title": "XML-RPC Interface Information Disclosure",
                        "description": "The Moodle XML-RPC interface is disclosing available methods, which could help attackers identify vulnerable functions.",
                        "severity": "Medium",
                        "evidence": f"XML-RPC methods disclosed: {methods_str}",
                        "endpoint": xmlrpc_url,
                        "remediation": "Disable the XML-RPC interface if not needed, or ensure proper authentication is required for all method calls."
                    }
        except Exception as e:
            self.logger.debug(f"Error testing XML-RPC interface: {str(e)}")
        
        return None 