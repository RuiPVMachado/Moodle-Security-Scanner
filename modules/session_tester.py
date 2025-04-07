#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module for testing Session Management security in Moodle
Part of the Moodle Security Scanner project
"""

import requests
import logging
import time
from urllib.parse import urlparse
from bs4 import BeautifulSoup

class MoodleSessionTester:
    """Class for testing Session Management vulnerabilities in Moodle"""
    
    def __init__(self, target_url, logger=None, timeout=30, proxy=None, cookies=None, delay=0):
        """Initialize the Moodle Session tester"""
        self.target_url = target_url
        self.timeout = timeout
        self.proxy = proxy
        self.initial_cookies = cookies.copy() if cookies else {}
        self.delay = delay
        self.version_info = None
        
        # Set up logging
        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger("MoodleSessionTester")
            self.logger.setLevel(logging.INFO)
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        
        # Initialize HTTP session
        self.session = requests.Session()
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        if self.initial_cookies:
            self.session.cookies.update(self.initial_cookies)

    def set_version_info(self, version_info):
        """Set version information to guide testing"""
        self.version_info = version_info

    def run_tests(self):
        """
        Run all Session Management tests
        Returns a dictionary with results information
        """
        self.logger.info("Running Session Management security tests...")
        
        results = {
            "vulnerabilities": [],
            "info": []
        }
        
        # Test cookie security attributes
        cookie_vulns = self.test_cookie_attributes()
        if cookie_vulns:
            results["vulnerabilities"].extend(cookie_vulns)
            
        # Test for Session Fixation (if credentials provided)
        # Note: This specific test was moved from auth_tester to here
        fixation_vuln = self.test_session_fixation()
        if fixation_vuln:
            results["vulnerabilities"].append(fixation_vuln)
            
        # Test for CSRF Protection in Session Handling (placeholder)
        csrf_info = self.test_csrf_protection()
        if csrf_info:
            results["info"].extend(csrf_info)
            
        # Check for HTTPS Usage
        https_info = self.check_https_usage()
        if https_info:
            results["info"].append(https_info)

        self.logger.info("Session Management tests completed.")
        return results

    def test_cookie_attributes(self):
        """Test for secure attributes on session cookies"""
        self.logger.info("Testing session cookie attributes (HttpOnly, Secure, SameSite)...")
        vulnerabilities = []
        
        try:
            # Make a request to get session cookies
            response = self.session.get(self.target_url, timeout=self.timeout)
            
            if self.delay > 0:
                time.sleep(self.delay)
                
            # Check cookies set by the server
            for cookie in self.session.cookies:
                if 'MoodleSession' in cookie.name:  # Focus on the main session cookie
                    
                    # Check Secure flag (only if HTTPS)
                    parsed_url = urlparse(self.target_url)
                    if parsed_url.scheme == 'https' and not cookie.secure:
                        self.logger.warning(f"Session cookie '{cookie.name}' missing Secure flag.")
                        vulnerabilities.append({
                            "title": "Session Cookie Missing Secure Flag",
                            "description": f"The session cookie '{cookie.name}' is missing the Secure flag. It could be transmitted over unencrypted HTTP.",
                            "severity": "Medium",
                            "evidence": f"Cookie: {cookie.name}",
                            "remediation": "Ensure the Moodle configuration ($CFG->cookiesecure) is set to true and the site enforces HTTPS."
                        })
                        
                    # Check HttpOnly flag
                    if not cookie.has_nonstandard_attr('HttpOnly') and not getattr(cookie, 'rfc2109', False): # Heuristic check
                         # A more robust check might involve inspecting raw Set-Cookie headers
                         # requests.cookies doesn't directly expose HttpOnly easily
                         self.logger.warning(f"Session cookie '{cookie.name}' potentially missing HttpOnly flag (heuristic check).")
                         vulnerabilities.append({
                             "title": "Session Cookie Potentially Missing HttpOnly Flag",
                             "description": f"The session cookie '{cookie.name}' appears to be missing the HttpOnly flag. It might be accessible via client-side scripts (XSS).",
                             "severity": "Medium",
                             "evidence": f"Cookie: {cookie.name}. Note: This check is based on heuristics.",
                             "remediation": "Ensure the Moodle configuration ($CFG->cookiehttponly) is set to true."
                         })

                    # Check SameSite attribute (needs raw header inspection, requests lib doesn't parse it well)
                    # This part is complex without direct header access or a different library
                    # We can add a note about checking it manually
                    self.logger.info(f"Manual check recommended for SameSite attribute on '{cookie.name}' cookie.")
                    # info.append({
                    #     "title": "Manual Check Recommended for SameSite Attribute",
                    #     "description": f"The presence and value (Lax/Strict) of the SameSite attribute on the '{cookie.name}' cookie should be checked manually using browser developer tools.",
                    #     "severity": "Info"
                    # })

        except Exception as e:
            self.logger.error(f"Error testing cookie attributes: {str(e)}")
            
        return vulnerabilities

    def test_session_fixation(self):
        """Test for session fixation vulnerabilities (Requires username/password)"""
        # This test requires authentication details which might not be available here
        # It was previously in auth_tester. We'll replicate the logic but need credentials.
        
        # Check if credentials were provided during scanner initialization (passed via cookies perhaps?)
        # A proper implementation would need access to the username/password args passed to the main scanner.
        # For now, this will be a placeholder unless we refactor how credentials are passed.
        
        self.logger.info("Skipping Session Fixation test - requires authentication context not directly available in this module.")
        # If we had username/password:
        # 1. Make request to login page, get pre-login MoodleSession cookie
        # 2. Post login credentials
        # 3. Check if MoodleSession cookie is the same post-login. If so, it's vulnerable.
        return None # Placeholder

    def test_csrf_protection(self):
        """Check for basic CSRF protection mechanisms related to sessions (e.g., sesskey)"""
        self.logger.info("Checking for presence of CSRF tokens (sesskey) in forms...")
        info_items = []
        
        try:
            # Access a page that likely has forms requiring CSRF protection (e.g., profile edit)
            profile_url = f"{self.target_url}/user/edit.php" # Needs authentication
            response = self.session.get(profile_url, timeout=self.timeout)
            
            if self.delay > 0:
                time.sleep(self.delay)

            if response.status_code == 200 and "login" not in response.url:
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                found_sesskey = False
                for form in forms:
                    if form.find('input', {'name': 'sesskey'}):
                        found_sesskey = True
                        break
                
                if found_sesskey:
                    self.logger.info("Found forms with 'sesskey' parameter, indicating CSRF protection.")
                    info_items.append({
                        "title": "CSRF Protection (sesskey) Found",
                        "description": "Forms were found containing the 'sesskey' parameter, which is Moodle's primary CSRF protection mechanism.",
                        "severity": "Info"
                    })
                else:
                     self.logger.warning("Could not find 'sesskey' in forms on profile page. CSRF protection might be weak or missing.")
                     # This could be a finding, but needs context (maybe no forms expected?)
                     info_items.append({
                         "title": "CSRF Token (sesskey) Potentially Missing",
                         "description": "Could not find 'sesskey' input fields in forms on the checked page(s). Review CSRF protection implementation.",
                         "severity": "Info" # Low/Medium if confirmed lack of protection
                     })
            elif "login" in response.url:
                 self.logger.info("Skipping CSRF check - not authenticated.")
            else:
                 self.logger.debug(f"Could not access profile page (status {response.status_code}) for CSRF check.")

        except Exception as e:
            self.logger.error(f"Error testing CSRF protection: {str(e)}")
            
        return info_items
        
    def check_https_usage(self):
        """Check if the target URL is using HTTPS"""
        self.logger.info("Checking if target URL uses HTTPS...")
        parsed_url = urlparse(self.target_url)
        if parsed_url.scheme != 'https':
            self.logger.warning("Target URL is not using HTTPS. Session cookies could be transmitted insecurely.")
            return {
                "title": "HTTPS Not Used",
                "description": "The target Moodle site is accessed via HTTP, not HTTPS. Session data is vulnerable to interception.",
                "severity": "High", # Often considered High because it compromises session integrity
                "remediation": "Configure the web server to enforce HTTPS for the entire Moodle site."
            }
        else:
            self.logger.info("Target URL uses HTTPS.")
            return None # No issue found here 