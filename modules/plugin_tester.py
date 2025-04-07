#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module for testing Moodle Plugin security
Part of the Moodle Security Scanner project
"""

import re
import requests
import logging
import time
from bs4 import BeautifulSoup
import json
import os

class MoodlePluginTester:
    """Class for testing vulnerabilities in Moodle Plugins"""
    
    def __init__(self, target_url, logger=None, timeout=30, proxy=None, cookies=None, delay=0):
        """Initialize the Moodle Plugin tester"""
        self.target_url = target_url
        self.timeout = timeout
        self.proxy = proxy
        self.cookies = cookies
        self.delay = delay
        self.version_info = None
        self.installed_plugins = [] # Store detected plugins
        self.vulnerable_plugin_db = self._load_vulnerable_plugin_db()
        
        # Set up logging
        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger("MoodlePluginTester")
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

    def _load_vulnerable_plugin_db(self):
        """Load known vulnerable plugin information from a file"""
        db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'vulnerable_plugins.json') # Adjust path as needed
        try:
            with open(db_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            self.logger.warning(f"Vulnerable plugin database not found at {db_path}. Plugin vulnerability checks will be limited.")
            return {}
        except json.JSONDecodeError:
             self.logger.error(f"Error decoding vulnerable plugin database at {db_path}.")
             return {}

    def set_version_info(self, version_info):
        """Set version information to guide testing"""
        self.version_info = version_info

    def run_tests(self):
        """
        Run all Plugin security tests
        Returns a dictionary with results information including detected plugins
        """
        self.logger.info("Running Moodle Plugin security tests...")
        
        results = {
            "vulnerabilities": [],
            "info": [],
            "plugins_detected": []
        }
        
        # Step 1: Detect installed plugins
        detected_plugins = self.detect_installed_plugins()
        if detected_plugins:
            self.installed_plugins = detected_plugins
            results["plugins_detected"] = [p['name'] for p in detected_plugins]
            results["info"].append({
                "title": "Detected Plugins",
                "description": f"Detected {len(detected_plugins)} potential plugins: {', '.join(results['plugins_detected'])}",
                "severity": "Info"
            })
        else:
             self.logger.info("Could not detect installed plugins.")
             results["info"].append({
                 "title": "Plugin Detection Failed",
                 "description": "Could not reliably detect installed plugins.",
                 "severity": "Info"
             })
             return results # Stop if we can't detect plugins
             
        # Step 2: Check detected plugins against known vulnerabilities
        known_vulns = self.check_known_vulnerabilities()
        if known_vulns:
            results["vulnerabilities"].extend(known_vulns)
            
        # Step 3: Test for common plugin misconfigurations or weaknesses (Placeholder)
        # E.g., check for default credentials in specific plugins, exposed sensitive paths
        config_vulns = self.test_plugin_misconfigurations()
        if config_vulns:
             results["vulnerabilities"].extend(config_vulns)

        self.logger.info("Plugin security tests completed.")
        return results

    def detect_installed_plugins(self):
        """Attempt to detect installed plugins by probing common paths and checking admin pages"""
        self.logger.info("Attempting to detect installed plugins...")
        detected = []
        checked_paths = set()

        # Common base paths for different types of plugins
        plugin_base_paths = [
            ("mod", "Activity Modules", "/mod/"),
            ("blocks", "Blocks", "/blocks/"),
            ("filter", "Filters", "/filter/"),
            ("theme", "Themes", "/theme/"),
            ("report", "Reports", "/report/"),
            ("local", "Local Plugins", "/local/"),
            ("admin/tool", "Admin Tools", "/admin/tool/"),
            ("repository", "Repositories", "/repository/"),
            ("auth", "Authentication Plugins", "/auth/"),
            ("enrol", "Enrolment Plugins", "/enrol/"),
            ("grade/export", "Grade Exports", "/grade/export/"),
            ("grade/import", "Grade Imports", "/grade/import/"),
            ("grade/report", "Grade Reports", "/grade/report/"),
            ("message/output", "Message Outputs", "/message/output/"),
            ("question/type", "Question Types", "/question/type/"),
            ("plagiarism", "Plagiarism Plugins", "/plagiarism/"),
            # Add more common plugin type paths if needed
        ]

        # Method 1: Probe common plugin directories
        for ptype, desc, base_path in plugin_base_paths:
            if self.delay > 0:
                time.sleep(self.delay)
                
            list_url = f"{self.target_url}{base_path}"
            try:
                response = self.session.get(list_url, timeout=self.timeout)
                if response.status_code == 200 and "Index of" not in response.text: # Avoid simple directory listing pages
                    soup = BeautifulSoup(response.text, 'html.parser')
                    # Look for links pointing to subdirectories within the base path
                    for link in soup.find_all('a'):
                        href = link.get('href', '')
                        # Basic check: does the link start with the base path or contain it?
                        if base_path in href:
                            # Try to extract the plugin name
                            match = re.search(f"{re.escape(base_path)}([a-zA-Z0-9_]+)/?", href)
                            if match:
                                plugin_name = match.group(1)
                                plugin_full_path = f"{base_path}{plugin_name}"
                                if plugin_name not in ['admin', 'index', 'db', 'lang', 'lib', 'pix', 'tests', 'templates'] and plugin_full_path not in checked_paths:
                                    self.logger.debug(f"Potentially detected plugin '{plugin_name}' ({desc}) at {plugin_full_path}")
                                    detected.append({"name": plugin_name, "type": ptype, "path": plugin_full_path})
                                    checked_paths.add(plugin_full_path)
            except Exception as e:
                self.logger.debug(f"Error probing plugin path {base_path}: {str(e)}")

        # Method 2: Check admin plugins overview page (requires admin privileges)
        admin_plugins_url = f"{self.target_url}/admin/plugins.php"
        try:
            if self.delay > 0:
                time.sleep(self.delay)
            response = self.session.get(admin_plugins_url, timeout=self.timeout)
            
            if response.status_code == 200 and "login" not in response.url and "Plugin overview" in response.text:
                self.logger.info("Accessing admin plugin overview page to refine plugin list.")
                soup = BeautifulSoup(response.text, 'html.parser')
                # Look for specific structures listing plugins (this depends heavily on Moodle theme/version)
                # Example: find table rows or divs that contain plugin links/names
                # This requires inspecting the actual HTML of the plugins page
                # Simplified example: look for links containing '/plugins/view.php?plugin='
                for link in soup.find_all('a', href=re.compile(r'/plugins\.php\?plugin=([a-zA-Z0-9_]+)')):
                     match = re.search(r'plugin=([a-zA-Z0-9_]+)', link['href'])
                     if match:
                         plugin_name = match.group(1)
                         # Need to determine type/path - might require more scraping or assumptions
                         # For now, just add the name if not already found
                         if not any(p['name'] == plugin_name for p in detected):
                             self.logger.debug(f"Detected plugin '{plugin_name}' from admin page.")
                             # Attempt to guess common path
                             guessed_path = f"/mod/{plugin_name}" # Default guess, might be wrong
                             detected.append({"name": plugin_name, "type": "unknown", "path": guessed_path})
                             checked_paths.add(guessed_path)
            else:
                self.logger.info("Could not access or parse admin plugin overview page (requires admin auth).")
                
        except Exception as e:
            self.logger.error(f"Error checking admin plugins page: {str(e)}")

        # Deduplicate based on name
        final_detected = []
        seen_names = set()
        for plugin in detected:
            if plugin['name'] not in seen_names:
                final_detected.append(plugin)
                seen_names.add(plugin['name'])
                
        self.logger.info(f"Detected {len(final_detected)} unique potential plugins.")
        return final_detected

    def check_known_vulnerabilities(self):
        """Check detected plugins against the known vulnerability database"""
        self.logger.info("Checking detected plugins against known vulnerability database...")
        vulnerabilities = []
        
        if not self.installed_plugins:
            self.logger.warning("No installed plugins detected, skipping known vulnerability check.")
            return vulnerabilities
            
        if not self.vulnerable_plugin_db:
             self.logger.warning("Vulnerable plugin database is empty, skipping check.")
             return vulnerabilities

        moodle_version = self.version_info.get("version") if self.version_info else None

        for plugin in self.installed_plugins:
            plugin_name = plugin['name']
            plugin_type = plugin['type']
            
            if plugin_name in self.vulnerable_plugin_db:
                vulns = self.vulnerable_plugin_db[plugin_name]
                for vuln in vulns:
                    # Check if the vulnerability applies to the detected Moodle version
                    applies = True
                    if moodle_version:
                        if "affected_moodle_versions" in vuln:
                             # Simple check: assumes versions are like '3.9', '4.1.2'
                             # Needs a proper version comparison function
                             # Placeholder: check if current version starts with any affected prefix
                             is_affected_version = False
                             for affected in vuln["affected_moodle_versions"]:
                                 if moodle_version.startswith(affected): # Basic check
                                     is_affected_version = True
                                     break
                             if not is_affected_version:
                                 applies = False
                                 
                    # Check plugin version if possible (requires detecting plugin version)
                    # This is hard without filesystem access or specific admin pages
                    # We'll assume it applies if Moodle version matches for now
                    
                    if applies:
                        self.logger.warning(f"Detected plugin '{plugin_name}' matches known vulnerability: {vuln.get('cve', vuln.get('title', 'Unknown CVE'))}")
                        vulnerabilities.append({
                            "title": f"Known Vulnerability in Plugin: {plugin_name} ({vuln.get('title', 'Details unavailable')})",
                            "description": vuln.get('description', 'No description.'),
                            "severity": vuln.get('severity', 'Medium'),
                            "evidence": f"Plugin Name: {plugin_name}\nType: {plugin_type}\nCVE: {vuln.get('cve', 'N/A')}",
                            "cve": vuln.get('cve'),
                            "references": vuln.get('references', []),
                            "remediation": vuln.get('remediation', "Update the plugin to a patched version or disable/remove it.")
                        })
                        
        return vulnerabilities
        
    def test_plugin_misconfigurations(self):
        """Test for common plugin misconfigurations (Placeholder)"""
        self.logger.info("(Placeholder) Testing for common plugin misconfigurations...")
        vulnerabilities = []
        # Examples:
        # - Check specific paths for debug info enablement (e.g., /local/myplugin/debug.php)
        # - Check for default credentials if a plugin adds its own login (rare)
        # - Check for exposed setup scripts (e.g., /mod/myplugin/install.php after install)
        return vulnerabilities
