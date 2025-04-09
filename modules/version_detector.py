#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module for detecting Moodle version information
Part of the Moodle Security Scanner project
"""

import re
import requests
import logging
import time
from typing import Dict, Optional, Any, List
from bs4 import BeautifulSoup

class MoodleVersionDetector:
    """Class for detecting Moodle version information"""
    
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
    ):
        """Initialize the Moodle version detector
        
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
        
        # Set up logging
        if logger:
            self.logger = logger
        else:
            self.logger = logging.getLogger("MoodleVersionDetector")
            self.logger.setLevel(logging.INFO)
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        
        # Initialize HTTP session
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
    
    def detect_version(self):
        """
        Detect the Moodle version of the target
        Returns a dictionary with version information
        """
        self.logger.info("Detecting Moodle version...")
        
        # Combine results from multiple detection methods
        version_info = {}
        
        # Method 1: Check HTML source for version
        html_version = self._detect_from_html()
        if html_version:
            version_info.update(html_version)
        
        # Method 2: Check pix/moodlelogo.png file
        if self.delay > 0:
            time.sleep(self.delay)
        
        logo_version = self._detect_from_logo()
        if logo_version:
            version_info.update(logo_version)
        
        # Method 3: Check via lib/upgrade.txt file
        if self.delay > 0:
            time.sleep(self.delay)
        
        upgrade_version = self._detect_from_upgrade_file()
        if upgrade_version:
            version_info.update(upgrade_version)
        
        # Method 4: Check version explicitly from admin/tool/installaddon/index.php
        if self.delay > 0:
            time.sleep(self.delay)
        
        admin_version = self._detect_from_admin_pages()
        if admin_version:
            version_info.update(admin_version)
        
        # Method 5: Check JavaScript files for version info
        if self.delay > 0:
            time.sleep(self.delay)
        
        js_version = self._detect_from_js_files()
        if js_version:
            version_info.update(js_version)
        
        # Determine the most reliable version from the collected data
        if "version" not in version_info and "version_candidates" in version_info:
            # If we have candidates but no confirmed version, use the most common one
            candidates = version_info["version_candidates"]
            if candidates:
                most_common = max(set(candidates), key=candidates.count)
                version_info["version"] = most_common
                version_info["version_confidence"] = "medium"
        
        if version_info:
            self.logger.info(f"Detected Moodle version information: {version_info}")
        else:
            self.logger.warning("Could not detect Moodle version")
        
        return version_info
    
    def _detect_from_html(self):
        """
        Detect version from HTML source code
        Returns a dictionary with version information
        """
        self.logger.debug("Attempting to detect version from HTML source...")
        
        version_info = {}
        version_candidates = []
        
        try:
            # Send a request to the homepage
            response = self.session.get(self.target_url, timeout=self.timeout)
            
            if response.status_code != 200:
                self.logger.debug(f"Failed to get homepage, status code: {response.status_code}")
                return None
            
            # Check for direct version comments in HTML source
            html_source = response.text
            
            # Pattern 1: Look for version in HTML comments
            version_comment_pattern = r'<!-- Moodle version.*?(\d+\.\d+(?:\.\d+)*).*?-->'
            version_matches = re.findall(version_comment_pattern, html_source, re.IGNORECASE)
            if version_matches:
                version = version_matches[0]
                version_info["version"] = version
                version_info["version_source"] = "html_comment"
                version_info["version_confidence"] = "high"
                return version_info
            
            # Pattern 2: Look for "Moodle" followed by version number anywhere in the HTML
            version_pattern = r'moodle\s*(?:version|release)?\s*:?\s*(\d+\.\d+(?:\.\d+)*)'
            version_matches = re.findall(version_pattern, html_source, re.IGNORECASE)
            if version_matches:
                for match in version_matches:
                    version_candidates.append(match)
            
            # Pattern 3: Look for script tags with moodle versions
            soup = BeautifulSoup(html_source, 'html.parser')
            for script in soup.find_all('script'):
                if script.string:
                    version_matches = re.findall(r'(?:M\.cfg\.version|cfg\.version)\s*=\s*[\'"](\d+\.\d+(?:\.\d+)*)[\'"]', script.string)
                    if version_matches:
                        for match in version_matches:
                            version_candidates.append(match)
            
            # Pattern 4: Check if meta tags contain version info
            for meta in soup.find_all('meta'):
                if meta.get('name') and 'generator' in meta.get('name').lower():
                    content = meta.get('content', '')
                    if 'moodle' in content.lower():
                        version_matches = re.findall(r'(\d+\.\d+(?:\.\d+)*)', content)
                        if version_matches:
                            version = version_matches[0]
                            version_info["version"] = version
                            version_info["version_source"] = "meta_generator"
                            version_info["version_confidence"] = "high"
                            return version_info
            
            # Pattern 5: Look for doctype which sometimes includes version
            doctype = soup.select_one('!doctype')
            if doctype:
                doctype_text = str(doctype)
                version_matches = re.findall(r'moodle\s+(\d+\.\d+(?:\.\d+)*)', doctype_text, re.IGNORECASE)
                if version_matches:
                    version = version_matches[0]
                    version_info["version"] = version
                    version_info["version_source"] = "doctype"
                    version_info["version_confidence"] = "medium"
                    return version_info
            
            # If we found candidates but no definitive version, store them
            if version_candidates:
                version_info["version_candidates"] = version_candidates
                version_info["version_source"] = "html_pattern"
                version_info["version_confidence"] = "low"
            
            # Check if this is definitely Moodle
            is_moodle = False
            if 'moodle' in html_source.lower():
                is_moodle = True
            
            # Check for Moodle-specific elements
            moodle_elements = [
                'login/index.php',
                'moodle-core',
                'course/view.php',
                'theme/boost',
                'theme/classic',
                'mod/forum',
                'mod/resource'
            ]
            
            for element in moodle_elements:
                if element in html_source:
                    is_moodle = True
                    break
            
            if is_moodle:
                version_info["is_moodle"] = True
            
            return version_info
            
        except Exception as e:
            self.logger.debug(f"Error detecting version from HTML: {str(e)}")
            return None
    
    def _detect_from_logo(self):
        """
        Detect version from Moodle logo properties
        Returns a dictionary with version information
        """
        self.logger.debug("Attempting to detect version from Moodle logo...")
        
        version_info = {}
        
        # Common Moodle logo paths for different versions
        logo_paths = [
            "/pix/moodlelogo.png",
            "/pix/moodlelogo.gif",
            "/pix/moodlelogo.jpg",
            "/theme/boost/pix/moodlelogo.png",
            "/theme/classic/pix/moodlelogo.png"
        ]
        
        try:
            for logo_path in logo_paths:
                logo_url = self.target_url + logo_path
                
                try:
                    response = self.session.head(logo_url, timeout=self.timeout)
                    
                    # If the logo exists, we can check properties
                    if response.status_code == 200:
                        # Get the logo file for analysis
                        response = self.session.get(logo_url, timeout=self.timeout)
                        
                        # Check the logo file size
                        file_size = len(response.content)
                        
                        # Map logo sizes to versions (approximate)
                        # These are rough estimates and may change with different installations
                        version_by_size = {
                            2508: "3.9.x",
                            1754: "3.5.x - 3.8.x",
                            1237: "3.0.x - 3.4.x",
                            1262: "2.5.x - 2.9.x",
                            945: "2.0.x - 2.4.x"
                        }
                        
                        # Find the closest size match
                        closest_size = min(version_by_size.keys(), key=lambda x: abs(x - file_size))
                        
                        # If the size is close enough to a known size
                        if abs(closest_size - file_size) < 100:
                            version_range = version_by_size[closest_size]
                            
                            # If we haven't found a more specific version already
                            if "version" not in version_info or version_info.get("version_confidence", "") != "high":
                                version_info["version_range"] = version_range
                                version_info["version_source"] = "logo_size"
                                version_info["version_confidence"] = "medium"
                                version_info["is_moodle"] = True
                        
                        # We found a logo, so this is likely Moodle
                        version_info["is_moodle"] = True
                        break
                
                except Exception as e:
                    self.logger.debug(f"Error checking logo at {logo_url}: {str(e)}")
                    continue
            
            return version_info
            
        except Exception as e:
            self.logger.debug(f"Error detecting version from logo: {str(e)}")
            return None
    
    def _detect_from_upgrade_file(self):
        """
        Detect version from upgrade.txt file
        Returns a dictionary with version information
        """
        self.logger.debug("Attempting to detect version from upgrade.txt file...")
        
        version_info = {}
        
        try:
            # Try to access the upgrade.txt file
            upgrade_url = self.target_url + "/lib/upgrade.txt"
            
            response = self.session.get(upgrade_url, timeout=self.timeout)
            
            # If the file exists, we can parse it for version info
            if response.status_code == 200:
                content = response.text
                
                # Look for version headers in the upgrade.txt file
                version_pattern = r'=+ (\d+\.\d+(?:\.\d+)*(?: ?(?:dev|beta|alpha|rc)\d*)?) =+'
                version_matches = re.findall(version_pattern, content)
                
                if version_matches:
                    # The latest version is typically at the top
                    latest_version = version_matches[0]
                    
                    version_info["version"] = latest_version
                    version_info["version_source"] = "upgrade_txt"
                    version_info["version_confidence"] = "high"
                    version_info["is_moodle"] = True
                
                # Even if we didn't find a version, if the file exists, it's likely Moodle
                version_info["is_moodle"] = True
            
            return version_info
            
        except Exception as e:
            self.logger.debug(f"Error detecting version from upgrade.txt: {str(e)}")
            return None
    
    def _detect_from_admin_pages(self):
        """
        Detect version from admin pages
        Returns a dictionary with version information
        """
        self.logger.debug("Attempting to detect version from admin pages...")
        
        version_info = {}
        
        # Common admin pages that might reveal version info
        admin_paths = [
            "/admin/index.php",
            "/admin/environment.php",
            "/admin/tool/installaddon/index.php",
            "/admin/tool/task/scheduledtasks.php",
            "/admin/settings.php",
            "/admin/tool/customlang/index.php",
            "/login/forgot_password.php"  # Sometimes reveals version in error messages
        ]
        
        try:
            for admin_path in admin_paths:
                admin_url = self.target_url + admin_path
                
                try:
                    response = self.session.get(admin_url, timeout=self.timeout)
                    
                    # If the page exists, check for version info
                    if response.status_code == 200:
                        content = response.text
                        
                        # Pattern 1: Direct version display
                        version_pattern = r'(?:Moodle|Version)\s+(?:version|release)?\s*:?\s*(\d+\.\d+(?:\.\d+)*(?:\s*(?:dev|beta|alpha|rc)\d*)?)'
                        version_matches = re.findall(version_pattern, content, re.IGNORECASE)
                        
                        if version_matches:
                            version = version_matches[0]
                            
                            version_info["version"] = version
                            version_info["version_source"] = "admin_page"
                            version_info["version_confidence"] = "high"
                            version_info["is_moodle"] = True
                            
                            # Found a definitive version, no need to check other pages
                            return version_info
                        
                        # Pattern 2: Check for release info in page source
                        soup = BeautifulSoup(content, 'html.parser')
                        release_info = soup.find(string=re.compile(r'Release\s*:?\s*\d+\.\d+'))
                        
                        if release_info:
                            version_match = re.search(r'(\d+\.\d+(?:\.\d+)*)', release_info)
                            if version_match:
                                version = version_match.group(1)
                                
                                version_info["version"] = version
                                version_info["version_source"] = "release_info"
                                version_info["version_confidence"] = "high"
                                version_info["is_moodle"] = True
                                
                                # Found a definitive version, no need to check other pages
                                return version_info
                
                except Exception as e:
                    self.logger.debug(f"Error checking admin page {admin_url}: {str(e)}")
                    continue
            
            return version_info
            
        except Exception as e:
            self.logger.debug(f"Error detecting version from admin pages: {str(e)}")
            return None
    
    def _detect_from_js_files(self):
        """
        Detect version from JavaScript files
        Returns a dictionary with version information
        """
        self.logger.debug("Attempting to detect version from JavaScript files...")
        
        version_info = {}
        version_candidates = []
        
        # Common JavaScript files that might contain version info
        js_paths = [
            "/lib/javascript.php",
            "/lib/requirejs.php",
            "/lib/amd/build/first.min.js",
            "/theme/boost/amd/build/index.min.js",
            "/lib/templates/mustache_helper.js"
        ]
        
        try:
            for js_path in js_paths:
                js_url = self.target_url + js_path
                
                try:
                    response = self.session.get(js_url, timeout=self.timeout)
                    
                    # If the file exists, check for version info
                    if response.status_code == 200:
                        content = response.text
                        
                        # Pattern 1: Look for version in JavaScript variable assignments
                        version_pattern = r'[\'"]?(?:version|release)[\'"]?\s*[:=]\s*[\'"](\d+\.\d+(?:\.\d+)*(?:\s*(?:dev|beta|alpha|rc)\d*)?)[\'"]'
                        version_matches = re.findall(version_pattern, content, re.IGNORECASE)
                        
                        if version_matches:
                            for match in version_matches:
                                version_candidates.append(match)
                        
                        # Pattern 2: Look for moodle config with version
                        config_pattern = r'M\.cfg\.version\s*=\s*[\'"](\d+\.\d+(?:\.\d+)*)[\'"]'
                        config_matches = re.findall(config_pattern, content)
                        
                        if config_matches:
                            version = config_matches[0]
                            
                            version_info["version"] = version
                            version_info["version_source"] = "js_config"
                            version_info["version_confidence"] = "high"
                            version_info["is_moodle"] = True
                            
                            # Found a definitive version, no need to check other files
                            return version_info
                
                except Exception as e:
                    self.logger.debug(f"Error checking JS file {js_url}: {str(e)}")
                    continue
            
            # If we found candidates but no definitive version, store them
            if version_candidates:
                version_info["version_candidates"] = version_candidates
                version_info["version_source"] = "js_files"
                version_info["version_confidence"] = "medium"
            
            return version_info
            
        except Exception as e:
            self.logger.debug(f"Error detecting version from JS files: {str(e)}")
            return None 