#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Moodle Security Scanner - Comprehensive testing tool
Author: Security Researcher
License: Educational purposes only

This tool is designed for educational purposes to help identify security vulnerabilities
in Moodle installations. Only use this on systems you have permission to test.
"""

import argparse
import logging
import os
import sys
import time
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Import testing modules
from modules.version_detector import MoodleVersionDetector
from modules.auth_tester import MoodleAuthTester
from modules.rce_tester import MoodleRCETester
from modules.api_tester import MoodleAPITester
from modules.xss_tester import MoodleXSSTester
from modules.plugin_tester import MoodlePluginTester
from modules.session_tester import MoodleSessionTester

class MoodleSecurityScanner:
    """Main class for coordinating security testing of Moodle installations"""
    
    def __init__(self, target_url, username=None, password=None, verbose=False, 
                 output_file=None, modules=None, threads=5, timeout=30, 
                 no_color=False, proxy=None, cookies=None, delay=0):
        """Initialize the security scanner with configuration parameters"""
        
        self.target_url = target_url.rstrip('/')
        self.username = username
        self.password = password
        self.verbose = verbose
        self.output_file = output_file
        self.threads = threads
        self.timeout = timeout
        self.no_color = no_color
        self.proxy = proxy
        self.cookies = cookies
        self.delay = delay
        
        # Setup logging
        self.setup_logging()
        
        # Initialize results storage
        self.results = {
            "target": self.target_url,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": [],
            "info": [],
            "version": None,
            "modules_tested": [],
            "plugins_detected": []
        }
        
        # Initialize testing modules
        self.modules = {}
        if modules is None or "version" in modules:
            self.modules["version"] = MoodleVersionDetector(self.target_url, self.logger, 
                                                           timeout=self.timeout, proxy=self.proxy,
                                                           cookies=self.cookies, delay=self.delay)
        
        if modules is None or "auth" in modules:
            self.modules["auth"] = MoodleAuthTester(self.target_url, self.logger, 
                                                   username=self.username, password=self.password,
                                                   timeout=self.timeout, proxy=self.proxy,
                                                   cookies=self.cookies, delay=self.delay)
            
        if modules is None or "rce" in modules:
            self.modules["rce"] = MoodleRCETester(self.target_url, self.logger, 
                                                 timeout=self.timeout, proxy=self.proxy,
                                                 cookies=self.cookies, delay=self.delay)
            
        if modules is None or "api" in modules:
            self.modules["api"] = MoodleAPITester(self.target_url, self.logger, 
                                                 timeout=self.timeout, proxy=self.proxy,
                                                 cookies=self.cookies, delay=self.delay)
            
        if modules is None or "xss" in modules:
            self.modules["xss"] = MoodleXSSTester(self.target_url, self.logger, 
                                                 timeout=self.timeout, proxy=self.proxy,
                                                 cookies=self.cookies, delay=self.delay)
            
        if modules is None or "plugins" in modules:
            self.modules["plugins"] = MoodlePluginTester(self.target_url, self.logger, 
                                                        timeout=self.timeout, proxy=self.proxy,
                                                        cookies=self.cookies, delay=self.delay)
            
        if modules is None or "session" in modules:
            self.modules["session"] = MoodleSessionTester(self.target_url, self.logger, 
                                                         timeout=self.timeout, proxy=self.proxy,
                                                         cookies=self.cookies, delay=self.delay)
            
    def setup_logging(self):
        """Configure logging"""
        log_level = logging.DEBUG if self.verbose else logging.INFO
        
        self.logger = logging.getLogger("MoodleScanner")
        self.logger.setLevel(log_level)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        
        # Formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        
        # Add handlers
        self.logger.addHandler(console_handler)
        
        # File handler if output file specified
        if self.output_file:
            file_handler = logging.FileHandler(self.output_file + ".log")
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def run_scan(self):
        """Execute the complete security scan"""
        self.print_banner()
        self.logger.info(f"Starting security scan of {self.target_url}")
        
        try:
            # First, detect Moodle version
            self.detect_version()
            
            # Execute all security tests in parallel
            self.run_security_tests()
            
            # Generate final report
            self.generate_report()
            
            return self.results
            
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user. Generating partial report...")
            self.generate_report()
            return self.results
        except Exception as e:
            self.logger.error(f"Error during scan: {str(e)}")
            return None
    
    def detect_version(self):
        """Detect the Moodle version of the target"""
        self.logger.info("Detecting Moodle version...")
        
        version_info = self.modules["version"].detect_version()
        if version_info:
            self.results["version"] = version_info
            self.logger.info(f"Detected Moodle version: {version_info.get('version', 'Unknown')}")
            
            # Set version info for all modules
            for module_name, module in self.modules.items():
                if hasattr(module, 'set_version_info'):
                    module.set_version_info(version_info)
        else:
            self.logger.warning("Could not detect Moodle version")
    
    def run_security_tests(self):
        """Run all security tests based on selected modules"""
        self.logger.info("Running security tests...")
        
        tests = [
            ("Authentication Tests", self.modules["auth"].run_tests if "auth" in self.modules else None),
            ("RCE Vulnerability Tests", self.modules["rce"].run_tests if "rce" in self.modules else None),
            ("API Endpoint Tests", self.modules["api"].run_tests if "api" in self.modules else None),
            ("XSS Vulnerability Tests", self.modules["xss"].run_tests if "xss" in self.modules else None),
            ("Plugin Security Tests", self.modules["plugins"].run_tests if "plugins" in self.modules else None),
            ("Session Security Tests", self.modules["session"].run_tests if "session" in self.modules else None)
        ]
        
        # Filter out None tests
        tests = [(name, test_func) for name, test_func in tests if test_func is not None]
        
        # Run tests in parallel using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_test = {executor.submit(test_func): name for name, test_func in tests}
            
            for future in future_to_test:
                name = future_to_test[future]
                try:
                    test_results = future.result()
                    self.results["modules_tested"].append(name)
                    
                    if test_results:
                        # Add vulnerabilities and info items
                        self.results["vulnerabilities"].extend(
                            [vuln for vuln in test_results.get("vulnerabilities", [])]
                        )
                        self.results["info"].extend(
                            [info for info in test_results.get("info", [])]
                        )
                        
                        # Add plugins if detected
                        if "plugins_detected" in test_results:
                            self.results["plugins_detected"].extend(test_results["plugins_detected"])
                    
                    self.logger.info(f"Completed {name}")
                    
                except Exception as e:
                    self.logger.error(f"Error in {name}: {str(e)}")
    
    def generate_report(self):
        """Generate a final security report"""
        self.logger.info("Generating security report...")
        
        # Count vulnerabilities by severity
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for vuln in self.results["vulnerabilities"]:
            severity = vuln.get("severity", "Info")
            severity_counts[severity] += 1
        
        # Print summary to console
        self.print_summary(severity_counts)
        
        # Save full results to JSON file if output file specified
        if self.output_file:
            with open(f"{self.output_file}.json", "w") as f:
                json.dump(self.results, f, indent=4)
            self.logger.info(f"Full report saved to {self.output_file}.json")
            
            # Generate HTML report
            self.generate_html_report()
    
    def print_summary(self, severity_counts):
        """Print a summary of scan results to the console"""
        print("\n" + "="*50)
        print(" MOODLE SECURITY SCAN SUMMARY ")
        print("="*50)
        print(f"Target: {self.target_url}")
        print(f"Scan completed: {self.results['scan_time']}")
        
        if self.results["version"]:
            print(f"Moodle version: {self.results['version'].get('version', 'Unknown')}")
            print(f"Version details: {self.results['version'].get('details', 'Unknown')}")
        else:
            print("Moodle version: Could not detect")
        
        print("\nVulnerabilities Found:")
        print(f"  Critical: {severity_counts['Critical']}")
        print(f"  High:     {severity_counts['High']}")
        print(f"  Medium:   {severity_counts['Medium']}")
        print(f"  Low:      {severity_counts['Low']}")
        print(f"  Info:     {severity_counts['Info']}")
        
        print("\nModules Tested:")
        for module in self.results["modules_tested"]:
            print(f"  - {module}")
        
        if self.results["plugins_detected"]:
            print("\nPlugins Detected:")
            for plugin in self.results["plugins_detected"]:
                print(f"  - {plugin}")
        
        print("\nTop Vulnerabilities:")
        for i, vuln in enumerate(sorted(self.results["vulnerabilities"], 
                                       key=lambda x: ["Info", "Low", "Medium", "High", "Critical"].index(x.get("severity", "Info")), 
                                       reverse=True)[:5]):
            print(f"  {i+1}. [{vuln.get('severity', 'Unknown')}] {vuln.get('title', 'Unknown vulnerability')}")
        
        print("="*50)
    
    def generate_html_report(self):
        """Generate an HTML report with detailed findings"""
        html_file = f"{self.output_file}.html"
        
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Moodle Security Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1, h2, h3 { color: #333; }
                .summary { background-color: #f5f5f5; padding: 15px; border-radius: 5px; }
                .vulnerability { margin: 15px 0; padding: 15px; border-radius: 5px; }
                .Critical { background-color: #ffdddd; border-left: 5px solid #ff0000; }
                .High { background-color: #ffeedd; border-left: 5px solid #ff6600; }
                .Medium { background-color: #ffffdd; border-left: 5px solid #ffcc00; }
                .Low { background-color: #ddffdd; border-left: 5px solid #00cc00; }
                .Info { background-color: #ddddff; border-left: 5px solid #0000ff; }
                table { width: 100%; border-collapse: collapse; }
                th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <h1>Moodle Security Scan Report</h1>
            <div class="summary">
                <h2>Scan Summary</h2>
                <p><strong>Target:</strong> {target}</p>
                <p><strong>Scan Time:</strong> {scan_time}</p>
                <p><strong>Moodle Version:</strong> {version}</p>
                
                <h3>Vulnerability Summary</h3>
                <table>
                    <tr>
                        <th>Severity</th>
                        <th>Count</th>
                    </tr>
                    <tr>
                        <td>Critical</td>
                        <td>{critical_count}</td>
                    </tr>
                    <tr>
                        <td>High</td>
                        <td>{high_count}</td>
                    </tr>
                    <tr>
                        <td>Medium</td>
                        <td>{medium_count}</td>
                    </tr>
                    <tr>
                        <td>Low</td>
                        <td>{low_count}</td>
                    </tr>
                    <tr>
                        <td>Info</td>
                        <td>{info_count}</td>
                    </tr>
                </table>
            </div>
            
            <h2>Vulnerabilities</h2>
            {vulnerabilities}
            
            <h2>Additional Information</h2>
            {info_items}
            
            <h2>Plugins Detected</h2>
            <ul>
                {plugins}
            </ul>
        </body>
        </html>
        """.format(
            target=self.target_url,
            scan_time=self.results["scan_time"],
            version=self.results["version"].get("version", "Unknown") if self.results["version"] else "Unknown",
            critical_count=len([v for v in self.results["vulnerabilities"] if v.get("severity") == "Critical"]),
            high_count=len([v for v in self.results["vulnerabilities"] if v.get("severity") == "High"]),
            medium_count=len([v for v in self.results["vulnerabilities"] if v.get("severity") == "Medium"]),
            low_count=len([v for v in self.results["vulnerabilities"] if v.get("severity") == "Low"]),
            info_count=len([v for v in self.results["vulnerabilities"] if v.get("severity") == "Info"]),
            vulnerabilities=self._format_vulnerabilities_html(),
            info_items=self._format_info_html(),
            plugins="\n".join([f"<li>{plugin}</li>" for plugin in self.results["plugins_detected"]])
        )
        
        with open(html_file, "w") as f:
            f.write(html_content)
        
        self.logger.info(f"HTML report saved to {html_file}")
    
    def _format_vulnerabilities_html(self):
        """Format vulnerabilities for HTML report"""
        if not self.results["vulnerabilities"]:
            return "<p>No vulnerabilities found.</p>"
        
        vuln_html = ""
        
        # Sort vulnerabilities by severity
        sorted_vulns = sorted(self.results["vulnerabilities"], 
                             key=lambda x: ["Info", "Low", "Medium", "High", "Critical"].index(x.get("severity", "Info")), 
                             reverse=True)
        
        for vuln in sorted_vulns:
            severity = vuln.get("severity", "Info")
            title = vuln.get("title", "Unknown vulnerability")
            description = vuln.get("description", "No description provided")
            evidence = vuln.get("evidence", "")
            remediation = vuln.get("remediation", "No remediation information provided")
            
            vuln_html += f"""
            <div class="vulnerability {severity}">
                <h3>[{severity}] {title}</h3>
                <p><strong>Description:</strong> {description}</p>
                {f'<p><strong>Evidence:</strong> <pre>{evidence}</pre></p>' if evidence else ''}
                <p><strong>Remediation:</strong> {remediation}</p>
            </div>
            """
        
        return vuln_html
    
    def _format_info_html(self):
        """Format info items for HTML report"""
        if not self.results["info"]:
            return "<p>No additional information.</p>"
        
        info_html = "<ul>"
        
        for info in self.results["info"]:
            info_html += f"<li>{info}</li>"
        
        info_html += "</ul>"
        return info_html
    
    def print_banner(self):
        """Print the tool banner"""
        banner = r"""
 __  __                 _ _        _____                      _ _           
|  \/  |               | | |      / ____|                    (_) |          
| \  / | ___   ___   __| | | ___ | (___   ___  ___ _   _ _ __ _| |_ _   _  
| |\/| |/ _ \ / _ \ / _` | |/ _ \ \___ \ / _ \/ __| | | | '__| | __| | | | 
| |  | | (_) | (_) | (_| | |  __/ ____) |  __/ (__| |_| | |  | | |_| |_| | 
|_|  |_|\___/ \___/ \__,_|_|\___| |_____/ \___|\___|\__,_|_|  |_|\__|\__, | 
                                                                      __/ | 
                                                                     |___/  
        """
        print(banner)
        print(f"Moodle Security Scanner - v1.0")
        print(f"Target: {self.target_url}")
        print("="*80)

def main():
    """Main function to parse arguments and run the scanner"""
    parser = argparse.ArgumentParser(description="Moodle Security Scanner")
    parser.add_argument("--target", "-t", required=True, help="Target Moodle URL")
    parser.add_argument("--username", "-u", help="Username for authenticated tests")
    parser.add_argument("--password", "-p", help="Password for authenticated tests")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--output", "-o", help="Output file name (without extension)")
    parser.add_argument("--modules", "-m", nargs="+", choices=["version", "auth", "rce", "api", "xss", "plugins", "session"], 
                        help="Specific modules to run")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads to use")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--proxy", help="Proxy to use for requests (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--cookies", help="Cookies to use for requests (format: name=value;name2=value2)")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests in seconds")
    
    args = parser.parse_args()
    
    # Convert cookies string to dictionary if provided
    cookies = None
    if args.cookies:
        cookies = {}
        for cookie in args.cookies.split(";"):
            if "=" in cookie:
                name, value = cookie.strip().split("=", 1)
                cookies[name] = value
    
    # Create and run scanner
    scanner = MoodleSecurityScanner(
        target_url=args.target,
        username=args.username,
        password=args.password,
        verbose=args.verbose,
        output_file=args.output,
        modules=args.modules,
        threads=args.threads,
        timeout=args.timeout,
        no_color=args.no_color,
        proxy=args.proxy,
        cookies=cookies,
        delay=args.delay
    )
    
    scanner.run_scan()

if __name__ == "__main__":
    main() 