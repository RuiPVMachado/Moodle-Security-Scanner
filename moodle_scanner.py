#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Moodle Security Scanner - A comprehensive security testing tool for Moodle LMS
Version: 1.0.1
"""

import argparse
import logging
import json
import sys
import time
import os
from datetime import datetime
from typing import Dict, List, Optional, Union, Any

try:
    import requests
    from colorama import init, Fore, Style
    import urllib3
    from modules import (
        MoodleVersionDetector,
        MoodleRCETester, 
        MoodleAuthTester,
        MoodleAPITester,
        MoodleXSSTester,
        MoodleLFITester,
        available_modules
    )
except ImportError as e:
    print(f"Error: Missing required module - {str(e)}")
    print("Please install required dependencies using:")
    print("pip install -r requirements.txt")
    sys.exit(1)

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Suppress insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class MoodleScanner:
    """Main class for scanning Moodle instances for security vulnerabilities"""
    
    def __init__(self, args: argparse.Namespace) -> None:
        """Initialize the scanner with command line arguments
        
        Args:
            args: Command line arguments parsed by argparse
        """
        self.args = args
        self.target_url = self._normalize_url(args.target)
        self.output_file = args.output
        self.modules_to_run = self._parse_modules(args.modules)
        self.proxy = args.proxy
        self.cookies = self._parse_cookies(args.cookies)
        self.timeout = args.timeout
        self.delay = args.delay
        self.threads = args.threads
        self.user_agent = args.user_agent
        self.verify_ssl = not args.no_verify_ssl
        self.verbose = args.verbose
        self.quiet = args.quiet
        self.logger = None  # Will be set up in setup_logging()
        
        # Initialize results structure
        self.results = {
            "scan_info": {
                "target": self.target_url,
                "timestamp": datetime.now().isoformat(),
                "modules_run": self.modules_to_run,
                "scanner_version": "1.0.1"
            },
            "vulnerabilities": [],
            "version_info": {},
            "summary": {}
        }
        
        # Setup logging
        self.setup_logging()
        
        self.logger.info(f"Initializing scan against {self.target_url}")
        
        # Show banner unless quiet mode is enabled
        if not self.quiet:
            self.show_banner()
    
    def _normalize_url(self, url: str) -> str:
        """Normalize target URL
        
        Args:
            url: URL to normalize
            
        Returns:
            Normalized URL with protocol and trailing slash
        """
        if not url:
            return ""
            
        normalized_url = url.strip()
        if not normalized_url.endswith('/'):
            normalized_url += '/'
        if not normalized_url.startswith(('http://', 'https://')):
            normalized_url = 'https://' + normalized_url
            self.logger.info(f"No protocol specified, using HTTPS by default: {normalized_url}")
        
        return normalized_url
    
    def setup_logging(self) -> None:
        """Setup logging configuration with appropriate handlers and formatters"""
        self.logger = logging.getLogger("MoodleScanner")
        
        # Clear any existing handlers to prevent duplicates
        if self.logger.handlers:
            self.logger.handlers.clear()
        
        # Set log level based on verbosity
        if self.verbose:
            log_level = logging.DEBUG
        elif self.quiet:
            log_level = logging.ERROR
        else:
            log_level = logging.INFO
        
        self.logger.setLevel(log_level)
        
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(formatter)
        
        # Add handler to logger
        self.logger.addHandler(console_handler)
        
        # Create file handler if output file is specified
        if self.output_file and self.output_file.endswith('.log'):
            try:
                # Create directory for log file if it doesn't exist
                log_dir = os.path.dirname(self.output_file)
                if log_dir and not os.path.exists(log_dir):
                    os.makedirs(log_dir)
                
                file_handler = logging.FileHandler(self.output_file, 'w')
                file_handler.setLevel(log_level)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)
                self.logger.info(f"Logging to file: {self.output_file}")
            except (IOError, OSError) as e:
                self.logger.error(f"Failed to create log file: {str(e)}")
    
    def _parse_modules(self, modules_arg: Optional[str]) -> List[str]:
        """Parse modules to run based on command line arguments
        
        Args:
            modules_arg: Comma-separated list of modules or 'all'
            
        Returns:
            List of module names to run
        """
        if not modules_arg or modules_arg.lower() == "all":
            return list(available_modules.keys())
        
        modules = []
        for module in modules_arg.split(','):
            module = module.strip().lower()
            if module in available_modules:
                modules.append(module)
            else:
                self.logger.warning(
                    f"Unknown module '{module}'. Available modules: {', '.join(available_modules.keys())}"
                )
        
        return modules
    
    def _parse_cookies(self, cookies_arg: Optional[str]) -> Optional[Dict[str, str]]:
        """Parse cookies from command line arguments
        
        Args:
            cookies_arg: Cookie string in format "name1=value1; name2=value2" or JSON format
            
        Returns:
            Dictionary of cookies or None if no cookies provided
        """
        if not cookies_arg:
            return None
        
        cookies = {}
        try:
            # Handle both formats: "name1=value1; name2=value2" and "{'name1': 'value1', 'name2': 'value2'}"
            if cookies_arg.startswith('{'):
                # JSON format - ensure proper JSON by replacing single quotes with double quotes
                cookies = json.loads(cookies_arg.replace("'", '"'))
            else:
                # Cookie string format
                for cookie in cookies_arg.split(';'):
                    if '=' in cookie:
                        name, value = cookie.strip().split('=', 1)
                        cookies[name.strip()] = value.strip()
        except Exception as e:
            self.logger.error(f"Error parsing cookies: {str(e)}")
            self.logger.error(
                "Format should be 'name1=value1; name2=value2' or \"{'name1': 'value1', 'name2': 'value2'}\""
            )
        
        return cookies
    
    def show_banner(self) -> None:
        """Display the banner with tool information"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║                                                          ║
║  {Fore.GREEN}███╗   ███╗ ██████╗  ██████╗ ██████╗ ██╗     ███████╗{Fore.CYAN}  ║
║  {Fore.GREEN}████╗ ████║██╔═══██╗██╔═══██╗██╔══██╗██║     ██╔════╝{Fore.CYAN}  ║
║  {Fore.GREEN}██╔████╔██║██║   ██║██║   ██║██║  ██║██║     █████╗{Fore.CYAN}    ║
║  {Fore.GREEN}██║╚██╔╝██║██║   ██║██║   ██║██║  ██║██║     ██╔══╝{Fore.CYAN}    ║
║  {Fore.GREEN}██║ ╚═╝ ██║╚██████╔╝╚██████╔╝██████╔╝███████╗███████╗{Fore.CYAN}  ║
║  {Fore.GREEN}╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝╚══════╝{Fore.CYAN}  ║
║                                                          ║
║  {Fore.YELLOW}Security Scanner v1.0.1{Fore.CYAN}                               ║
║  {Fore.YELLOW}A comprehensive security testing tool for Moodle LMS{Fore.CYAN}  ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
        print(f"Target: {Fore.GREEN}{self.target_url}{Style.RESET_ALL}")
        print(f"Modules: {Fore.GREEN}{', '.join(self.modules_to_run)}{Style.RESET_ALL}")
        print(f"Starting scan at: {Fore.GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print("")
    
    def run(self) -> Dict[str, Any]:
        """Run the scanner with selected modules
        
        Returns:
            Dictionary containing scan results
        """
        start_time = time.time()
        
        try:
            # Always run version detection first if it's selected
            if "version" in self.modules_to_run:
                self.run_version_detector()
            else:
                self.logger.warning("Version detection module not selected. Some tests may be less effective.")
            
            # Run selected modules
            for module_name in self.modules_to_run:
                if module_name == "version":
                    continue  # Already ran version detection
                
                if module_name in available_modules:
                    self.run_module(module_name)
                else:
                    self.logger.warning(f"Unknown module: {module_name}")
            
            # Generate summary
            self.generate_summary()
            
            # Save results to file if specified
            if self.output_file:
                if not self.output_file.endswith('.log'):
                    self.save_results()
            
            elapsed_time = time.time() - start_time
            self.logger.info(f"Scan completed in {elapsed_time:.2f} seconds")
            
            self.print_summary()
            
            return self.results
            
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
            elapsed_time = time.time() - start_time
            self.logger.info(f"Partial scan completed in {elapsed_time:.2f} seconds")
            
            # Save partial results
            if self.output_file and not self.output_file.endswith('.log'):
                self.save_results(partial=True)
            
            return self.results
        
        except Exception as e:
            self.logger.error(f"Error during scan: {str(e)}", exc_info=True)
            return self.results
    
    def run_version_detector(self) -> None:
        """Run the version detection module"""
        self.logger.info("Running version detection...")
        
        version_detector = MoodleVersionDetector(
            target_url=self.target_url,
            logger=self.logger,
            timeout=self.timeout,
            proxy=self.proxy,
            cookies=self.cookies,
            delay=self.delay,
            user_agent=self.user_agent,
            verify_ssl=self.verify_ssl
        )
        
        version_info = version_detector.detect_version()
        
        if version_info:
            self.results["version_info"] = version_info
            version = version_info.get("version", "Unknown")
            self.logger.info(f"Detected Moodle version: {version}")
        else:
            self.logger.warning("Could not detect Moodle version")
    
    def run_module(self, module_name: str) -> None:
        """Run a specific testing module
        
        Args:
            module_name: Name of the module to run
        """
        self.logger.info(f"Running {module_name} tests...")
        
        try:
            # Use the appropriate module class based on the module name
            module_class = available_modules[module_name]
            
            # Initialize the module with common parameters
            module = module_class(
                target_url=self.target_url,
                logger=self.logger,
                timeout=self.timeout,
                proxy=self.proxy,
                cookies=self.cookies,
                delay=self.delay,
                user_agent=self.user_agent if hasattr(self, 'user_agent') else None,
                verify_ssl=self.verify_ssl if hasattr(self, 'verify_ssl') else True
            )
            
            # Set version info if available
            if hasattr(module, 'set_version_info') and self.results.get("version_info"):
                module.set_version_info(self.results["version_info"])
            
            # Run the module's tests
            results = module.run_tests()
            
            # Process results
            if results:
                vulnerabilities = results.get("vulnerabilities", [])
                if vulnerabilities:
                    self.results["vulnerabilities"].extend(vulnerabilities)
                    self.logger.info(f"Found {len(vulnerabilities)} {module_name} vulnerabilities")
                else:
                    self.logger.info(f"No {module_name} vulnerabilities found")
        
        except Exception as e:
            self.logger.error(f"Error running {module_name} module: {str(e)}", exc_info=self.verbose)
    
    def generate_summary(self) -> None:
        """Generate a summary of scan results"""
        vulnerabilities = self.results["vulnerabilities"]
        
        summary = {
            "total_vulnerabilities": len(vulnerabilities),
            "severity_counts": {
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Info": 0
            },
            "vulnerabilities_by_module": {},
            "top_vulnerabilities": []
        }
        
        # Count vulnerabilities by severity
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Unknown")
            if severity in summary["severity_counts"]:
                summary["severity_counts"][severity] += 1
            else:
                summary["severity_counts"][severity] = 1
        
        # Count vulnerabilities by module
        for module in self.modules_to_run:
            summary["vulnerabilities_by_module"][module] = 0
        
        for vuln in vulnerabilities:
            # Try to determine which module found this vulnerability
            module = None
            for mod_name in available_modules.keys():
                if mod_name.lower() in vuln.get("title", "").lower():
                    module = mod_name
                    break
            
            if module and module in summary["vulnerabilities_by_module"]:
                summary["vulnerabilities_by_module"][module] += 1
        
        # Get top vulnerabilities (sorted by severity)
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda x: severity_order.get(x.get("severity", "Unknown"), 999)
        )
        
        summary["top_vulnerabilities"] = [
            {
                "title": vuln.get("title", "Unknown"),
                "severity": vuln.get("severity", "Unknown")
            }
            for vuln in sorted_vulns[:10]  # Top 10 vulnerabilities
        ]
        
        self.results["summary"] = summary
    
    def print_summary(self) -> None:
        """Print a summary of scan results to the console"""
        if self.quiet:
            return
        
        summary = self.results["summary"]
        version_info = self.results.get("version_info", {})
        
        print("\n" + "=" * 60)
        print(f"Scan Summary for {self.target_url}")
        print("=" * 60 + "\n")
        
        print("Moodle Information:")
        version = version_info.get("version", "Unknown")
        print(f"Version: {Fore.CYAN}{version}{Style.RESET_ALL}")
        print("")
        
        print("Vulnerability Summary:")
        total = summary.get("total_vulnerabilities", 0)
        print(f"Total vulnerabilities found: {Fore.YELLOW}{total}{Style.RESET_ALL}")
        
        severity_counts = summary.get("severity_counts", {})
        if severity_counts.get("Critical", 0) > 0:
            print(f"Critical: {Fore.RED}{severity_counts['Critical']}{Style.RESET_ALL}")
        if severity_counts.get("High", 0) > 0:
            print(f"High: {Fore.LIGHTRED_EX}{severity_counts['High']}{Style.RESET_ALL}")
        if severity_counts.get("Medium", 0) > 0:
            print(f"Medium: {Fore.YELLOW}{severity_counts['Medium']}{Style.RESET_ALL}")
        if severity_counts.get("Low", 0) > 0:
            print(f"Low: {Fore.BLUE}{severity_counts['Low']}{Style.RESET_ALL}")
        if severity_counts.get("Info", 0) > 0:
            print(f"Info: {Fore.GREEN}{severity_counts['Info']}{Style.RESET_ALL}")
        print("")
        
        print("Vulnerabilities by Module:")
        for module, count in summary.get("vulnerabilities_by_module", {}).items():
            print(f"{module}: {count}")
        print("")
        
        top_vulns = summary.get("top_vulnerabilities", [])
        if top_vulns:
            print("Top Vulnerabilities:")
            for i, vuln in enumerate(top_vulns, 1):
                severity = vuln.get("severity", "Unknown")
                if severity == "Critical":
                    severity_color = Fore.RED
                elif severity == "High":
                    severity_color = Fore.LIGHTRED_EX
                elif severity == "Medium":
                    severity_color = Fore.YELLOW
                elif severity == "Low":
                    severity_color = Fore.BLUE
                else:
                    severity_color = Fore.GREEN
                
                print(f"{i}. [{severity_color}{severity}{Style.RESET_ALL}] {vuln.get('title', 'Unknown')}")
        
        print("\n" + "=" * 60)
        
        if self.output_file and not self.output_file.endswith('.log'):
            print(f"\nDetailed results saved to: {Fore.GREEN}{self.output_file}{Style.RESET_ALL}")
    
    def save_results(self, partial: bool = False) -> None:
        """Save scan results to a file
        
        Args:
            partial: Whether this is a partial scan result due to interruption
        """
        try:
            if partial:
                self.results["scan_info"]["status"] = "partial"
            else:
                self.results["scan_info"]["status"] = "complete"
            
            # Ensure directory exists
            output_dir = os.path.dirname(self.output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # Determine output format based on file extension
            if self.output_file.endswith('.json'):
                # Write JSON results
                with open(self.output_file, 'w', encoding='utf-8') as f:
                    json.dump(self.results, f, indent=2, ensure_ascii=False)
                self.logger.info(f"Results saved to {self.output_file} (JSON format)")
            elif self.output_file.endswith('.html'):
                # Generate HTML report
                self._save_html_report(self.output_file)
                self.logger.info(f"Results saved to {self.output_file} (HTML format)")
            elif self.output_file.endswith('.txt'):
                # Generate text report
                self._save_text_report(self.output_file)
                self.logger.info(f"Results saved to {self.output_file} (text format)")
            else:
                # Default to JSON
                with open(self.output_file, 'w', encoding='utf-8') as f:
                    json.dump(self.results, f, indent=2, ensure_ascii=False)
                self.logger.info(f"Results saved to {self.output_file} (JSON format)")
        
        except Exception as e:
            self.logger.error(f"Error saving results to {self.output_file}: {str(e)}")
    
    def _save_html_report(self, file_path: str) -> None:
        """Generate and save HTML report
        
        Args:
            file_path: Path to save the HTML report
        """
        vulns = self.results["vulnerabilities"]
        summary = self.results["summary"]
        version_info = self.results.get("version_info", {})
        
        # HTML template with CSS styling
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Moodle Security Scan Report - {self.target_url}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .summary {{
            background: #f8f9fa;
            border: 1px solid #ddd;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .vulnerability {{
            border: 1px solid #ddd;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 5px;
        }}
        .vulnerability h3 {{
            margin-top: 0;
        }}
        .critical {{
            border-left: 5px solid #dc3545;
        }}
        .high {{
            border-left: 5px solid #fd7e14;
        }}
        .medium {{
            border-left: 5px solid #ffc107;
        }}
        .low {{
            border-left: 5px solid #17a2b8;
        }}
        .info {{
            border-left: 5px solid #28a745;
        }}
        .evidence {{
            background: #f8f9fa;
            padding: 10px;
            border-left: 3px solid #6c757d;
            font-family: monospace;
            white-space: pre-wrap;
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        table, th, td {{
            border: 1px solid #ddd;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        .footer {{
            margin-top: 30px;
            text-align: center;
            font-size: 0.8em;
            color: #6c757d;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Moodle Security Scan Report</h1>
        <p>Target: {self.target_url}</p>
        <p>Scan Date: {self.results["scan_info"]["timestamp"]}</p>
        <p>Scanner Version: {self.results["scan_info"]["scanner_version"]}</p>
        <p>Modules Run: {', '.join(self.results["scan_info"]["modules_run"])}</p>
    </div>
    
    <div class="summary">
        <h2>Scan Summary</h2>
        <p>Moodle Version: {version_info.get("version", "Unknown")}</p>
        <p>Total Vulnerabilities Found: {summary.get("total_vulnerabilities", 0)}</p>
        
        <h3>Vulnerabilities by Severity</h3>
        <table>
            <tr>
                <th>Severity</th>
                <th>Count</th>
            </tr>
            <tr>
                <td>Critical</td>
                <td>{summary.get("severity_counts", {}).get("Critical", 0)}</td>
            </tr>
            <tr>
                <td>High</td>
                <td>{summary.get("severity_counts", {}).get("High", 0)}</td>
            </tr>
            <tr>
                <td>Medium</td>
                <td>{summary.get("severity_counts", {}).get("Medium", 0)}</td>
            </tr>
            <tr>
                <td>Low</td>
                <td>{summary.get("severity_counts", {}).get("Low", 0)}</td>
            </tr>
            <tr>
                <td>Info</td>
                <td>{summary.get("severity_counts", {}).get("Info", 0)}</td>
            </tr>
        </table>
        
        <h3>Vulnerabilities by Module</h3>
        <table>
            <tr>
                <th>Module</th>
                <th>Count</th>
            </tr>
"""
        
        # Add module counts to the HTML
        for module, count in summary.get("vulnerabilities_by_module", {}).items():
            html += f"""
            <tr>
                <td>{module}</td>
                <td>{count}</td>
            </tr>"""
        
        html += """
        </table>
    </div>
    
    <h2>Detailed Vulnerability Findings</h2>
"""
        
        if not vulns:
            html += "<p>No vulnerabilities were found during the scan.</p>"
        else:
            # Sort vulnerabilities by severity
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
            sorted_vulns = sorted(
                vulns,
                key=lambda x: severity_order.get(x.get("severity", "Unknown"), 999)
            )
            
            # Add each vulnerability to the HTML report
            for i, vuln in enumerate(sorted_vulns, 1):
                severity = vuln.get("severity", "Unknown")
                severity_class = severity.lower() if severity in ["Critical", "High", "Medium", "Low", "Info"] else "info"
                
                html += f"""
    <div class="vulnerability {severity_class}">
        <h3>{i}. {vuln.get("title", "Unknown Vulnerability")}</h3>
        <p><strong>Severity:</strong> {severity}</p>
        <p><strong>Description:</strong> {vuln.get("description", "No description provided.")}</p>
"""
                
                # Add URL if available
                if "url" in vuln:
                    html += f"""
        <p><strong>URL:</strong> <a href="{vuln.get('url')}" target="_blank">{vuln.get('url')}</a></p>"""
                
                # Add CVE if available
                if "cve" in vuln:
                    html += f"""
        <p><strong>CVE:</strong> {vuln.get('cve')}</p>"""
                
                # Add CWE if available
                if "cwe" in vuln:
                    html += f"""
        <p><strong>CWE:</strong> {vuln.get('cwe')}</p>"""
                
                # Add evidence if available
                if "evidence" in vuln:
                    html += f"""
        <div>
            <p><strong>Evidence:</strong></p>
            <div class="evidence">{vuln.get('evidence')}</div>
        </div>"""
                
                # Add payload if available
                if "payload" in vuln:
                    html += f"""
        <p><strong>Payload:</strong> <code>{vuln.get('payload')}</code></p>"""
                
                # Add remediation steps if available
                if "remediation" in vuln:
                    html += f"""
        <p><strong>Remediation:</strong> {vuln.get('remediation')}</p>"""
                
                # Add references if available
                if "references" in vuln and vuln["references"]:
                    html += """
        <p><strong>References:</strong></p>
        <ul>"""
                    for ref in vuln["references"]:
                        html += f"""
            <li><a href="{ref}" target="_blank">{ref}</a></li>"""
                    html += """
        </ul>"""
                
                html += """
    </div>"""
        
        # Close the HTML
        html += """
    <div class="footer">
        <p>Generated by Moodle Security Scanner</p>
    </div>
</body>
</html>
"""
        
        # Write the HTML report to the file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _save_text_report(self, file_path: str) -> None:
        """Generate and save text report
        
        Args:
            file_path: Path to save the text report
        """
        vulns = self.results["vulnerabilities"]
        summary = self.results["summary"]
        version_info = self.results.get("version_info", {})
        
        # Start building the text report
        report = [
            "=" * 80,
            f"MOODLE SECURITY SCAN REPORT",
            "=" * 80,
            f"Target: {self.target_url}",
            f"Scan Date: {self.results['scan_info']['timestamp']}",
            f"Scanner Version: {self.results['scan_info']['scanner_version']}",
            f"Modules Run: {', '.join(self.results['scan_info']['modules_run'])}",
            "",
            "SCAN SUMMARY",
            "-" * 80,
            f"Moodle Version: {version_info.get('version', 'Unknown')}",
            f"Total Vulnerabilities Found: {summary.get('total_vulnerabilities', 0)}",
            "",
            "Vulnerabilities by Severity:",
            f"  Critical: {summary.get('severity_counts', {}).get('Critical', 0)}",
            f"  High: {summary.get('severity_counts', {}).get('High', 0)}",
            f"  Medium: {summary.get('severity_counts', {}).get('Medium', 0)}",
            f"  Low: {summary.get('severity_counts', {}).get('Low', 0)}",
            f"  Info: {summary.get('severity_counts', {}).get('Info', 0)}",
            "",
            "Vulnerabilities by Module:"
        ]
        
        # Add module counts
        for module, count in summary.get("vulnerabilities_by_module", {}).items():
            report.append(f"  {module}: {count}")
        
        report.append("")
        report.append("DETAILED VULNERABILITY FINDINGS")
        report.append("=" * 80)
        
        if not vulns:
            report.append("No vulnerabilities were found during the scan.")
        else:
            # Sort vulnerabilities by severity
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
            sorted_vulns = sorted(
                vulns,
                key=lambda x: severity_order.get(x.get("severity", "Unknown"), 999)
            )
            
            # Add each vulnerability to the text report
            for i, vuln in enumerate(sorted_vulns, 1):
                severity = vuln.get("severity", "Unknown")
                
                report.extend([
                    f"{i}. [{severity}] {vuln.get('title', 'Unknown Vulnerability')}",
                    "-" * 80,
                    f"Description: {vuln.get('description', 'No description provided.')}",
                ])
                
                # Add URL if available
                if "url" in vuln:
                    report.append(f"URL: {vuln.get('url')}")
                
                # Add CVE if available
                if "cve" in vuln:
                    report.append(f"CVE: {vuln.get('cve')}")
                
                # Add CWE if available
                if "cwe" in vuln:
                    report.append(f"CWE: {vuln.get('cwe')}")
                
                # Add evidence if available
                if "evidence" in vuln:
                    report.extend([
                        "Evidence:",
                        f"{vuln.get('evidence')}"
                    ])
                
                # Add payload if available
                if "payload" in vuln:
                    report.append(f"Payload: {vuln.get('payload')}")
                
                # Add remediation steps if available
                if "remediation" in vuln:
                    report.append(f"Remediation: {vuln.get('remediation')}")
                
                # Add references if available
                if "references" in vuln and vuln["references"]:
                    report.append("References:")
                    for ref in vuln["references"]:
                        report.append(f"  - {ref}")
                
                report.append("")
                report.append("-" * 80)
                report.append("")
        
        # Add footer
        report.extend([
            "",
            "Generated by Moodle Security Scanner"
        ])
        
        # Write the text report to the file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(report))


def parse_args() -> argparse.Namespace:
    """Parse command line arguments
    
    Returns:
        Parsed command line arguments
    """
    parser = argparse.ArgumentParser(
        description="Moodle Security Scanner - A comprehensive security testing tool for Moodle LMS",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target Moodle URL (e.g., https://moodle.example.com)"
    )
    parser.add_argument(
        "-m", "--modules",
        default="all",
        help="Comma-separated list of modules to run (e.g., version,xss,auth) or 'all'"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file (e.g., results.json or results.log)"
    )
    parser.add_argument(
        "--proxy",
        help="Proxy URL (e.g., http://127.0.0.1:8080)"
    )
    parser.add_argument(
        "--cookies",
        help="Cookies to use in requests (e.g., 'name1=value1; name2=value2' or \"{'name1': 'value1'}\")"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0,
        help="Delay between requests in seconds (can be a decimal)"
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=5,
        help="Number of threads to use for testing"
    )
    parser.add_argument(
        "--user-agent",
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        help="User-agent string to use"
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Enable quiet mode (only errors will be displayed)"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="Moodle Security Scanner v1.0.1",
        help="Show the version number and exit"
    )
    
    return parser.parse_args()


def main() -> None:
    """Main entry point for the scanner"""
    args = parse_args()
    
    # Check for incompatible options
    if args.verbose and args.quiet:
        print("Error: Cannot use both --verbose and --quiet options together")
        sys.exit(1)
    
    scanner = MoodleScanner(args)
    scanner.run()


if __name__ == "__main__":
    main() 