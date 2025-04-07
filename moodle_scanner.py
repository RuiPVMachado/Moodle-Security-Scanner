#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Moodle Security Scanner - A comprehensive security testing tool for Moodle LMS
"""

import argparse
import logging
import json
import sys
import time
import random
import os
from datetime import datetime

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
    print("pip install requests colorama urllib3 beautifulsoup4")
    sys.exit(1)

# Initialize colorama
init()

# Suppress insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class MoodleScanner:
    """Main class for scanning Moodle instances for security vulnerabilities"""
    
    def __init__(self, args):
        """Initialize the scanner with command line arguments"""
        self.args = args
        self.target_url = args.target
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
        self.results = {
            "scan_info": {
                "target": self.target_url,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "modules_run": self.modules_to_run
            },
            "vulnerabilities": [],
            "version_info": {},
            "summary": {}
        }
        
        # Setup logging
        self.setup_logging()
        
        # Normalize target URL
        if not self.target_url.endswith('/'):
            self.target_url += '/'
        if not self.target_url.startswith('http'):
            self.target_url = 'http://' + self.target_url
        
        self.logger.info(f"Initializing scan against {self.target_url}")
        
        # Show banner unless quiet mode is enabled
        if not self.quiet:
            self.show_banner()
    
    def setup_logging(self):
        """Setup logging configuration"""
        self.logger = logging.getLogger("MoodleScanner")
        
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
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        
        # Add handler to logger
        self.logger.addHandler(console_handler)
        
        # Create file handler if output file is specified
        if self.output_file and self.output_file.endswith('.log'):
            file_handler = logging.FileHandler(self.output_file)
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def _parse_modules(self, modules_arg):
        """Parse modules to run based on command line arguments"""
        if not modules_arg or modules_arg == "all":
            return list(available_modules.keys())
        
        modules = []
        for module in modules_arg.split(','):
            module = module.strip().lower()
            if module in available_modules:
                modules.append(module)
            else:
                print(f"Warning: Unknown module '{module}'. Available modules: {', '.join(available_modules.keys())}")
        
        return modules
    
    def _parse_cookies(self, cookies_arg):
        """Parse cookies from command line arguments"""
        if not cookies_arg:
            return None
        
        cookies = {}
        try:
            # Handle both formats: "name1=value1; name2=value2" and "{'name1': 'value1', 'name2': 'value2'}"
            if cookies_arg.startswith('{'):
                cookies = json.loads(cookies_arg.replace("'", '"'))
            else:
                for cookie in cookies_arg.split(';'):
                    name, value = cookie.strip().split('=', 1)
                    cookies[name] = value
        except Exception as e:
            self.logger.error(f"Error parsing cookies: {str(e)}")
            self.logger.error("Format should be 'name1=value1; name2=value2' or \"{'name1': 'value1', 'name2': 'value2'}\"")
        
        return cookies
    
    def show_banner(self):
        """Display the banner"""
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
║  {Fore.YELLOW}Security Scanner v1.0{Fore.CYAN}                                 ║
║  {Fore.YELLOW}A comprehensive security testing tool for Moodle LMS{Fore.CYAN}  ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
        print(f"Target: {Fore.GREEN}{self.target_url}{Style.RESET_ALL}")
        print(f"Modules: {Fore.GREEN}{', '.join(self.modules_to_run)}{Style.RESET_ALL}")
        print(f"Starting scan at: {Fore.GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print("")
    
    def run(self):
        """Run the scanner with selected modules"""
        start_time = time.time()
        
        try:
            # Always run version detection first
            if "version" in self.modules_to_run or "all" in self.modules_to_run:
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
                self.save_results()
            
            # Print summary
            if not self.quiet:
                self.print_summary()
            
            scan_duration = time.time() - start_time
            self.logger.info(f"Scan completed in {scan_duration:.2f} seconds")
            
            return self.results
        
        except KeyboardInterrupt:
            self.logger.error("Scan interrupted by user")
            if not self.quiet:
                print(f"\n{Fore.RED}Scan interrupted by user.{Style.RESET_ALL}")
            
            # Save partial results if possible
            if self.output_file:
                self.save_results()
            
            return None
        
        except Exception as e:
            self.logger.error(f"Error running scanner: {str(e)}")
            if not self.quiet:
                print(f"\n{Fore.RED}Error running scanner: {str(e)}{Style.RESET_ALL}")
            
            return None
    
    def run_version_detector(self):
        """Run the version detection module"""
        self.logger.info("Running version detection module...")
        
        if not self.quiet:
            print(f"{Fore.CYAN}[*] Detecting Moodle version...{Style.RESET_ALL}")
        
        try:
            version_detector = MoodleVersionDetector(
                target_url=self.target_url,
                logger=self.logger,
                timeout=self.timeout,
                proxy=self.proxy,
                cookies=self.cookies,
                delay=self.delay
            )
            
            version_info = version_detector.detect_version()
            
            if version_info:
                self.results["version_info"] = version_info
                
                if version_info.get("version"):
                    version = version_info.get("version")
                    self.logger.info(f"Detected Moodle version: {version}")
                    
                    if not self.quiet:
                        print(f"{Fore.GREEN}[+] Detected Moodle version: {version}{Style.RESET_ALL}")
                else:
                    self.logger.warning("Could not determine exact Moodle version")
                    
                    if not self.quiet:
                        print(f"{Fore.YELLOW}[!] Could not determine exact Moodle version{Style.RESET_ALL}")
            else:
                self.logger.warning("Version detection failed")
                
                if not self.quiet:
                    print(f"{Fore.YELLOW}[!] Version detection failed{Style.RESET_ALL}")
        
        except Exception as e:
            self.logger.error(f"Error in version detection: {str(e)}")
            
            if not self.quiet:
                print(f"{Fore.RED}[!] Error in version detection: {str(e)}{Style.RESET_ALL}")
    
    def run_module(self, module_name):
        """Run a specific testing module"""
        self.logger.info(f"Running {module_name} module...")
        
        if not self.quiet:
            print(f"\n{Fore.CYAN}[*] Running {module_name} tests...{Style.RESET_ALL}")
        
        try:
            # Initialize the module
            module_class = available_modules.get(module_name)
            if not module_class:
                self.logger.warning(f"Module {module_name} not found")
                return
            
            module = module_class(
                target_url=self.target_url,
                logger=self.logger,
                timeout=self.timeout,
                proxy=self.proxy,
                cookies=self.cookies,
                delay=self.delay
            )
            
            # Set version info if available
            if hasattr(module, "set_version_info") and self.results.get("version_info"):
                module.set_version_info(self.results["version_info"])
            
            # Run the module tests
            module_results = module.run_tests()
            
            # Process results
            if module_results:
                # Add vulnerabilities to the main results
                if "vulnerabilities" in module_results and module_results["vulnerabilities"]:
                    vulns = module_results["vulnerabilities"]
                    self.results["vulnerabilities"].extend(vulns)
                    
                    self.logger.info(f"Found {len(vulns)} vulnerabilities in {module_name} tests")
                    
                    if not self.quiet:
                        for vuln in vulns:
                            severity = vuln.get("severity", "Unknown")
                            severity_color = self._get_severity_color(severity)
                            print(f"{severity_color}[!] {vuln.get('title')}: {vuln.get('description')}{Style.RESET_ALL}")
                
                # Store module-specific information
                self.results[f"{module_name}_results"] = module_results
            else:
                self.logger.info(f"No vulnerabilities found in {module_name} tests")
                
                if not self.quiet:
                    print(f"{Fore.GREEN}[+] No vulnerabilities found in {module_name} tests{Style.RESET_ALL}")
        
        except Exception as e:
            self.logger.error(f"Error running {module_name} module: {str(e)}")
            
            if not self.quiet:
                print(f"{Fore.RED}[!] Error running {module_name} module: {str(e)}{Style.RESET_ALL}")
    
    def generate_summary(self):
        """Generate a summary of the scan results"""
        vulnerabilities = self.results.get("vulnerabilities", [])
        
        # Count vulnerabilities by severity
        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Unknown")
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["Info"] += 1
        
        # Count vulnerabilities by module
        module_counts = {}
        for module_name in self.modules_to_run:
            module_counts[module_name] = 0
        
        for vuln in vulnerabilities:
            # Try to determine which module found the vulnerability
            module = None
            for module_name in self.modules_to_run:
                if module_name in str(vuln.get("title", "")).lower() or module_name in str(vuln.get("description", "")).lower():
                    module = module_name
                    break
            
            if module and module in module_counts:
                module_counts[module] += 1
        
        # Generate summary
        self.results["summary"] = {
            "total_vulnerabilities": len(vulnerabilities),
            "severity_counts": severity_counts,
            "module_counts": module_counts,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    def save_results(self):
        """Save results to file"""
        try:
            file_extension = os.path.splitext(self.output_file)[1].lower()
            
            if file_extension == '.json':
                with open(self.output_file, 'w') as f:
                    json.dump(self.results, f, indent=4)
            elif file_extension == '.log':
                # Log file was already set up in setup_logging
                pass
            else:
                # Default to JSON if extension not recognized
                with open(self.output_file, 'w') as f:
                    json.dump(self.results, f, indent=4)
            
            self.logger.info(f"Results saved to {self.output_file}")
            
            if not self.quiet:
                print(f"\n{Fore.GREEN}Results saved to {self.output_file}{Style.RESET_ALL}")
        
        except Exception as e:
            self.logger.error(f"Error saving results to file: {str(e)}")
            
            if not self.quiet:
                print(f"\n{Fore.RED}Error saving results to file: {str(e)}{Style.RESET_ALL}")
    
    def print_summary(self):
        """Print a summary of the scan results"""
        summary = self.results.get("summary", {})
        vulnerabilities = self.results.get("vulnerabilities", [])
        version_info = self.results.get("version_info", {})
        
        print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Scan Summary for {self.target_url}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
        
        # Print version info
        print(f"\n{Fore.CYAN}Moodle Information:{Style.RESET_ALL}")
        if version_info:
            version = version_info.get("version", "Unknown")
            print(f"{Fore.WHITE}Version: {version}{Style.RESET_ALL}")
            
            for key, value in version_info.items():
                if key != "version":
                    print(f"{Fore.WHITE}{key}: {value}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}Version information not available{Style.RESET_ALL}")
        
        # Print vulnerability summary
        total_vulns = summary.get("total_vulnerabilities", 0)
        
        print(f"\n{Fore.CYAN}Vulnerability Summary:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Total vulnerabilities found: {self._get_count_color(total_vulns)}{total_vulns}{Style.RESET_ALL}")
        
        # Print vulnerabilities by severity
        severity_counts = summary.get("severity_counts", {})
        for severity, count in severity_counts.items():
            severity_color = self._get_severity_color(severity)
            print(f"{Fore.WHITE}{severity}: {severity_color}{count}{Style.RESET_ALL}")
        
        # Print vulnerabilities by module
        module_counts = summary.get("module_counts", {})
        
        print(f"\n{Fore.CYAN}Vulnerabilities by Module:{Style.RESET_ALL}")
        for module, count in module_counts.items():
            print(f"{Fore.WHITE}{module}: {self._get_count_color(count)}{count}{Style.RESET_ALL}")
        
        # Print top 5 vulnerabilities
        if vulnerabilities:
            print(f"\n{Fore.CYAN}Top Vulnerabilities:{Style.RESET_ALL}")
            
            # Sort vulnerabilities by severity
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
            sorted_vulns = sorted(
                vulnerabilities,
                key=lambda x: severity_order.get(x.get("severity", "Info"), 999)
            )
            
            # Print top 5 or all if less than 5
            top_vulns = sorted_vulns[:5]
            for i, vuln in enumerate(top_vulns, 1):
                severity = vuln.get("severity", "Unknown")
                severity_color = self._get_severity_color(severity)
                title = vuln.get("title", "Unknown Vulnerability")
                print(f"{i}. {severity_color}[{severity}]{Style.RESET_ALL} {title}")
        
        print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
    
    def _get_severity_color(self, severity):
        """Get the color for a severity level"""
        severity = str(severity).lower()
        
        if "critical" in severity:
            return Fore.RED + Style.BRIGHT
        elif "high" in severity:
            return Fore.RED
        elif "medium" in severity:
            return Fore.YELLOW
        elif "low" in severity:
            return Fore.GREEN
        else:
            return Fore.CYAN
    
    def _get_count_color(self, count):
        """Get the color for a count based on its value"""
        if count > 10:
            return Fore.RED
        elif count > 5:
            return Fore.YELLOW
        elif count > 0:
            return Fore.GREEN
        else:
            return Fore.WHITE


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Moodle Security Scanner - A comprehensive security testing tool for Moodle LMS",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "-t", "--target",
        dest="target",
        required=True,
        help="Target Moodle URL (e.g., https://moodle.example.com)"
    )
    
    parser.add_argument(
        "-m", "--modules",
        dest="modules",
        default="all",
        help="Comma-separated list of modules to run (e.g., version,xss,auth) or 'all'"
    )
    
    parser.add_argument(
        "-o", "--output",
        dest="output",
        help="Output file (e.g., results.json or results.log)"
    )
    
    parser.add_argument(
        "--proxy",
        dest="proxy",
        help="Proxy URL (e.g., http://127.0.0.1:8080)"
    )
    
    parser.add_argument(
        "--cookies",
        dest="cookies",
        help="Cookies to use in requests (e.g., 'name1=value1; name2=value2' or \"{'name1': 'value1', 'name2': 'value2'}\")"
    )
    
    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=int,
        default=30,
        help="Request timeout in seconds"
    )
    
    parser.add_argument(
        "--delay",
        dest="delay",
        type=float,
        default=0,
        help="Delay between requests in seconds (can be a decimal)"
    )
    
    parser.add_argument(
        "--threads",
        dest="threads",
        type=int,
        default=5,
        help="Number of threads to use for testing"
    )
    
    parser.add_argument(
        "--user-agent",
        dest="user_agent",
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        help="User-agent string to use"
    )
    
    parser.add_argument(
        "--no-verify-ssl",
        dest="no_verify_ssl",
        action="store_true",
        help="Disable SSL certificate verification"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        dest="verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "-q", "--quiet",
        dest="quiet",
        action="store_true",
        help="Enable quiet mode (only errors will be displayed)"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="Moodle Security Scanner v1.0"
    )
    
    return parser.parse_args()


def main():
    """Main function"""
    args = parse_arguments()
    
    scanner = MoodleScanner(args)
    scanner.run()


if __name__ == "__main__":
    main() 