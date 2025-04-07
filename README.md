# Moodle Security Scanner

A comprehensive security testing tool for Moodle Learning Management System.

## Overview

Moodle Security Scanner is a specialized tool designed to identify security vulnerabilities in Moodle LMS installations. The scanner implements a range of security tests covering common attack vectors including SQL injection, cross-site scripting (XSS), remote code execution (RCE), authentication bypasses, API security issues, and more.

**Note:** This tool is intended for legitimate security testing with proper authorization. Unauthorized security testing against systems you don't own or have permission to test is illegal and unethical.

## Features

- **Version Detection**: Accurately identifies Moodle version to enable more precise vulnerability testing
- **Authentication Testing**: Checks for authentication bypass vulnerabilities and weak credentials
- **XSS Detection**: Tests for reflected, stored, and DOM-based cross-site scripting vulnerabilities
- **Remote Code Execution**: Identifies potential RCE vulnerabilities including upload bypasses and code evaluation issues
- **SQL Injection**: Tests for SQL injection vulnerabilities in GET/POST parameters and forms
- **Local File Inclusion**: Detects LFI vulnerabilities that could expose sensitive files
- **API Security**: Tests Moodle API endpoints for security issues
- **Version-specific Vulnerabilities**: Targets known vulnerabilities based on detected version (where applicable within modules)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/moodle-security-scanner.git
cd moodle-security-scanner

# Install requirements
pip install -r requirements.txt
```

## Usage

Basic usage:

```bash
python moodle_scanner.py -t https://your-moodle-site.com
```

Advanced options:

```bash
python moodle_scanner.py -t https://your-moodle-site.com \
  -m version,xss,rce,sqli,lfi,auth,api \
  -o results.json \
  --cookies "MoodleSession=yoursessioncookie" \
  --delay 0.5 \
  --threads 10 \
  --verbose
```

### Command-line Options

- `-t, --target`: Target Moodle URL (e.g., https://moodle.example.com) (required)
- `-m, --modules`: Comma-separated list of modules to run (e.g., version,xss,auth) or 'all' (default: all)
- `-o, --output`: Output file (e.g., results.json or results.log)
- `--proxy`: Proxy URL (e.g., http://127.0.0.1:8080)
- `--cookies`: Cookies to use in requests (e.g., 'name1=value1; name2=value2' or "{'name1': 'value1', 'name2': 'value2'}")
- `--timeout`: Request timeout in seconds (default: 30)
- `--delay`: Delay between requests in seconds (can be a decimal) (default: 0)
- `--threads`: Number of threads to use for testing (default: 5)
- `--user-agent`: User-agent string to use (default: Mozilla/5.0 ...)
- `--no-verify-ssl`: Disable SSL certificate verification
- `-v, --verbose`: Enable verbose output
- `-q, --quiet`: Enable quiet mode (only errors will be displayed)
- `--version`: Show the version number and exit

## Testing Modules

The scanner includes the following testing modules:

| Module  | Description                                            |
| ------- | ------------------------------------------------------ |
| version | Detects Moodle version information                     |
| auth    | Tests authentication security including login bypasses |
| xss     | Tests for cross-site scripting vulnerabilities         |
| rce     | Tests for remote code execution vulnerabilities        |
| sqli    | Tests for SQL injection vulnerabilities                |
| lfi     | Tests for local file inclusion vulnerabilities         |
| api     | Tests API endpoints for security issues                |

## Additional Resources

- **Exploit Guide**: See `exploit_guide.md` for more detailed information on specific vulnerability exploitation techniques, including session hijacking.

## Security Considerations

- Always obtain proper authorization before testing any Moodle installation.
- Use the `--delay` option to prevent overloading the target server.
- Consider using a test/staging environment rather than a production system.
- Set appropriate timeouts to prevent hanging connections.
- The tool is designed to minimize false positives but review all findings.

## Example Output

```
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║  ███╗   ███╗ ██████╗  ██████╗ ██████╗ ██╗     ███████╗  ║
║  ████╗ ████║██╔═══██╗██╔═══██╗██╔══██╗██║     ██╔════╝  ║
║  ██╔████╔██║██║   ██║██║   ██║██║  ██║██║     █████╗    ║
║  ██║╚██╔╝██║██║   ██║██║   ██║██║  ██║██║     ██╔══╝    ║
║  ██║ ╚═╝ ██║╚██████╔╝╚██████╔╝██████╔╝███████╗███████╗  ║
║  ╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝╚══════╝  ║
║                                                          ║
║  Security Scanner v1.0                                   ║
║  A comprehensive security testing tool for Moodle LMS    ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝

Target: https://moodle.example.com/
Modules: version, auth, xss, rce, sqli, lfi, api
Starting scan at: 2023-11-12 09:15:23

[*] Detecting Moodle version...
[+] Detected Moodle version: 3.11.4

[*] Running auth tests...
[!] Weak Default Credentials: The admin account uses default credentials.

[*] Running xss tests...
[!] Reflected XSS Vulnerability: The /search/index.php page is vulnerable to reflected XSS via the query parameter.

[*] Running rce tests...
[!] Calculated Question RCE Vulnerability: The Moodle installation is vulnerable to a Remote Code Execution vulnerability in calculated questions.

====================================================
Scan Summary for https://moodle.example.com/
====================================================

Moodle Information:
Version: 3.11.4

Vulnerability Summary:
Total vulnerabilities found: 3
Critical: 1
High: 1
Medium: 1
Low: 0
Info: 0

Vulnerabilities by Module:
version: 0
auth: 1
xss: 1
rce: 1
sqli: 0
lfi: 0
api: 0

Top Vulnerabilities:
1. [Critical] Calculated Question RCE Vulnerability
2. [High] Reflected XSS Vulnerability
3. [Medium] Weak Default Credentials

====================================================
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and legitimate security testing purposes only. The authors accept no liability for misuse or damage caused by this program.
