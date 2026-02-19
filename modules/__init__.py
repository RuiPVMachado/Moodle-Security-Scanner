#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Modules package for Moodle Security Scanner
"""

# Import all modules to make them available via modules.*
from modules.version_detector import MoodleVersionDetector
from modules.rce_tester import MoodleRCETester
from modules.auth_tester import MoodleAuthTester
from modules.api_tester import MoodleAPITester
from modules.xss_tester import MoodleXSSTester
from modules.lfi_tester import MoodleLFITester
from modules.sqli_tester import MoodleSQLITester

# Define module availability for dynamic loading
available_modules = {
    "version": MoodleVersionDetector,
    "rce": MoodleRCETester,
    "auth": MoodleAuthTester,
    "api": MoodleAPITester,
    "xss": MoodleXSSTester,
    "lfi": MoodleLFITester,
    "sqli": MoodleSQLITester
}

__all__ = [
    "MoodleVersionDetector",
    "MoodleRCETester",
    "MoodleAuthTester",
    "MoodleAPITester",
    "MoodleXSSTester",
    "MoodleLFITester",
    "MoodleSQLITester",
    "available_modules"
] 