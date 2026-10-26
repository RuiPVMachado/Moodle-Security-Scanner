#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Modules package for Moodle Security Scanner."""

from modules.api_tester import MoodleAPITester
from modules.auth_tester import MoodleAuthTester
from modules.config_tester import MoodleConfigTester
from modules.cve_matcher import MoodleCVETester
from modules.lfi_tester import MoodleLFITester
from modules.passive import MoodlePassiveTester
from modules.plugin_tester import MoodlePluginTester
from modules.rce_tester import MoodleRCETester
from modules.session_tester import MoodleSessionTester
from modules.sqli_tester import MoodleSQLITester
from modules.supplychain import MoodleSupplyChainTester
from modules.version_detector import MoodleVersionDetector
from modules.xss_tester import MoodleXSSTester

# Dynamic loading registry.  "version" is always executed first by the
# orchestrator, even when it is not explicitly selected.
available_modules = {
    "version": MoodleVersionDetector,
    "cve": MoodleCVETester,
    "passive": MoodlePassiveTester,
    "auth": MoodleAuthTester,
    "api": MoodleAPITester,
    "config": MoodleConfigTester,
    "xss": MoodleXSSTester,
    "sqli": MoodleSQLITester,
    "lfi": MoodleLFITester,
    "rce": MoodleRCETester,
    "plugin": MoodlePluginTester,
    "session": MoodleSessionTester,
    "supplychain": MoodleSupplyChainTester,
}

__all__ = [
    "MoodleVersionDetector",
    "MoodleCVETester",
    "MoodlePassiveTester",
    "MoodleRCETester",
    "MoodleAuthTester",
    "MoodleAPITester",
    "MoodleConfigTester",
    "MoodleXSSTester",
    "MoodleLFITester",
    "MoodleSQLITester",
    "MoodlePluginTester",
    "MoodleSessionTester",
    "MoodleSupplyChainTester",
    "available_modules",
]
