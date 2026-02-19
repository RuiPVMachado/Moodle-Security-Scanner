#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Compatibility wrapper for the canonical Moodle scanner CLI."""

import warnings

from moodle_scanner import main


if __name__ == "__main__":
    warnings.warn(
        (
            "moodle_security_scanner.py is deprecated. "
            "Use moodle_scanner.py as the canonical CLI entry point."
        ),
        DeprecationWarning,
        stacklevel=1,
    )
    main()
