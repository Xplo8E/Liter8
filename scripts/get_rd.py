#!/usr/bin/env python3
"""Liter8 `fw get-rd` entry point."""

from boot_artifacts import build_restore_boot
from liter8_workflow import main_guard


if __name__ == "__main__":
    main_guard(build_restore_boot)
