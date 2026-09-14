#!/usr/bin/env python3
"""Run PAL integration tests on this host; use --help for report options."""
from platform_test_runner import main

if __name__ == '__main__':
    raise SystemExit(main(integration=True))
