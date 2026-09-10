"""Compatibility guard for the old Python server manager.

All local test servers are launched before pytest begins by the fleet CLI —
``python3 -m cmdscripts.manage_test_servers start-all``, run from ``tests/``.
Tests must use fixed ports from settings.py or test_env instead of creating
per-test nginx/brix instances here.
"""

DEDICATED_ONLY_ERROR = (
    "Dynamic Python-managed test servers have been removed. Add the scenario "
    "as a fixed dedicated role in the fleet catalogue "
    "(tests/brix_suite/catalogue/) and consume its settings.py port from the "
    "test."
)


def start_servers(cache_profile=None, wt_enable=False, wt_mode=None):
    raise RuntimeError(DEDICATED_ONLY_ERROR)


def stop_servers():
    return None


def restart_servers():
    raise RuntimeError(DEDICATED_ONLY_ERROR)
