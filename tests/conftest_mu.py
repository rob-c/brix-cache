"""Alias shim (testsuite-modernization-plan §10.2): the multi-user conformance
fixtures moved to ``brix_suite.harness_ext`` in TS-2.  Replacing this module's
sys.modules entry with the canonical module keeps both import paths — and the
``pytest_plugins = ["conftest_mu"]`` registration in conftest_part3 — pointing
at ONE module object, so fixtures, the leak-ledger hook, and any monkeypatching
all act on the same namespace regardless of which name imported first.
"""
import sys

import brix_suite.harness_ext as _canon

sys.modules[__name__] = _canon
