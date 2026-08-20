"""Centralized test settings — §10.2 self-replacement shim (TS-3).

The verbatim grown body moved to ``brix_suite.settings_values`` (typed
view + ``TESTS_DIR`` added by the ``brix_suite.settings`` facade; the
pre-move body is archived at ``brix_suite/_legacy/settings_flat.py``).
This file replaces itself in ``sys.modules`` with the canonical module,
so ``import settings`` and ``import brix_suite.settings`` are ONE module
object: identical values, coherent monkeypatching, and the historical
import-time side effects (TEST_ROOT republish, TMPDIR pin, port-ladder
rebase + env republish) still fire exactly once, on first import by
either name.

The explicit sys.path bootstrap makes the shim self-sufficient for
standalone entry points (cmdscripts, guards, ad-hoc ``python -c``) that
import ``settings`` from tests/ without pytest's ``pythonpath`` or a
conftest having prepared ``brixtest/src``.
"""

import os as _os
import sys as _sys

_SRC = _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
    "brixtest", "src",
)
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)

import brix_suite.settings as _canonical

_sys.modules[__name__] = _canonical
