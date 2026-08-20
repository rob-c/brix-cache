"""Load-driver continuation shard 3 — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.perf.load_test_part3` (pre-move body archived
at ``brix_suite/_legacy/load_test_part3_flat.py``).  This is the shard that held
the driver's ``main()`` and its ``__main__`` guard; the guard is gone and
``run_cli()`` took its place, called from ``tests/load_test.py`` — see the note
there for why a guard could not survive the move."""

import os as _os
import sys as _sys

_TESTS = _os.path.dirname(_os.path.abspath(__file__))
_SRC = _os.path.join(_os.path.dirname(_TESTS), "brixtest", "src")
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.perf.load_test_part3 as _canonical

_sys.modules[__name__] = _canonical
