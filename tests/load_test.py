"""Concurrent transfer load driver — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.perf.load_test` (pre-move body archived at
``brix_suite/_legacy/load_test_flat.py``), taking its two continuation shards
with it: ``split_continuation.load`` resolves them against the *parent's*
``__file__``, so the three are one unit and move together or not at all.

This file is a CLI as well as a module — ``python3 tests/load_test.py --target
both`` is how the phase-33 comparison table is produced, and `docs/` documents
that spelling.  The entry point is called by name below.  It used to be a
``__main__`` guard at the foot of shard 3, firing on the parent's ``__name__``;
once the parent is a package module that name is never ``"__main__"`` again, so
the guard would have gone quiet and the driver would have exited 0 having
measured nothing.
"""

import os as _os
import sys as _sys

_TESTS = _os.path.dirname(_os.path.abspath(__file__))
_SRC = _os.path.join(_os.path.dirname(_TESTS), "brixtest", "src")
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.perf.load_test as _canonical

if __name__ == "__main__":
    raise SystemExit(_canonical.run_cli())

_sys.modules[__name__] = _canonical
