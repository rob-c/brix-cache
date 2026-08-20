"""Load-driver continuation shard 2 — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.perf.load_test_part2` (pre-move body archived
at ``brix_suite/_legacy/load_test_part2_flat.py``).  Nothing imports this
spelling — the shard is exec-composed into ``load_test``'s globals by
``split_continuation.load`` and is not a module anyone reaches by name — but the
shim exists so the flat and package spellings can never become two objects with
two copies of a 400-line namespace, which is the failure the split_continuation
shards are most able to hide."""

import os as _os
import sys as _sys

_TESTS = _os.path.dirname(_os.path.abspath(__file__))
_SRC = _os.path.join(_os.path.dirname(_TESTS), "brixtest", "src")
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.perf.load_test_part2 as _canonical

_sys.modules[__name__] = _canonical
