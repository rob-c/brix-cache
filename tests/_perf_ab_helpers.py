"""Phase-33 P0 A/B throughput measurer — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.perf._perf_ab_helpers` (pre-move body
archived at ``brix_suite/_legacy/_perf_ab_helpers_flat.py``).  Three consumers
use the flat spelling and one of them cannot use any other: ``_perf_netem_
helpers`` re-executes *itself* inside a network namespace and its ``--measure``
mode does ``sys.path.insert(0, dirname(__file__))`` then ``from
_perf_ab_helpers import measure_read_throughput``.  That module stays at
``tests/`` (see ``brix_suite/perf/__init__.py``), so its ``dirname`` is still
this directory and this shim is what the child finds.

It is also a small CLI (``--host/--port/--size-mib``) used to take one-off
numbers by hand, so the entry point is called by name below rather than left to
a guard that a package module never fires."""

import os as _os
import sys as _sys

_TESTS = _os.path.dirname(_os.path.abspath(__file__))
_SRC = _os.path.join(_os.path.dirname(_TESTS), "brixtest", "src")
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.perf._perf_ab_helpers as _canonical

if __name__ == "__main__":
    raise SystemExit(_canonical._main(_sys.argv[1:]))

_sys.modules[__name__] = _canonical
