"""ConformanceFleet — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.mesh.wlcg_conformance_fleet` (pre-move body
archived at ``brix_suite/_legacy/wlcg_conformance_fleet_flat.py``).  Seven
conformance suites and the two port-inventory modules name it flat.
"""

import os as _os
import sys as _sys

_TESTS = _os.path.dirname(_os.path.abspath(__file__))
_SRC = _os.path.join(_os.path.dirname(_TESTS), "brixtest", "src")
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.mesh.wlcg_conformance_fleet as _canonical

_sys.modules[__name__] = _canonical
