"""Cachemx catalog schema — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.cachemx._cachemx_catalog_schema` (pre-move
body archived at ``brix_suite/_legacy/_cachemx_catalog_schema_flat.py``).
Pure shape checking: the module imports nothing and moved unchanged.
"""

import os as _os
import sys as _sys

_TESTS = _os.path.dirname(_os.path.abspath(__file__))
_SRC = _os.path.join(_os.path.dirname(_TESTS), "brixtest", "src")
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.cachemx._cachemx_catalog_schema as _canonical

_sys.modules[__name__] = _canonical
