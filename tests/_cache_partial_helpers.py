"""Partial-fill and .cinfo readers — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.cachemx._cache_partial_helpers` (pre-move
body archived at ``brix_suite/_legacy/_cache_partial_helpers_flat.py``).  Like
its ``_cachemx`` sibling it names ``xrdcinfo``/``xrdcp`` under the repo, so
``REPO`` comes from the settings suite root rather than from this file.
"""

import os as _os
import sys as _sys

_TESTS = _os.path.dirname(_os.path.abspath(__file__))
_SRC = _os.path.join(_os.path.dirname(_TESTS), "brixtest", "src")
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.cachemx._cache_partial_helpers as _canonical

_sys.modules[__name__] = _canonical
