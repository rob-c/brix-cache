"""Cache-matrix stack and plane drivers — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.cachemx._cachemx` (pre-move body archived at
``brix_suite/_legacy/_cachemx_flat.py``).  ``REPO`` is now named from the
settings module's searched suite root instead of this file's parents: the
native client binaries stayed at ``client/bin/`` in the repo and this module
did not.  Twenty-odd ``test_cachemx_*`` suites import the flat spelling.
"""

import os as _os
import sys as _sys

_TESTS = _os.path.dirname(_os.path.abspath(__file__))
_SRC = _os.path.join(_os.path.dirname(_TESTS), "brixtest", "src")
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.cachemx._cachemx as _canonical

_sys.modules[__name__] = _canonical
