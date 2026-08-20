"""The WLCG token-conformance library — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.servers.tokenconf` (pre-move body archived
at ``brix_suite/_legacy/tokenconf_flat.py``).

Twenty-six suites spell it ``from lib.tokenconf import ...``; the shim keeps
that spelling and the package spelling ONE module object, which matters because
``ensure_conformance_data()`` memoises the provisioned tree in module state.
"""

import os as _os
import sys as _sys

_TESTS = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_SRC = _os.path.join(_os.path.dirname(_TESTS), "brixtest", "src")
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.servers.tokenconf as _canonical

_sys.modules[__name__] = _canonical
