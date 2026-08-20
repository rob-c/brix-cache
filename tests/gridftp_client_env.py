"""GSI client environment — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.clients.gridftp` (pre-move body archived at
``brix_suite/_legacy/gridftp_client_env_flat.py``).  Five gsiftp suites import
this name.
"""

import os as _os
import sys as _sys

_SRC = _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
    "brixtest", "src",
)
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
_TESTS = _os.path.dirname(_os.path.abspath(__file__))
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.clients.gridftp as _canonical

_sys.modules[__name__] = _canonical
