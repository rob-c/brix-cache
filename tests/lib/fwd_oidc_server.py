"""The minimal HTTPS OIDC discovery server — §10.2 shim (TS-5).

The body moved to :mod:`brix_suite.servers.fwd_oidc_server` (pre-move body
archived at ``brix_suite/_legacy/fwd_oidc_server_flat.py``).

Spawned **by absolute path** from ``cmdscripts/_fwd_matrix_live_part2_mixina``,
which is why this spelling has to keep working as a script.
"""

import os as _os
import sys as _sys

_TESTS = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_SRC = _os.path.join(_os.path.dirname(_TESTS), "brixtest", "src")
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.servers.fwd_oidc_server as _canonical

if __name__ == "__main__":
    _sys.exit(_canonical.main())

_sys.modules[__name__] = _canonical
