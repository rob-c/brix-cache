"""WlcgInstance — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.mesh.wlcg_fleet` (pre-move body archived at
``brix_suite/_legacy/wlcg_fleet_flat.py``).

This one has to be a single object rather than merely equivalent: the throwaway
server certificate is memoised in module globals through ``global``, and
``wlcg_conformance_fleet`` reaches the private ``_ensure_server_cert`` that
writes them.  Two module objects would mean two certificates and an ``openssl``
run per importer.
"""

import os as _os
import sys as _sys

_TESTS = _os.path.dirname(_os.path.abspath(__file__))
_SRC = _os.path.join(_os.path.dirname(_TESTS), "brixtest", "src")
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.mesh.wlcg_fleet as _canonical

_sys.modules[__name__] = _canonical
