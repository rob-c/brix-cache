"""Hybrid-mesh start/stop orchestrator — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.mesh.hybrid_mesh_servers` (pre-move body
archived at ``brix_suite/_legacy/hybrid_mesh_servers_flat.py``).  Runnable by
path as well as by ``-m``, for the same reason as ``cms_mesh_servers.py``.
"""

import os as _os
import sys as _sys

_TESTS = _os.path.dirname(_os.path.abspath(__file__))
_SRC = _os.path.join(_os.path.dirname(_TESTS), "brixtest", "src")
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.mesh.hybrid_mesh_servers as _canonical

if __name__ == "__main__":
    _sys.exit(_canonical.main(_sys.argv))

_sys.modules[__name__] = _canonical
