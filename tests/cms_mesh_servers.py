"""CMS-mesh start/stop orchestrator — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.mesh.cms_mesh_servers` (pre-move body
archived at ``brix_suite/_legacy/cms_mesh_servers_flat.py``).  The catalogue
now starts it as ``python -m brix_suite.mesh.cms_mesh_servers start``; this
path spelling stays runnable because the docs, the k8s charts and any
operator's muscle memory still name it.
"""

import os as _os
import sys as _sys

_TESTS = _os.path.dirname(_os.path.abspath(__file__))
_SRC = _os.path.join(_os.path.dirname(_TESTS), "brixtest", "src")
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.mesh.cms_mesh_servers as _canonical

if __name__ == "__main__":
    _sys.exit(_canonical.main(_sys.argv))

_sys.modules[__name__] = _canonical
