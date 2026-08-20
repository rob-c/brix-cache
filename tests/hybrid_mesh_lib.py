"""Hybrid two-tier mesh — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.mesh.hybrid_mesh_lib` (pre-move body
archived at ``brix_suite/_legacy/hybrid_mesh_lib_flat.py``).  It reuses
``cms_mesh_lib``'s ``Mesh`` launcher and config builders, so the two modules
must resolve to the same objects however either is spelled.
"""

import os as _os
import sys as _sys

_TESTS = _os.path.dirname(_os.path.abspath(__file__))
_SRC = _os.path.join(_os.path.dirname(_TESTS), "brixtest", "src")
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.mesh.hybrid_mesh_lib as _canonical

_sys.modules[__name__] = _canonical
