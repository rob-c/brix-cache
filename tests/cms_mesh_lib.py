"""CMS-mesh daemon lifecycle — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.mesh.cms_mesh_lib`, with its two
continuation shards (pre-move bodies archived at
``brix_suite/_legacy/cms_mesh_lib{,_part2,_part3}_flat.py``).

Six suites and the spec catalogue read ``cms_mesh_lib.PORTS`` by this flat
name, and ``hybrid_mesh_lib`` reuses its ``Mesh`` launcher.  Replacing this
module in ``sys.modules`` keeps both spellings one object, so the discovered
binaries and the launched-instance bookkeeping cannot exist twice.
"""

import os as _os
import sys as _sys

_TESTS = _os.path.dirname(_os.path.abspath(__file__))
_SRC = _os.path.join(_os.path.dirname(_TESTS), "brixtest", "src")
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.mesh.cms_mesh_lib as _canonical

_sys.modules[__name__] = _canonical
