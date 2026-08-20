"""CMS-mesh continuation shard 2 — §10.2 self-replacement shim (TS-5).

Not an importable module: the body is exec'd into ``cms_mesh_lib``'s namespace
by ``split_continuation.load``, and moved with its parent to
``brix_suite/mesh/``.  This shim exists so that anything reaching the shard by
its flat name — a guard, a linter, a stale import — lands on the composed
parent instead of re-executing a half-namespace.
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
