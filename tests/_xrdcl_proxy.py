"""Out-of-process XrdCl proxy — §10.2 self-replacement shim (TS-5).

The two ``exec``-composed shards moved to :mod:`brix_suite.clients.xrdcl`
(pre-move bodies archived at ``brix_suite/_legacy/_xrdcl_proxy_flat.py`` and
``_xrdcl_proxy_part2_flat.py``).  This file replaces itself in ``sys.modules``
with the canonical package, so ``import _xrdcl_proxy``, the shadow
``XRootD.client`` re-export and ``import brix_suite.clients.xrdcl`` are ONE
module object.

That identity is load-bearing here, not cosmetic.  The layer keeps a **single
worker subprocess per pytest process** in a module global, guarded by a module
lock and torn down by a module ``atexit`` hook.  Two module objects would mean
two workers, two locks and one hook — an orphaned pyxrootd child per session,
and a second copy of the XrdCl poller threads this whole layer exists to keep
out of the interpreter.
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

import brix_suite.clients.xrdcl as _canonical

_sys.modules[__name__] = _canonical
