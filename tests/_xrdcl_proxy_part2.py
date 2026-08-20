"""Shard 2 of the XrdCl proxy — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.clients.xrdcl` (proxy objects in
``.proxies``, the wire codec in ``.results``); the pre-move shard is archived
at ``brix_suite/_legacy/_xrdcl_proxy_part2_flat.py``.

This shard was never imported — ``split_continuation.load`` ``exec``-ed it into
shard 1's globals — so its first 41 lines were a verbatim copy of shard 1's
prelude, re-executed over it on every load.  ``_WORKER`` and ``_CALL_TIMEOUT``
were therefore assigned twice per process, to the same values.  The package
assigns them once.  The shim exists so the flat spelling keeps resolving to the
same module object as shard 1, which is what it always was.
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
