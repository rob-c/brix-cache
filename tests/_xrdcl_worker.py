"""XrdCl worker process — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.clients.xrdcl.worker` (pre-move body
archived at ``brix_suite/_legacy/_xrdcl_worker_flat.py``).

This file is a **script**, not a library: nothing imports it, and the proxy
starts it by absolute path.  The canonical path is data the package carries
(``brix_suite.clients.xrdcl.worker_link.WORKER_SCRIPT``); this spelling stays
live because it is the one an operator types when debugging a hung transfer,
and because a path that no longer resolves does not fail loudly here — the
proxy's interpreter probe would simply find no candidate,
``real_bindings_available()`` would return False, and every XrdCl suite would
SKIP.  Green, and wrong.

The ``__main__`` guard therefore calls ``main()`` by name, before the
``sys.modules`` self-replacement: a guard is a property of how the interpreter
was started and does not travel through an import (guard #11).
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

import brix_suite.clients.xrdcl.worker as _canonical

if __name__ == "__main__":
    _canonical.main()
    raise SystemExit(0)

_sys.modules[__name__] = _canonical
