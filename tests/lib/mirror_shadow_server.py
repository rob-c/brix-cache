"""The hit-recording mirror shadow upstream — §10.2 shim (TS-5).

The body moved to :mod:`brix_suite.servers.mirror_shadow_server` (pre-move body
archived at ``brix_suite/_legacy/mirror_shadow_server_flat.py``).

Started by the ``mirror-shadow`` spec (now ``-m``). The phase-24 mirror suites
read its recorded-hit journal.
"""

import os as _os
import sys as _sys

_TESTS = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_SRC = _os.path.join(_os.path.dirname(_TESTS), "brixtest", "src")
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.servers.mirror_shadow_server as _canonical

if __name__ == "__main__":
    _sys.exit(_canonical.main())

_sys.modules[__name__] = _canonical
