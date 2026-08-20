"""The RFC-3820 proxy minter — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.servers.fwd_mint_proxy` (pre-move body
archived at ``brix_suite/_legacy/fwd_mint_proxy_flat.py``).

Spawned **by absolute path** from ``cmdscripts/_fwd_matrix_live_part2_mixina``;
it is a one-shot CLI, not a server, and its exit code is the caller's verdict.
"""

import os as _os
import sys as _sys

_TESTS = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_SRC = _os.path.join(_os.path.dirname(_TESTS), "brixtest", "src")
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.servers.fwd_mint_proxy as _canonical

if __name__ == "__main__":
    _sys.exit(_canonical.main())

_sys.modules[__name__] = _canonical
