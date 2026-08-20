"""The hit-counting HTTP guard upstream — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.servers.guard_stub_server` (pre-move body
archived at ``brix_suite/_legacy/guard_stub_server_flat.py``).

Started by the ``guard-stub`` spec, which now spawns it as ``python -m
brix_suite.servers.guard_stub_server``. This path spelling stays live because
the phase-65 guard suites and ``brix_suite.clients.http`` document the contract
by it.
"""

import os as _os
import sys as _sys

_TESTS = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_SRC = _os.path.join(_os.path.dirname(_TESTS), "brixtest", "src")
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.servers.guard_stub_server as _canonical

if __name__ == "__main__":
    _sys.exit(_canonical.main())

_sys.modules[__name__] = _canonical
