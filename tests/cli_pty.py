"""CLI pipe/PTY runners — §10.2 self-replacement shim (TS-5).

The body was **promoted to core** as :mod:`brixtest.clients.pty` (pre-move body
archived at ``brix_suite/_legacy/cli_pty_flat.py``): pure stdlib, no settings,
no fleet, generic to any project driving a CLI that changes behaviour under
``isatty(2)``.  ``TIMEOUT_S`` is a module constant the golden-baseline tests
read, so the two spellings must stay ONE module object.
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

import brixtest.clients.pty as _canonical

_sys.modules[__name__] = _canonical
