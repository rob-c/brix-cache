"""The mock RFC 7662 introspection IdP — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.servers.introspect_idp_server` (pre-move
body archived at ``brix_suite/_legacy/introspect_idp_server_flat.py``).

Started by the ``introspect-idp`` spec (now ``-m``). The phase-21 OIDC suite
drives token introspection through it.
"""

import os as _os
import sys as _sys

_TESTS = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_SRC = _os.path.join(_os.path.dirname(_TESTS), "brixtest", "src")
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.servers.introspect_idp_server as _canonical

if __name__ == "__main__":
    _sys.exit(_canonical.main())

_sys.modules[__name__] = _canonical
