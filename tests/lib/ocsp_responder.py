"""The controllable OCSP responder — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.servers.ocsp_responder` (pre-move body
archived at ``brix_suite/_legacy/ocsp_responder_flat.py``).

Started by the audit-16 revocation suites with an argv the tests build; its
``main(argv=None)`` is the whole contract.
"""

import os as _os
import sys as _sys

_TESTS = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_SRC = _os.path.join(_os.path.dirname(_TESTS), "brixtest", "src")
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.servers.ocsp_responder as _canonical

if __name__ == "__main__":
    _sys.exit(_canonical.main())

_sys.modules[__name__] = _canonical
