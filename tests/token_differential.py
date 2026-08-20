"""WLCG token conformance Layer-3 driver — §10.2 self-replacement shim (TS-5).

The verbatim grown body moved to :mod:`brix_suite.security.tokens_vectors`
(pre-move body archived at ``brix_suite/_legacy/token_differential_flat.py``).
This file replaces itself in ``sys.modules`` with the canonical module, so
``import token_differential`` and the package spelling are ONE module object.

It is also a CLI: ``cmdscripts/token_differential.py`` starts it as
``python3 tests/token_differential.py [stock_port]`` — an *absolute path*, so
the entry point has to survive here as well as in the package.  It is called by
name below rather than left to a ``__main__`` guard: guards do not travel
through imports, which is how the token forge's CLI came to exit 0 while
writing nothing (see ``tools/ci/check_shard_entrypoints.py``).  That failure
mode is worse here than anywhere else in the cluster — the pytest wrapper
``test_cmd_token_differential.py`` SKIPs unless ``TEST_TOKEN_DIFF=1``, so a
driver that ran nothing and exited 0 would be reported as a pass.
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

import brix_suite.security.tokens_vectors as _canonical

if __name__ == "__main__":
    raise SystemExit(_canonical.main(_sys.argv[1:]))

_sys.modules[__name__] = _canonical
