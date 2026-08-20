"""MIT Kerberos KDC provisioner — §10.2 self-replacement shim (TS-5).

The verbatim grown body moved to :mod:`brix_suite.security.kdc` (pre-move body
archived at ``brix_suite/_legacy/kdc_helpers_flat.py``).  This file replaces
itself in ``sys.modules`` with the canonical module, so ``import kdc_helpers``
and ``import brix_suite.security.kdc`` are ONE module object — which matters
here because the realm lock and ``_realm_lock_fd`` are module state: two copies
would mean two locks and two ideas of whether the KDC is up.

This module is also a CLI, started by the spec catalogue as
``[python, tests/kdc_helpers.py, "up"|"down"]`` — an *absolute path*, so the
entry point has to survive here as well as in the package.  It is called by
name below rather than left to a ``__main__`` guard: guards do not travel
through imports, which is how the token forge's CLI came to exit 0 while
writing nothing (see ``tools/ci/check_shard_entrypoints.py``).
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

import brix_suite.security.kdc as _canonical

if __name__ == "__main__":
    #: `up` exits 3 when the MIT tooling is absent — a *clean skip* the caller
    #: reads to mean "do not start the nginx krb5 instance".  Losing the entry
    #: point would have exited 0 instead, and the tier would have been started
    #: against a realm that was never provisioned.
    raise SystemExit(_canonical.main(_sys.argv[1:]))

_sys.modules[__name__] = _canonical
