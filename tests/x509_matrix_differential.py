"""x509 clause-matrix differential — §10.2 self-replacement shim (TS-5).

The verbatim grown body moved to :mod:`brix_suite.security.x509_matrix_vectors`
(pre-move body archived at
``brix_suite/_legacy/x509_matrix_differential_flat.py``).  This file replaces
itself in ``sys.modules`` with the canonical module, so the two spellings are
ONE module object.

It is also a CLI: ``cmdscripts/x509_matrix_differential.py`` starts it as
``python3 tests/x509_matrix_differential.py <outdir>`` — an *absolute path*, so
the entry point survives here, called by name rather than left to a
``__main__`` guard (guards do not travel through imports; see
``tools/ci/check_shard_entrypoints.py``).  Its pytest wrapper SKIPs unless
``TEST_X509_DIFF=1``, so a stranded entry point would have exited 0 without
replaying a single clause and been reported as a pass.
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

import brix_suite.security.x509_matrix_vectors as _canonical

if __name__ == "__main__":
    raise SystemExit(_canonical.main(_sys.argv[1:]))

_sys.modules[__name__] = _canonical
