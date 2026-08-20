"""Helpers for rebuilding the local test PKI — §10.2 self-replacement shim (TS-5).

The verbatim grown body moved to :mod:`brix_suite.security.pki` (pre-move body
archived at ``brix_suite/_legacy/pki_helpers_flat.py``).  This file replaces
itself in ``sys.modules`` with the canonical module, so ``import pki_helpers``
and ``import brix_suite.security.pki`` are ONE module object.

That matters more here than for most of the cluster.  Ten call sites reach this
generator, and six of them do it by *string* from a subprocess —
``python -c "from pki_helpers import blitz_test_pki; blitz_test_pki()"`` in
``lib_py/pki``, ``resilience/servers`` and four ``cmdscripts`` live drivers —
which no import rewrite can find and no linter can flag.  ``prep_steps`` also
``importlib.reload``s it; reload follows the module object, so it now re-reads
the canonical file, which is what it always meant.

The explicit ``sys.path`` bootstrap makes the shim self-sufficient for exactly
those standalone ``python -c`` entry points, which run with ``PYTHONPATH=tests``
and no conftest.
"""

import os as _os
import sys as _sys

_SRC = _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
    "brixtest", "src",
)
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)

import brix_suite.security.pki as _canonical

_sys.modules[__name__] = _canonical
