"""WLCG token conformance fixture forge.

TS-5's security cluster moved the seven flat ``tokenforge*`` modules into the
:mod:`brix_suite.security.tokens` package, replacing the ``exec`` composition
(``tokenforge.py`` compiled parts 2 and 3 into its own globals; part 2 imported
four line-count mixins) with ordinary imports.  This file is a §10.2
self-replacement shim: it puts ``brixtest/src`` on ``sys.path`` and rebinds its
own entry in :data:`sys.modules` to the package facade, so ``tokenforge`` and
:mod:`brix_suite.security.tokens` are ONE module object rather than two copies.

The move fixed a live defect that the ``exec`` composition had been hiding:
``header_jwk_injection`` called ``_rsa_jwk``, a helper defined in this
module's globals but *not* in the imported slice whose method used it, so it
raised ``NameError`` for every caller and silently disabled the two security
tests that assert an embedded ``jwk`` header is not trusted (RFC 7515 §4.1.3,
rules 29/150).  Keeping one module object is what stops that class of defect
from coming back through a second copy.

The names this shim must keep exposing are frozen in
``docs/refactor/testsuite-shim-baseline.json`` and checked every CI run by
``tools/ci/check_shim_completeness.py`` (guard #3).
"""

import os as _os
import sys as _sys

_SRC = _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
    "brixtest", "src",
)
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)

import brix_suite.security.tokens as _canonical

if __name__ == "__main__":
    #: ``prep_steps.FleetArtifactsStep`` runs this file as a script.  Under the
    #: flat stack the CLI came from ``tokenforge_part3``'s ``__main__`` guard,
    #: which fired only because part 3 was ``exec``-ed into this module's
    #: globals.  Imports do not carry ``__name__``, so the entry point is now
    #: called by name.  Self-replacement is skipped here: ``__main__`` is this
    #: script, not the package, and rebinding it would hand the package to any
    #: later ``import __main__``.
    from brix_suite.security.tokens.manifest import main as _main

    raise SystemExit(_main())

_sys.modules[__name__] = _canonical
