"""Signature algorithms and JOSE header handling for the token forge.

TS-5's security cluster moved the seven flat ``tokenforge*`` modules into the
:mod:`brix_suite.security.tokens` package, replacing the ``exec`` composition
(``tokenforge.py`` compiled parts 2 and 3 into its own globals; part 2 imported
four line-count mixins) with ordinary imports.  This file is a §10.2
self-replacement shim: it puts ``brixtest/src`` on ``sys.path`` and rebinds its
own entry in :data:`sys.modules` to the package facade, so ``_tokenforge_part2_mixinb`` and
:mod:`brix_suite.security.tokens` are ONE module object rather than two copies.

Nothing but the old ``tokenforge_part2`` ever imported this name, but the
shim points at the facade rather than at its topic module so the historical
``_TokenForgeMixin*`` spellings still resolve: the facade keeps them as
aliases onto the renamed classes.

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

_sys.modules[__name__] = _canonical
