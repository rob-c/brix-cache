"""x509forge, shard 3 -- the scenario catalogue and clause matrix.

TS-5's security cluster replaced the ``split_continuation`` composition
(``x509forge.py`` compiled ``x509forge_part2.py`` and ``x509forge_part3.py``
into its own globals) with the :mod:`brix_suite.security.x509` package.  This
file is a §10.2 self-replacement shim: it puts ``brixtest/src`` on ``sys.path``
and rebinds its own :data:`sys.modules` entry to the package facade, so the flat
spelling and the package are ONE module object rather than two copies that
could drift.

Thirty-eight consumers still import the flat name -- the ``clauses/`` package,
`c_auth_units`, `wlcg_conformance_fleet`, `ocsp_responder`, and fifteen test
modules -- and every one of them keeps working unchanged.

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

import brix_suite.security.x509 as _canonical

_sys.modules[__name__] = _canonical
