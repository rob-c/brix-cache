"""Declarative catalogue of the registry-native test fleet.

TS-4 item 7 merged ``fleet_specs.py`` + ``fleet_specs_part2.py`` +
``fleet_values.py`` into the :mod:`brix_suite.catalogue` package.  This file
is a §10.2 self-replacement shim: it puts ``brixtest/src`` on ``sys.path``
and then rebinds its own entry in :data:`sys.modules` to :mod:`brix_suite.catalogue`, so
``fleet_specs`` and :mod:`brix_suite.catalogue` are ONE module object.

That identity is the point, not a convenience.  Registration is a *side
effect on a singleton*: :func:`register_full_fleet` mutates
``brix_suite.registry._SPECS``, and every spec accessor reads it back.  Two
module objects would mean the fleet a launcher starts and the fleet a test
queries could be different sets — the failure would show up as a missing
server hours later, not as an import error here.

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

import brix_suite.catalogue as _canonical

_sys.modules[__name__] = _canonical
