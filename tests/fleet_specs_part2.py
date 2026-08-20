"""Declarative catalogue of the registry-native test fleet — shard 2.

TS-4 item 7 merged ``fleet_specs.py`` + ``fleet_specs_part2.py`` +
``fleet_values.py`` into the :mod:`brix_suite.catalogue` package.  This file
is a §10.2 self-replacement shim: it puts ``brixtest/src`` on ``sys.path``
and then rebinds its own entry in :data:`sys.modules` to :mod:`brix_suite.catalogue`, so
``fleet_specs_part2`` and :mod:`brix_suite.catalogue` are ONE module object.

That identity is the point, not a convenience.  Registration is a *side
effect on a singleton*: :func:`register_full_fleet` mutates
``brix_suite.registry._SPECS``, and every spec accessor reads it back.  Two
module objects would mean the fleet a launcher starts and the fleet a test
queries could be different sets — the failure would show up as a missing
server hours later, not as an import error here.

This file is also the one place TS-4 item 7 *fixed* rather than merely moved.
It was never a module: ``fleet_specs.py`` compiled it into its own globals via
``split_continuation.load``, so its functions closed over names — ``_data``,
``_ded``, ``_CRL_DIR`` — that it never imported.  Importing it directly raised
``NameError: name '_data' is not defined`` from ``ha_specs()``.  Pointing the
name at the merged package makes ``import fleet_specs_part2`` work for the
first time; the topic split behind it uses ordinary imports, no ``exec``.

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
