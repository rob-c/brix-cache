"""Session artifact generation for the fleet — moved to `brix_suite.prep_steps`.

§10.2 self-replacement shim.  `import fleet_prep` and
`import brix_suite.prep_steps` are the SAME module object, not two copies:
the last line rebinds this module's `sys.modules` entry to the canonical one,
so a name rebound on either spelling is rebound for both.

That property is what makes this shim safe to install today.
`test_fleet_prep_cache.py` rebinds five names in `fleet_prep`'s module dict —
`regenerate_pki`, `_make_token`, `_run`, `_GENERATOR_SOURCES`, `_cache_dir` —
and `prepare()` reads all five out of that same dict at call time.  A package
split (what TS-4 item 4 measured on the launcher) would have put the rebind on
one dict and the read on another, silently; a flat-to-flat move does not,
because there is only ever one dict.
"""

import os as _os
import sys as _sys

_SRC = _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
    "brixtest", "src",
)
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)

import brix_suite.prep_steps as _canonical  # noqa: E402

if __name__ == "__main__":
    #: `python3 tests/fleet_prep.py` generates the session artifacts and prints
    #: a line operators grep for.  It is called by name because `__main__`
    #: guards do not travel through imports: left in the canonical module alone
    #: this path exited 0 having generated nothing, which is the failure guard
    #: #11 (`tools/ci/check_shim_entrypoints.py`) exists to catch.  Self-
    #: replacement is skipped here — `__main__` is this script, not the package.
    raise SystemExit(_canonical.main(_sys.argv[1:]))

_sys.modules[__name__] = _canonical
