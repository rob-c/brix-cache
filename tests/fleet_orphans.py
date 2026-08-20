"""Finding and reaping fleet processes a dead session left behind — moved to `brix_suite.orphans`.

§10.2 self-replacement shim.  `import fleet_orphans` and
`import brix_suite.orphans` are the SAME module object, not two copies:
the last line rebinds this module's `sys.modules` entry to the canonical
one, so a name rebound on either spelling is rebound for both.

That property is load-bearing here.  `owns` is imported by two operator CLIs as well as the teardown path
(history §10), so the flat spelling has to keep resolving to the same
function object the suite reaps with.
"""

import os as _os
import sys as _sys

_SRC = _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
    "brixtest", "src",
)
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)

import brix_suite.orphans as _canonical  # noqa: E402

_sys.modules[__name__] = _canonical
