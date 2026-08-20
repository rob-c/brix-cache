"""Which tests declare which fleet instances — moved to `brix_suite.declares`.

§10.2 self-replacement shim.  `import fleet_declares` and
`import brix_suite.declares` are the SAME module object, not two copies:
the last line rebinds this module's `sys.modules` entry to the canonical
one, so a name rebound on either spelling is rebound for both.

That property is load-bearing here.  `test_conftest_fleet_lifecycle.py` rebinds `analyze_source` through
`conftest.fleet_declares` to count how often the AST scan runs.  Two
module objects would leave the counter on one and the real call on
the other, and the test would read zero without failing.
"""

import os as _os
import sys as _sys

_SRC = _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
    "brixtest", "src",
)
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)

import brix_suite.declares as _canonical  # noqa: E402

_sys.modules[__name__] = _canonical
