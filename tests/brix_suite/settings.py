"""The canonical ``settings`` namespace (TS-3, §10.2).

``tests/settings.py`` is now a self-replacement shim onto THIS module, so
``import settings`` and ``import brix_suite.settings`` name one module
object and every dependent — conftest, launcher, cmdscripts, 899 import
sites — observes identical values and coherent monkeypatching.

The values themselves are computed by the VERBATIM grown body in
``brix_suite.settings_values`` (env-at-import order, the TEST_ROOT
republish, the TMPDIR pin, and the closing ``port_ladder`` rebase all
preserved byte-for-byte; rollback archive: ``_legacy/settings_flat.py``)
and re-exported here.  The 600-line file-size guard on brixtest/src is
why body and facade are two files — see the §15 TS-3 note.

New here, additive only:
  * ``TESTS_DIR`` — the flat ``tests/`` tree, derived from the repo
    layout (the ``settings.__file__`` anchor trick died with the shim).
  * ``SuiteSettings`` / ``SETTINGS`` — the §9.2.1 configuration object,
    a frozen typed view pinned to the values the body computed.
"""

import os
import sys
import warnings
from pathlib import Path


def _tests_dir() -> str:
    """The flat ``tests/`` tree — located by searching for ``port_ladder.py``.

    Found by search rather than a fixed number of ``parents[]`` hops
    because this package has already been relocated once mid-migration
    (``testsuite/src/brix_suite`` → ``tests/brix_suite``), and the hop
    count silently began naming a directory that does not exist.  That
    is invisible under pytest — ``pythonpath = tests`` has already put
    the tree on the path — and surfaces only much later, as the registry
    fixture launching a fleet from the wrong root.  Falling back to the
    package's parent keeps a layout this search does not anticipate
    working, with a warning rather than a new refusal.
    """
    here = Path(__file__).resolve()
    for candidate in here.parents:
        if (candidate / "port_ladder.py").is_file():
            return str(candidate)
    fallback = str(here.parents[1])
    warnings.warn(
        "brix_suite.settings: no ancestor of %s holds port_ladder.py; "
        "assuming the flat tests tree is %s" % (here, fallback),
        RuntimeWarning, stacklevel=2,
    )
    return fallback


# Bootstrap the flat tree onto sys.path BEFORE the body import: the body's
# closing rebase imports ``port_ladder``, which still lives there (its
# consolidation is deferred — §15 TS-3 note).  Under pytest this is a
# no-op; it matters for standalone ``import brix_suite.settings`` (guards,
# cmdscripts run outside tests/).
TESTS_DIR = _tests_dir()
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

from brix_suite.settings_values import *          # noqa: F401,F403
from brix_suite.settings_values import _server_host_env  # noqa: F401

from brix_suite import settings_values as _values
from brix_suite.settings_model import SuiteSettings, build_suite_settings  # noqa: F401

# The one default instance (§9.2.1).  Built over the body's computed
# namespace — never re-derived from env — so the typed view cannot drift
# from the module attributes the 690 dependents read.
SETTINGS = build_suite_settings(vars(_values))
