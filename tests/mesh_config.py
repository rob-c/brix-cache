"""Mesh config-template rendering — §10.2 self-replacement shim (TS-5).

The body moved to :mod:`brix_suite.mesh.mesh_config` (pre-move body archived
at ``brix_suite/_legacy/mesh_config_flat.py``).  ``CONFIGS_DIR`` is now named
from the settings module's searched suite root instead of this file's parent,
because the templates stayed in ``tests/configs/mesh/`` and the module did not.
"""

import os as _os
import sys as _sys

_TESTS = _os.path.dirname(_os.path.abspath(__file__))
_SRC = _os.path.join(_os.path.dirname(_TESTS), "brixtest", "src")
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)
if _TESTS not in _sys.path:
    _sys.path.insert(0, _TESTS)

import brix_suite.mesh.mesh_config as _canonical

_sys.modules[__name__] = _canonical
