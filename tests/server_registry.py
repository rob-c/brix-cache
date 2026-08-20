"""Registry of pytest-owned test servers — §10.2 self-replacement shim (TS-4).

The verbatim grown body moved to ``brix_suite.registry``.  This file
replaces itself in ``sys.modules`` with the canonical module, so
``import server_registry`` and ``import brix_suite.registry`` are ONE
module object.  That matters more here than anywhere else in the
migration: the registry keeps its state in module-level singletons
(``_SPECS``, ``_COMMAND_SPECS``, ``_REGISTRATION_SITES``, ``_MANIFEST``),
and two module objects would mean two fleets — specs registered by a
conftest under one name, invisible to a launcher importing the other.

``NginxInstanceSpec`` survives as an alias of the canonical
``InstanceSpec``; every existing spelling keeps working.

The explicit sys.path bootstrap makes the shim self-sufficient for
standalone entry points (cmdscripts, guards, ad-hoc ``python -c``) that
import ``server_registry`` from tests/ without pytest's ``pythonpath``
or a conftest having prepared ``brixtest/src``.
"""

import os as _os
import sys as _sys

_SRC = _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
    "brixtest", "src",
)
if _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)

import brix_suite.registry as _canonical

_sys.modules[__name__] = _canonical
