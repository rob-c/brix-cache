"""brix_suite — the nginx-xrootd adapter for BriXTest.

This package is where everything repo-specific will live as the
migration (charter §11, TS-1 onward) moves it out of ``tests/``:

- kind profiles for ``nginx`` (custom ``nginx -s quit`` stopper,
  ``logs/nginx.pid``), ``xrootd``/``xrdhttp`` (``run/xrootd.pid``,
  signal-pidfile), ``haproxy``, ``proc``, and ``external``;
- the 126-spec instance catalogue;
- prep steps (CA material, JWT keys, data trees);
- the declaration maps (fixture → specs, port-constant → spec,
  backbone) feeding the undeclared-server gate;
- the ``HarnessConfig`` the CLI and conftest activate
  (``BRIXTEST_APP=brix_suite:app``).

Deliberately empty at BriXTest 0.1.0: the generic core landed first,
ground-up; the adapter is populated by the migration steps, not
invented ahead of them.
"""

import os as _os
import sys as _sys

#: The adapter cannot be imported without the core it registers into, and the
#: core is not installed — it lives at ``brixtest/src`` beside ``tests/``.  Under
#: pytest the conftest puts it on the path; the §10.2 shims each bootstrap it for
#: their own standalone entry points.  Neither helps a bare ``python -c "import
#: brix_suite.security.pki"``, which is how six live drivers reach the PKI
#: generator once it is spelled canonically.  Do it here, once, so importing the
#: adapter by its real name is never the spelling that fails.
_SRC = _os.path.join(
    _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))),
    "brixtest", "src",
)
if _os.path.isdir(_SRC) and _SRC not in _sys.path:
    _sys.path.insert(0, _SRC)

__version__ = "0.1.0"
