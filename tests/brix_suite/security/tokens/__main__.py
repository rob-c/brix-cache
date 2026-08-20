"""``python -m brix_suite.security.tokens`` -- the forge CLI.

The subcommands (``manifest``, ``fleet-artifacts``) are unchanged from the flat
``tokenforge.py`` CLI; only the spelling of the entry point is new.  The flat
name still works, through the shim in ``tests/tokenforge.py``.
"""

from brix_suite.security.tokens.manifest import main

raise SystemExit(main())
