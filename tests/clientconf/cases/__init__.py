"""
cases — per-tool differential case tables (pure data).

Each module exposes a ``CASES`` list of ``clientconf.model.Case``.  The matching
``tests/test_clientconf_<tool>.py`` shim parametrizes ``runner.expand(CASES)``
across endpoints and executes them through the runner.

Adding a test = adding a row here.  See ``docs/09-developer-guide/testing/clientconf/README.md``.
"""
