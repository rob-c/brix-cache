"""brix_suite.harness — the grown conftest machinery, absorbed module by module.

TS-2 (testsuite-modernization-plan §11) moves the conftest constellation's
separable halves here verbatim:

- ``kill_tracer``  — the fleet sentinel's forensic half (os.kill / Popen
  wrapping + the per-test nodeid the tracer attributes kills to);
- ``sentinel``     — the arbiter half (fleet-health baseline, conservation
  check, watchdog) plus the two per-test sentinel hooks;
- ``fixtures``     — the session/service fixtures and the matrix
  parametrization layer.

``tests/conftest.py`` imports these and re-exports every name into its own
namespace, so pytest collection, the exec-composed lifecycle shards and the
by-path pinning suite (tests/test_conftest_fleet_lifecycle.py) all keep
working unchanged.  Nothing here is imported by ``brixtest`` (the generic
core must never depend on the adapter) and nothing runs at
``import brix_suite`` time — these modules load only when the conftest (or a
test) asks for them.
"""
