"""Perf harnesses — the phase-33 A/B throughput measurers and the load driver.

Nothing is imported here.  ``load_test`` builds its URL constants against the
fixed perf-band ports (12093–12798) at import time and ``_perf_ab_helpers``
reaches into ``_test_a_robustness_helpers`` for the wire framing, so importing
the package would drag both in for anyone who only wanted the other.

**One module of this cluster deliberately did not move**:
``tests/_perf_netem_helpers.py``.  It is the third entry in
``test_server_registry_lint.LAUNCH_BACKLOG`` — a *relative-path*-keyed,
shrink-only allowlist in a pre-TS-4 test file that NG1 holds out of reach until
TS-7.  Moving it would have registered a new direct nginx launcher at the new
path, a second one in its ``_legacy`` archive, and a stale entry at the old
path: three failures in a guard whose whole job is to notice exactly that, and
no way to fix them without editing the file NG1 protects.  It stays flat, keeps
importing ``_perf_ab_helpers`` through the shim, and is carried to TS-7 with the
guard change that makes the move possible.
"""
