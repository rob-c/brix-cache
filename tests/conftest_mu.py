"""Session/function fixtures for the multi-user permission conformance suite.

Loaded as a pytest plugin from tests/conftest.py. The `mu_fleet` fixture is privileged: it
provisions real accounts, seeds the export, renders backends + configs, starts the paired
direct+cache fleet, and reaps everything on teardown. Non-fleet fixtures (`cast`) are usable
during collection and in unprivileged logic tests.
"""
import os

import pytest

from mu_authz_lib import accounts, corpus, fleet, policy, ports, principals


@pytest.fixture(scope="session")
def cast():
    # cast is evaluated BEFORE mu_fleet (which depends on it), and build_cast()
    # generates VOMS proxies from MU-only service certs that exist only in the
    # privileged MU fleet — off a privileged host it raises, erroring every mu
    # test before mu_fleet's own skip can fire.  Skip here (the earliest mu
    # fixture) so the whole multi-user suite skips cleanly without root.
    if os.geteuid() != 0:
        pytest.skip("MU conformance suite requires root (spec D4) — run "
                    "tests/run_multiuser_authz.sh under sudo")
    return principals.build_cast()


def _seed_export(cast_map) -> None:
    """Create every CORPUS object with its declared owner uid + mode."""
    for obj in corpus.CORPUS:
        full = os.path.join(ports.MU.DATA_ROOT, obj.path.lstrip("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(b"S" * 65536)
        try:
            os.chown(full, cast_map[obj.owner].uid, cast_map[obj.owner].uid)
            os.chmod(full, obj.mode)
        except PermissionError:
            pass  # non-privileged dev; the privileged fleet does this for real


@pytest.fixture(scope="session")
def mu_fleet(cast):
    """Privileged: bring up the paired MU fleet with real accounts; reap on teardown."""
    if os.geteuid() != 0:
        # An unmet ENVIRONMENT requirement (real user accounts + setuid need
        # root) is a skip, not a failure: pytest.fail() here turned every
        # multi-user test into an ERROR in the ordinary non-root full-suite run
        # (~230 cascading errors).  Skip cleanly so the suite stays green off a
        # privileged host; run tests/run_multiuser_authz.sh under sudo to
        # actually exercise them.
        pytest.skip("MU conformance suite requires root (spec D4) — run "
                    "tests/run_multiuser_authz.sh under sudo")
    accounts.sweep_leftover()
    accounts.provision(cast)
    backends = policy.render_corpus_policy(cast)
    _seed_export(cast)
    fleet.render_configs(backends)
    fleet.start()
    fleet.wait_listening(20)
    try:
        yield fleet
    finally:
        fleet.stop()
        accounts.reap()


@pytest.fixture
def apply_policy(cast):
    """Re-render backends for a custom policy and reload the fleet."""
    def _apply(pol):
        backends = policy.render_policy(pol, cast)
        fleet.render_configs(backends)
        fleet.stop()
        fleet.start()
        fleet.wait_listening(20)
    return _apply


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Print the cross-user LEAK LEDGER: every leak-marked failure with its node id (spec §10).
    This is the deliverable that answers 'is per-user access correctly cached?' with evidence."""
    failed = terminalreporter.stats.get("failed", [])
    leaks = [r for r in failed if any(m == "leak" for m in getattr(r, "keywords", {}))]
    if not leaks:
        return
    terminalreporter.write_sep("=", "CROSS-USER LEAK LEDGER (fail-loudly, spec §10)")
    for rep in leaks:
        terminalreporter.write_line(f"  LEAK  {rep.nodeid}")
    terminalreporter.write_line(
        f"  {len(leaks)} cross-user leak(s) — each is a cache/stage serve whose verdict "
        f"diverges from the direct oracle.")


@pytest.fixture
def revoke(cast):
    """Revoke a principal's access by `what` ∈ {token, gridmap} and reload the fleet."""
    def _revoke(what, who):
        p = cast[who]
        if what == "token":
            from mu_authz_lib import creds
            p.token = creds.mint_token(p.sub, p.scope, p.name, expired=True)
        elif what == "gridmap":
            # Drop this principal's line from the gridmap, then reload.
            lines = [ln for ln in open(ports.MU.GRIDMAP).read().splitlines()
                     if p.dn not in ln and (not p.krb_princ or p.krb_princ not in ln)]
            with open(ports.MU.GRIDMAP, "w") as f:
                f.write("\n".join(lines) + "\n")
        fleet.stop()
        fleet.start()
        fleet.wait_listening(20)
    return _revoke
