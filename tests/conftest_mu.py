"""Session/function fixtures for the multi-user permission conformance suite.

Loaded as a pytest plugin from tests/conftest.py. The `mu_fleet` fixture is privileged: it
provisions real accounts, seeds the export, renders backends + configs, starts the paired
direct+cache fleet, and reaps everything on teardown. Non-fleet fixtures (`cast`) are usable
during collection and in unprivileged logic tests.
"""
import os

import pytest

from mu_authz_lib import accounts, fleet, policy, ports, principals

_DEFAULT_POLICY = policy.Policy(
    path="/cms/secret.dat", allow=["alice", "svc"], deny=["bob", "carol", "mallory"],
    vo="cms", scope_prefix="storage.read:/cms")


@pytest.fixture(scope="session")
def cast():
    return principals.build_cast()


def _seed_export(cast_map) -> None:
    """Create /cms/secret.dat readable only by svc+alice (mode 0640, owned by svc)."""
    d = os.path.join(ports.MU.DATA_ROOT, "cms")
    os.makedirs(d, exist_ok=True)
    f = os.path.join(d, "secret.dat")
    with open(f, "wb") as fh:
        fh.write(b"S" * 65536)
    try:
        os.chown(f, cast_map["svc"].uid, cast_map["svc"].uid)
        os.chmod(f, 0o640)
    except PermissionError:
        pass  # non-privileged collection/dev; the privileged fleet does this for real


@pytest.fixture(scope="session")
def mu_fleet(cast):
    """Privileged: bring up the paired MU fleet with real accounts; reap on teardown."""
    if os.geteuid() != 0:
        pytest.fail("MU conformance suite requires root (spec D4) — run "
                    "tests/run_multiuser_authz.sh under sudo")
    accounts.sweep_leftover()
    accounts.provision(cast)
    backends = policy.render_policy(_DEFAULT_POLICY, cast)
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


@pytest.fixture
def seed_service_only(cast):
    """Create /cms/service-only.dat readable ONLY by the service identity (mode 0600, svc)."""
    d = os.path.join(ports.MU.DATA_ROOT, "cms")
    os.makedirs(d, exist_ok=True)
    f = os.path.join(d, "service-only.dat")
    with open(f, "wb") as fh:
        fh.write(b"X" * 65536)
    if os.geteuid() == 0:
        os.chown(f, cast["svc"].uid, cast["svc"].uid)
        os.chmod(f, 0o600)
    return "/cms/service-only.dat"


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
