"""Session/function fixtures for the multi-user permission conformance suite.

Loaded as a pytest plugin from tests/conftest.py under its legacy name
``conftest_mu`` (that file is now a §10.2 alias shim onto this module).  The
`mu_fleet` fixture is privileged: it provisions real accounts, seeds the
export, renders backends + configs, starts the paired direct+cache fleet, and
reaps everything on teardown.  Non-fleet fixtures (`cast`) are usable during
collection and in unprivileged logic tests.
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


def _revoke_token(p) -> None:
    from mu_authz_lib import creds
    p.token = creds.mint_token(p.sub, p.scope, p.name, expired=True)


def _revoke_gridmap(p) -> None:
    lines = [ln for ln in open(ports.MU.GRIDMAP).read().splitlines()
             if p.dn not in ln and (not p.krb_princ or p.krb_princ not in ln)]
    with open(ports.MU.GRIDMAP, "w") as f:
        f.write("\n".join(lines) + "\n")


def _reload_fleet() -> None:
    fleet.stop()
    fleet.start()
    fleet.wait_listening(20)


@pytest.fixture
def revoke(cast):
    """Revoke a principal's access by `what` ∈ {token, gridmap}, reload, then RESTORE.

    Both revocations outlive the call that makes them, and neither is a fact this
    test owns: creds.mint_token() writes every mint for a principal to the SAME
    file, TOKENS_DIR/<name>.jwt, so revoking alice OVERWRITES the credential the
    session-scoped `cast` hands to every test after this one; the gridmap is a
    file the whole fleet reads.  Without the restore below, the first test to
    revoke alice left her holding an expired token for the rest of the run, and
    because the HTTP probes present the token by preference, each later test then
    failed setting ITSELF up ("must be cached before revocation") and never
    reached the property it exists to check.  The root:// cells hid it — their
    probe falls back to the GSI proxy — so the davs:// cells beside them appeared
    to be a protocol-specific defect rather than a credential a sibling had
    expired.

    The restore therefore rewinds file CONTENT, not the path (the path never
    changed, which is precisely why saving it restored nothing), and reloads once
    so the fleet the next test meets is the fleet this fixture promised it.
    """
    taken: "list[tuple[str, str]]" = []

    def _save(path):
        with open(path) as fh:
            taken.append((path, fh.read()))

    def _revoke(what, who):
        p = cast[who]
        if what == "token":
            _save(p.token)
            _revoke_token(p)
        elif what == "gridmap":
            _save(ports.MU.GRIDMAP)
            _revoke_gridmap(p)
        _reload_fleet()

    yield _revoke

    if not taken:
        return
    for path, original in reversed(taken):
        with open(path, "w") as fh:
            fh.write(original)
    _reload_fleet()
