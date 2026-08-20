"""
test_audit15g_authdb_load_failure.py — what happens when the authorization
database does not parse (audit §B1.7, the row the authdb tests never reached:
every existing acc test hands the server a VALID authdb).

An authdb is a text file an operator edits by hand, in production, to change who
may read what.  The interesting states of that file are therefore not "correct"
— they are "correct until someone appended a line".  This file drives the two
places brix reads one, because they handle the same broken file in two
completely different ways:

  * at WORKER START (brix_acc_init_server, auth/authz/acc/config.c:239), a parse
    failure returns NGX_ERROR and takes the worker down;
  * on a REFRESH TIMER (brix_acc_refresh_handler, config.c:57), a parse failure
    is swallowed and the previous tables keep enforcing — the swap is guarded by
    `if (nt != NULL)`.

THE FINDING — DEFECT CANDIDATE #20.  A malformed `brix_authdb` passes
`nginx -t`.  The authdb is built per-worker from init_process
(core/config/process_server_init.c:438), and `-t` runs neither init_process nor
any worker, so the validation an operator performs before a restart cannot see
the error at all.  What happens next is the part that matters: every worker logs
[emerg] and exits 2, nginx declines to respawn them ("cannot be respawned"), and
the MASTER stays up holding the listening sockets.  The plane therefore still
ACCEPTS TCP connections and then answers nothing, so a client hangs until its
own timeout instead of being refused — and a health check that only proves the
port is open reports the site as healthy.

The refresh arm is the counter-example that makes the first one a defect rather
than a policy: the same broken file, delivered a second later through the timer,
is handled exactly as it should be.  It is also the direction that must never
invert — a reload that failed open, granting what the last good file denied,
would turn a typo into an authorization bypass, so that is asserted from both
sides (the granted path stays granted, the denied path stays denied).

Cases:
  * success      — a valid authdb serves the path its rules grant
  * sec-negative — the same authdb refuses the path it does not name (3010)
  * defect pin   — a malformed authdb passes `nginx -t`, kills every worker, and
                   leaves the plane accepting connections it will never answer
  * success      — a VALID edit is picked up by the refresh timer (the control:
                   without it, the case below could pass because the timer never
                   fired at all)
  * sec-negative — a MALFORMED edit is refused and the last good tables stay in
                   force, on both the grant and the deny side
"""

import os
import socket
import subprocess
from pathlib import Path

import pytest

from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS
from server_registry import NginxInstanceSpec
from settings import HOST, BIND_HOST, NGINX_BIN
from _test_audit15g_helpers import open_fails, read_whole, seed_tree, wait_until
from _test_phase25_ratelimit_helpers import _xrd_login

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15g-badacc")]

NAME = "lc-audit15g-badacc"
REFRESH_PORT = LIFECYCLE_SHARED_PORTS[NAME]["extra"]["REFRESH_PORT"]

XERR_NOT_AUTHORIZED = 3010

SEED = b"audit15g-authdb-load-failure\n" * 32
GRANTED = "/pub/obj.bin"
DENIED = "/priv/obj.bin"

# One `u *` record, two <path> <privs> pairs would be the way to grant both; this
# grants only /pub, so /priv is denied by omission rather than by a rule.
GOOD = "u * /pub rl\n"
# The mistake an operator actually makes: a second record for the same identity,
# added to grant one more path.  Only ONE record per identity is legal — the
# second is "duplicate rule for id" and the whole file is rejected
# (auth/authz/acc/authfile_record.c:441).
BROKEN = "u * /pub rl\nu * /priv rl\n"


# The refresh timer compares mtimes at SECOND resolution (ngx_file_mtime), so an
# edit has to land on a strictly different second to be seen at all.  Fixed dates
# rather than "now + a few seconds": two writes a fraction of a second apart both
# truncate to the same second, and this host's clock is not monotonic anyway
# (WSL2 steps it backwards).  Same epochs as TestHttpHotReload in
# test_acc_residual.py — 2020-01-01 and 2024-06-01.
AUTHDB_MTIME, AUTHDB_MTIME_EDITED = 1577836800, 1717200000


def _write_authdb(path, text, *, mtime=AUTHDB_MTIME):
    path.write_text(text)
    os.chmod(path, 0o644)
    os.utime(path, (mtime, mtime))


@pytest.fixture
def plane(lifecycle, tmp_path):
    """`start(static=..., refresh=..., reason=...) -> (endpoint, paths)`.

    A factory rather than a plain fixture because the authdb's CONTENT is the
    variable under test and it has to be on disk before the worker starts: the
    static plane reads it exactly once, and there is no second chance to change
    what it read."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    def _start(*, static=GOOD, refresh=GOOD, reason):
        dirs = {name: tmp_path / name for name in ("static", "refresh")}
        for path in dirs.values():
            path.mkdir()
            os.chmod(path, 0o777)
        os.chmod(tmp_path, 0o777)
        for path in dirs.values():
            seed_tree(path, {GRANTED: SEED, DENIED: SEED})

        authdbs = {"static": tmp_path / "static.authdb",
                   "refresh": tmp_path / "refresh.authdb"}
        _write_authdb(authdbs["static"], static)
        _write_authdb(authdbs["refresh"], refresh)

        endpoint = lifecycle.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_audit15g_badacc.conf",
            protocol="root",
            readiness="tcp",
            data_root=str(dirs["static"]),
            template_values={
                "BIND_HOST": BIND_HOST,
                "STATIC_DIR": str(dirs["static"]),
                "STATIC_AUTHDB": str(authdbs["static"]),
                "REFRESH_DIR": str(dirs["refresh"]),
                "REFRESH_AUTHDB": str(authdbs["refresh"])},
            reason=reason))
        return endpoint, authdbs

    return _start


def _log(endpoint):
    path = Path(endpoint.prefix, "logs", "error.log")
    return path.read_text(errors="replace") if path.exists() else ""


def _wait(endpoint, predicate, *, what, timeout=20):
    """`wait_until` with the server's log attached to the failure.  Everything
    waited on here is a decision the worker logged as it made it, so a timeout
    without the log says only that something did not happen."""
    try:
        return wait_until(predicate, timeout=timeout, tick=0.5, what=what)
    except AssertionError as exc:
        raise AssertionError(
            f"{exc}\n--- error.log (tail) ---\n{_log(endpoint)[-3000:]}") from exc


# --------------------------------------------------------------------------- #
# the authdb the worker read at start
# --------------------------------------------------------------------------- #

def test_a_valid_authdb_serves_the_path_its_rules_grant(plane):
    """success: the baseline every case below is attributed against.  `rl` on
    /pub is read+lookup, which is exactly what an open-for-read needs, so a
    failure here is the engine and not the rule."""
    endpoint, _authdbs = plane(reason="audit-15g authdb: valid, static plane")

    assert read_whole(endpoint.port, GRANTED, len(SEED)) == SEED


def test_a_valid_authdb_refuses_the_path_it_does_not_name(plane):
    """security-negative: /priv exists on disk and is world-readable — the only
    thing standing between the client and it is the authdb.  An authdb that
    grants what it names but does not DENY what it omits is not an authorization
    database, so this is the half of the baseline that actually matters."""
    endpoint, _authdbs = plane(reason="audit-15g authdb: valid, static plane")

    assert open_fails(endpoint.port, DENIED) == XERR_NOT_AUTHORIZED
    # And the grant still works in the same process: a plane that refuses
    # everything would pass the line above for entirely the wrong reason.
    assert read_whole(endpoint.port, GRANTED, len(SEED)) == SEED


def test_a_malformed_authdb_passes_config_test_then_kills_every_worker(plane):
    """DEFECT PIN — CANDIDATE #20.  The authdb below cannot parse.  Three things
    are measured, in the order an operator meets them:

      1. `nginx -t` accepts the configuration.  It has to: the launcher gates
         every start on it, so reaching the assertions at all is already the
         first half of the finding.  It is re-run explicitly anyway, because
         that is the command a site runs before a restart and its exit status is
         the whole basis for trusting the restart.
      2. The workers are gone — [emerg] on the authdb, exit 2, and nginx's
         "cannot be respawned".
      3. The plane still ACCEPTS a TCP connection, and then never speaks.  The
         master outlives its workers holding the listening sockets, so the
         failure presents to a client as a hang and to a port-probing health
         check as a healthy server.

    WHEN THIS IS FIXED the expected shape is that the authdb is parsed during
    configuration (so `nginx -t` fails and returncode is non-zero), and this
    test inverts to assert that — the connection assertions then have no plane
    to run against and go away with it.  A weaker fix that keeps the parse in
    the worker must at least stop the master from surviving with bound
    listeners, in which case `_xrd_login` raises ConnectionRefusedError instead
    of timing out and only that assertion changes."""
    endpoint, _authdbs = plane(static=BROKEN,
                               reason="audit-15g authdb: malformed, static")

    # INVERT WHEN FIXED: returncode != 0, and the stderr names the authdb.
    checked = subprocess.run(
        [NGINX_BIN, "-t", "-p", endpoint.prefix, "-c", "conf/nginx.conf"],
        capture_output=True, text=True, check=False)
    assert checked.returncode == 0, (
        "`nginx -t` now rejects a malformed authdb — invert this test: "
        f"{checked.stderr}")

    log = _wait(endpoint,
                lambda: _log(endpoint) if "cannot be respawned" in _log(endpoint)
                else None,
                what="the worker to die on the authdb", timeout=15)
    assert "duplicate rule for id" in log, log[-2000:]
    assert "failed to load authorization database" in log, log[-2000:]

    # The listener is still bound: this is a connect(), and it succeeds.
    with socket.create_connection((HOST, endpoint.port), timeout=5):
        pass
    # And nothing behind it ever answers the handshake.
    with pytest.raises(TimeoutError):
        _xrd_login(HOST, endpoint.port)


# --------------------------------------------------------------------------- #
# the authdb the refresh timer re-read
# --------------------------------------------------------------------------- #

def test_a_valid_edit_is_picked_up_by_the_refresh_timer(plane):
    """success, and the control for the case below.  Without proof that the
    timer fires and swaps, "the broken edit changed nothing" would be equally
    well explained by "no edit ever changes anything", which is the wrong
    conclusion and the reassuring one."""
    endpoint, authdbs = plane(reason="audit-15g authdb: valid edit, refresh")

    assert open_fails(REFRESH_PORT, DENIED) == XERR_NOT_AUTHORIZED
    _write_authdb(authdbs["refresh"], "u * /pub rl /priv rl\n",
                  mtime=AUTHDB_MTIME_EDITED)

    _wait(endpoint, lambda: open_fails(REFRESH_PORT, DENIED) == 0,
          what="the refreshed authdb to grant /priv")
    assert "xrootd authdb reloaded" in _log(endpoint)


def test_a_malformed_edit_leaves_the_last_good_tables_enforcing(plane):
    """security-negative: the file the worker is re-reading stops parsing.  The
    rebuild must be discarded, not installed — and "discarded" has to mean the
    PREVIOUS tables, not an empty set, because both ways of getting that wrong
    are silent:

      * failing OPEN turns a typo in an authdb into an authorization bypass —
        /priv would start answering;
      * failing CLOSED turns it into an outage that looks like a permissions
        change — /pub would stop.

    Both directions are asserted, after waiting for the parse error in the log
    so this is a measurement of the reload rather than of the timer's period."""
    endpoint, authdbs = plane(reason="audit-15g authdb: malformed edit, refresh")

    assert read_whole(REFRESH_PORT, GRANTED, len(SEED)) == SEED
    assert open_fails(REFRESH_PORT, DENIED) == XERR_NOT_AUTHORIZED

    _write_authdb(authdbs["refresh"], BROKEN, mtime=AUTHDB_MTIME_EDITED)
    _wait(endpoint, lambda: "duplicate rule for id" in _log(endpoint),
          what="the refresh timer to reject the file")

    assert open_fails(REFRESH_PORT, DENIED) == XERR_NOT_AUTHORIZED, \
        "a broken authdb granted a path the last good one denied"
    assert read_whole(REFRESH_PORT, GRANTED, len(SEED)) == SEED, \
        "a broken authdb revoked a path the last good one granted"
    assert "xrootd authdb reloaded" not in _log(endpoint), \
        "the server logged a successful reload of a file that does not parse"
