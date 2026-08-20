"""
test_audit15f_acc_group_resolution.py — OS-group resolution inside the acc
authorization engine (testsuite-combinatorial-coverage-audit 2026-08-15, §B1
zero-coverage appendix): brix_acc_pgo and brix_acc_gidretran were the last two
directives in the audit's 95-name appendix with no coverage of any kind.  Both
decide which `g <group>` rules of an XrdAcc authdb apply to a session, so an
untested value here silently widens or removes access.

The identity comes from `brix_auth unix` — the one scheme where a loopback
client simply declares its name (src/auth/unix/auth.c).  Declaring the account
the test runs as makes the acc engine resolve a REAL Unix gidlist through NSS
(acc/groups.c acc_resolve_unix), which is exactly the input both knobs act on;
no privileges and no fixture users are needed.  The authdb grants one path per
group, so a decision is readable as a single kXR_open.

Both knobs are installed into process globals (acc/config.c →
brix_acc_groups_set_primary_only / _set_gidretran), so every arm is its own
nginx process; the lifecycle fixture gives one per `reason`.

Cases:
  * success       — by default BOTH the primary-group and a supplementary-group
    rule grant, so the gidlist really is the engine's input;
  * security-neg  — with brix_acc_pgo on the supplementary rule stops granting
    (only the primary gid is resolved) while the primary one still does;
  * security-neg  — brix_acc_gidretran <supplementary gid> drops exactly that
    group's rule and leaves the primary one intact;
  * security-neg  — the mirror image: retranning the PRIMARY gid drops the
    primary rule and leaves the supplementary one, so the skip list is keyed on
    the gid itself and is not a synonym for "non-primary";
  * error         — a non-numeric brix_acc_gidretran is silently ignored (the
    parser stops at the first non-digit, XrdAcc best-effort), so a typo skips
    NOTHING and every group rule keeps granting;
  * security-neg  — a group the account does not belong to never grants, in any
    arm, and the denial is kXR_NotAuthorized rather than a missing file.

Run:
    PYTHONPATH=tests pytest tests/test_audit15f_acc_group_resolution.py -v
"""

import getpass
import grp
import os
import pwd
import pathlib
import struct

import pytest

from server_registry import NginxInstanceSpec
from settings import NGINX_BIN, BIND_HOST, HOST
from test_pgwrite_cse import _handshake_login, kXR_ok
from test_unix_auth_wire import _auth, _open_read

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.timeout(120),
              pytest.mark.xdist_group("lc-audit15f-accgrp")]

KXR_NOT_AUTHORIZED = 3010          # "xrdacc denied"
KXR_NOT_FOUND = 3011               # a seeding slip, never an authz verdict

NO_SUCH_GROUP = "brix-no-such-group"
RULE_DIRS = ("u-own", "g-prim", "g-supp", "g-none")
SEED = b"acc group resolution\n"


def _identity():
    """(user, primary group name, primary gid, supplementary name, gid).

    Skips when the account has no supplementary group: without one there is no
    difference for brix_acc_pgo to make.
    """
    user = getpass.getuser()
    try:
        entry = pwd.getpwnam(user)
    except KeyError:                                 # pragma: no cover
        pytest.skip(f"{user} is not a local NSS account")
    for gid in os.getgrouplist(user, entry.pw_gid):
        if gid == entry.pw_gid:
            continue
        try:
            supp = grp.getgrgid(gid).gr_name
        except KeyError:
            continue
        return (user, grp.getgrgid(entry.pw_gid).gr_name, entry.pw_gid,
                supp, gid)
    pytest.skip(f"{user} has no resolvable supplementary group")


def _start(lifecycle, tmp_path, reason, extra=""):
    """One acc server for one arm; returns (endpoint, identity)."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    ident = _identity()
    user, prim, _pgid, supp, _sgid = ident
    authdb = tmp_path / "authdb"
    authdb.write_text(f"u {user} /u-own rl\n"
                      f"g {prim} /g-prim rl\n"
                      f"g {supp} /g-supp rl\n"
                      f"g {NO_SUCH_GROUP} /g-none rl\n")
    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15f-accgrp",
        template="nginx_audit15f_accgroups.conf",
        protocol="root",
        readiness="tcp",
        template_values={"BIND_HOST": BIND_HOST, "AUTHDB": str(authdb),
                         "ACC_EXTRA": extra},
        reason=reason))
    for name in RULE_DIRS:
        directory = pathlib.Path(endpoint.data_root) / name
        directory.mkdir(exist_ok=True)
        (directory / "f.txt").write_bytes(SEED)
    return endpoint, ident


def _open_as(endpoint, user, path):
    """Authenticate as `user` over unix auth and open `path`.

    Returns "granted", or the kXR error code behind the refusal — so an authz
    denial (3010) can never be confused with a seeding slip (3011).
    """
    sock = _handshake_login(host=HOST, port=endpoint.port)
    try:
        status, errcode, _ = _auth(sock, b"unix\x00" + user.encode())
        assert status == kXR_ok, f"unix auth refused: {status}/{errcode}"
        status, body = _open_read(sock, path.encode())
        if status == kXR_ok:
            return "granted"
        return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else None
    finally:
        sock.close()


def _verdicts(endpoint, user):
    """The four rule paths' verdicts in one dict, for whole-arm assertions."""
    return {name: _open_as(endpoint, user, f"/{name}/f.txt")
            for name in RULE_DIRS}


# ── the baseline: the OS gidlist is what `g` rules match ──────────────────

def test_both_group_rules_grant_by_default(lifecycle, tmp_path):
    """success: with neither knob set the engine resolves the full gidlist, so
    the primary-group rule AND the supplementary-group rule both grant.  This
    is the control every arm below is measured against; the `u` rule proves the
    identity itself arrived, and /g-none proves an unheld group never grants."""
    endpoint, (user, _p, _pg, _s, _sg) = _start(
        lifecycle, tmp_path, "audit-15f acc group resolution baseline")
    assert _verdicts(endpoint, user) == {
        "u-own": "granted", "g-prim": "granted", "g-supp": "granted",
        "g-none": KXR_NOT_AUTHORIZED}


# ── brix_acc_pgo: resolve the primary group only ──────────────────────────

def test_pgo_drops_every_supplementary_group(lifecycle, tmp_path):
    """security-negative: brix_acc_pgo on replaces getgrouplist() with the
    passwd entry's primary gid alone, so a rule keyed on a supplementary group
    stops applying — the narrowing this knob exists for.  The primary rule
    still grants, so this is a narrowing and not a wholesale loss of group
    resolution."""
    endpoint, (user, _p, _pg, _s, _sg) = _start(
        lifecycle, tmp_path, "audit-15f brix_acc_pgo primary-group-only",
        extra="brix_acc_pgo on;")
    assert _verdicts(endpoint, user) == {
        "u-own": "granted", "g-prim": "granted",
        "g-supp": KXR_NOT_AUTHORIZED, "g-none": KXR_NOT_AUTHORIZED}


# ── brix_acc_gidretran: skip named gids during resolution ─────────────────

def test_gidretran_drops_exactly_the_listed_supplementary_gid(lifecycle,
                                                              tmp_path):
    """security-negative: listing the supplementary gid makes acc_gid_retran
    skip it before getgrgid(), so no group NAME is ever produced for it and its
    rule cannot apply.  The primary group, absent from the list, still does."""
    ident = _identity()
    endpoint, (user, _p, _pg, _s, _sg) = _start(
        lifecycle, tmp_path, "audit-15f brix_acc_gidretran supplementary gid",
        extra=f"brix_acc_gidretran {ident[4]};")
    assert _verdicts(endpoint, user) == {
        "u-own": "granted", "g-prim": "granted",
        "g-supp": KXR_NOT_AUTHORIZED, "g-none": KXR_NOT_AUTHORIZED}


def test_gidretran_drops_the_primary_gid_just_as_readily(lifecycle, tmp_path):
    """security-negative (the mirror image): the skip list is keyed on the gid,
    not on "supplementary", so retranning the PRIMARY gid drops the primary
    rule and leaves the supplementary one granting.  Pinning both directions
    separates this knob from brix_acc_pgo, which the arm above shares a shape
    with."""
    ident = _identity()
    endpoint, (user, _p, _pg, _s, _sg) = _start(
        lifecycle, tmp_path, "audit-15f brix_acc_gidretran primary gid",
        extra=f"brix_acc_gidretran {ident[2]};")
    assert _verdicts(endpoint, user) == {
        "u-own": "granted", "g-prim": KXR_NOT_AUTHORIZED,
        "g-supp": "granted", "g-none": KXR_NOT_AUTHORIZED}


def test_a_non_numeric_gidretran_is_silently_ignored(lifecycle, tmp_path):
    """error: the gid list is parsed best-effort at runtime (XrdAcc parity —
    brix_acc_groups_set_gidretran stops at the first non-digit and logs
    nothing), and the directive itself is a plain string slot, so `nginx -t`
    accepts a typo.  The result is a skip list that skips NOTHING: every group
    rule keeps granting.  Pinned because it fails OPEN — an operator who
    misspells the value gets the baseline, not a refusal."""
    endpoint, (user, _p, _pg, _s, _sg) = _start(
        lifecycle, tmp_path, "audit-15f brix_acc_gidretran typo is inert",
        extra="brix_acc_gidretran not-a-gid;")
    assert _verdicts(endpoint, user) == {
        "u-own": "granted", "g-prim": "granted", "g-supp": "granted",
        "g-none": KXR_NOT_AUTHORIZED}


def test_a_denied_path_is_refused_as_unauthorized_not_missing(lifecycle,
                                                              tmp_path):
    """security-negative: every denial above must be an authorization verdict.
    The rule paths are all seeded, so a kXR_NotFound would mean the arms were
    reading an absent file and proving nothing; assert both codes explicitly on
    one arm to keep that reading honest."""
    endpoint, (user, _p, _pg, _s, _sg) = _start(
        lifecycle, tmp_path, "audit-15f acc denial is an authz verdict",
        extra="brix_acc_pgo on;")
    assert _open_as(endpoint, user, "/g-supp/f.txt") == KXR_NOT_AUTHORIZED
    assert _open_as(endpoint, user, "/u-own/f.txt") == "granted"
    assert _open_as(endpoint, user, "/u-own/absent.txt") == KXR_NOT_FOUND
