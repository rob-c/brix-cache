"""Per-caller SSS identity on the FUSE mount (phase-115 W7.2a, audit §7.10).

The parity audit's other half of that row is "no per-user sss identity": stock
XrootdFS opens one connection as the mount owner, so every local user reaching
a shared mount is the same principal at the server and the server's own authz
can never distinguish them. `--sss-identity` (client/apps/fs/xrootdfs_identity.c)
gives each caller uid its own pool/mgr, logged in under that caller's own name.

That is only safe because of what the SERVER does with a proposed name, and
that is what this file's live half proves on the wire:

  * success   — under an `anybody` key the proposed name is the identity, and
                two different names on one server are two different identities
                (the entire point of a per-caller table)
  * error     — an empty proposed name is mapped to "nobody", not to the
                connecting account and not to a crash
  * security  — a keytab minted for a FIXED user IGNORES the proposed name
                entirely.  `--sss-identity` therefore cannot escalate: it can
                only ask, and what an operator's keytab issues is the ceiling.
                A client that proposes "root" against `u:svc` is logged as
                "svc".

Plus one compat note the cross turned up: `BRIX_SSS_OPT_NOIPCK` (a keytab name
ending in `+`) is parsed by src/auth/sss/config.c:75-78 and then consulted
nowhere in the tree.  In stock XrdSecsss the `+` suppresses a client-IP check;
brix performs no such check at all, so the suffix is inert.  Pinned live rather
than by grep, because "inert" is a behavioural claim.

The client half cannot be driven here — it needs a real FUSE mount with several
uids — so the table's decisions are pinned by static guards instead.  They are
not decoration: every one of them is a property that, if it silently flipped,
would hand a request to the WRONG identity rather than fail.

Nothing external is needed: _test_sss_helpers mints the credential in Python
(see test_audit15h_tpc_sss.py for the same technique), so this runs without the
native client built.

Run (serial):
    PYTHONPATH=tests pytest tests/test_phase115_fuse_caller_identity.py -v
"""

import os
import re
import time

import pytest

from _test_sss_helpers import sss_auth_frame, sss_credential, sss_write_keytab
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST
from test_phase25_ratelimit import KXR_OK, _xrd_login, _xrd_recv_status

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p115-sss-ident")]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
IDENT_C = os.path.join(CLIENT_DIR, "apps", "fs", "xrootdfs_identity.c")
XFS_C = os.path.join(CLIENT_DIR, "apps", "fs", "xrootdfs.c")
XFS_IO_C = os.path.join(CLIENT_DIR, "apps", "fs", "xrootdfs_io.c")
XFS_INT_H = os.path.join(CLIENT_DIR, "apps", "fs", "xrootdfs_internal.h")
USAGE_C = os.path.join(CLIENT_DIR, "apps", "fs", "xrootdfs_usage.c")
MAKEFILE = os.path.join(CLIENT_DIR, "Makefile")

SECRET = bytes(range(1, 17))


# --------------------------------------------------------------------------
# live: what the server does with a proposed identity
# --------------------------------------------------------------------------

def _server(lifecycle, tmp_path, tag, user, group, name):
    """One stream instance whose keytab issues (user, group) under `name`."""
    data = tmp_path / f"data-{tag}"
    data.mkdir()
    (data / "probe.txt").write_bytes(b"ident-ok\n")

    keytab = str(tmp_path / f"{tag}.keytab")
    sss_write_keytab(keytab, SECRET, key_id=1, user=user, group=group,
                     name=name)

    return lifecycle.start(NginxInstanceSpec(
        name=f"lc-p115-sss-ident-{tag}",
        template="nginx_lc_native_sss.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data),
                         "KEYTAB": keytab},
        reason=f"phase-115 W7.2a: sss keytab issuing u:{user} g:{group}."))


@pytest.fixture()
def anybody(lifecycle, tmp_path):
    """`u:anybody g:anygroup` — the key a per-caller mount would be given."""
    return _server(lifecycle, tmp_path, "any", "anybody", "anygroup",
                   "brixtest")


@pytest.fixture()
def fixed(lifecycle, tmp_path):
    """`u:svc` — a service keytab. The proposed name must not be able to
    move the identity off `svc`."""
    return _server(lifecycle, tmp_path, "svc", "svc", "svcgrp", "brixtest")


@pytest.fixture()
def plus_name(lifecycle, tmp_path):
    """The same anybody key with a `+` name suffix (NOIPCK)."""
    return _server(lifecycle, tmp_path, "plus", "anybody", "anygroup",
                   "brixtest+")


def _propose(endpoint, username):
    """Authenticate proposing `username`. Returns the server's auth status."""
    s = _xrd_login(HOST, endpoint.port)
    try:
        s.sendall(sss_auth_frame(sss_credential(SECRET, username=username)))
        status, body = _xrd_recv_status(s)
    finally:
        s.close()
    return status, body


_OK_LINE = re.compile(r'SSS auth OK user="([^"]*)" group="([^"]*)"')


def _identities(endpoint, expect, timeout=10.0):
    """Every (user, group) the server logged, once at least `expect` are there.

    Polled: the auth reply reaches the socket before the worker's log write is
    necessarily flushed, so asserting on a single read races the server rather
    than testing it.
    """
    path = os.path.join(endpoint.prefix, "logs", "error.log")
    deadline = time.time() + timeout
    found = []
    while time.time() < deadline:
        try:
            with open(path, errors="replace") as fh:
                found = _OK_LINE.findall(fh.read())
        except FileNotFoundError:
            found = []
        if len(found) >= expect:
            return found
        time.sleep(0.2)
    return found


def test_a_proposed_name_becomes_the_identity(anybody):
    """(success) Under an anybody key the caller's own login name is what the
    server authenticates — the property the per-caller table depends on."""
    status, body = _propose(anybody, "alice")
    assert status == KXR_OK, ("sss auth refused", status, body)

    ids = _identities(anybody, 1)
    assert ids, "the server logged no SSS auth at all"
    assert ids[-1][0] == "alice", ids
    # No group TLV is sent, and the key is anygroup, so the mapping's own
    # placeholder must appear rather than the key's group or an empty string.
    assert ids[-1][1] == "nogroup", ids


def test_two_callers_are_two_identities(anybody):
    """(success) The same server, two names, two distinct authenticated users.
    If the server collapsed them, a per-caller mount would be theatre."""
    for who in ("alice", "bob"):
        status, body = _propose(anybody, who)
        assert status == KXR_OK, (who, status, body)

    ids = _identities(anybody, 2)
    users = [u for u, _ in ids]
    assert users[-2:] == ["alice", "bob"], users


def test_an_empty_proposed_name_maps_to_nobody(anybody):
    """(error) A caller with no resolvable login name still has to land
    somewhere defined.  It must be the anonymous placeholder — never the
    account nginx runs as, and never a refused-then-retried loop."""
    status, body = _propose(anybody, "")
    assert status == KXR_OK, ("empty name should authenticate", status, body)

    ids = _identities(anybody, 1)
    assert ids and ids[-1][0] == "nobody", ids


def test_a_fixed_keytab_ignores_the_proposed_name(fixed):
    """(security) THE escalation negative for --sss-identity.

    The client proposes "root".  The keytab issues `u:svc`, so ANYUSR is not
    set and sss_map_identity keeps `key->user`.  A per-caller identity can
    therefore only ever be what the operator's keytab already grants: the
    client half asks, the server half decides, and asking for root gets svc.
    """
    status, body = _propose(fixed, "root")
    assert status == KXR_OK, ("sss auth refused", status, body)

    ids = _identities(fixed, 1)
    assert ids, "the server logged no SSS auth at all"
    assert ids[-1][0] == "svc", f"proposed name escaped the keytab: {ids}"
    assert ids[-1][0] != "root"
    assert ids[-1][1] == "svcgrp", ids


def test_the_noipck_name_suffix_changes_nothing(plus_name):
    """(compat) A keytab name ending in `+` sets BRIX_SSS_OPT_NOIPCK, which is
    derived in src/auth/sss/config.c and then read nowhere.  In stock XrdSecsss
    it suppresses a client-IP check; brix has no such check, so the flag is
    inert and the suffix must not change the identity.  Pinned live so the day
    someone wires an IP check up, this row says what used to be true."""
    status, body = _propose(plus_name, "alice")
    assert status == KXR_OK, ("the '+' suffix broke auth", status, body)

    ids = _identities(plus_name, 1)
    assert ids and ids[-1] == ("alice", "nogroup"), ids


# --------------------------------------------------------------------------
# static: the client-side table's decisions
# --------------------------------------------------------------------------

def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)


def _code(path):
    """The file with comments blanked out — every header below explains the
    behaviour it forbids, and a raw scan would read the warning as the offence.
    Newlines are preserved so line arithmetic holds."""
    return _COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)),
                        _read(path))


_FUNC = re.compile(r"^([a-z_][a-z_0-9]*)\(.*?^\}", re.M | re.S)


def _functions(text):
    return {m.group(1): m.group(0) for m in _FUNC.finditer(text)}


class TestIdentityNeverFallsBack:
    """The refusal is the feature."""

    def test_a_failure_refuses_instead_of_using_the_mount_owner(self):
        """(security) Serving a caller's request over the mount owner's
        connection is exactly the pre-W7.2a behaviour, and it would now be
        SILENT — the caller asked to be someone else and was not told they
        weren't.  The failure path must reach neither g_pool nor g_mgr."""
        get = _functions(_code(IDENT_C))["xfs_ident_get"]
        head, _, tail = get.partition("e = ident_get(uid);")
        assert tail, "xfs_ident_get no longer resolves through ident_get"
        # The mount-wide pair may only be handed out on the "feature off" path,
        # which precedes the lookup.
        assert "g_pool" in head and "g_mgr" in head, \
            "the --sss-identity-off passthrough disappeared"
        for owner in ("g_pool", "g_mgr"):
            assert owner not in tail, \
                f"{owner} is reachable after an identity lookup — silent fallback"

    def test_the_two_failures_stay_distinguishable(self):
        """(error) -EMFILE is an operator capacity limit (raise the table),
        -EACCES is this identity failing to authenticate.  Collapsing them
        turns a fixable misconfiguration into an unexplained permission
        error."""
        get = _functions(_code(IDENT_C))["xfs_ident_get"]
        assert "-EMFILE" in get and "-EACCES" in get, \
            "the two identity failures were collapsed into one errno"
        assert "ident_full(uid)" in get, \
            "nothing distinguishes a full table from a failed login any more"

    def test_the_flag_is_both_parsable_and_documented(self):
        """(error) A security-relevant flag that --help never mentions is
        shipped only to whoever read the diff."""
        assert '"--sss-identity"' in _code(XFS_C), \
            "--sss-identity is not matched by the option parser"
        assert "--sss-identity" in _read(USAGE_C), \
            "--sss-identity is absent from the usage text"


class TestIdentityTableLifetime:
    """Why a pointer handed to a caller stays valid."""

    def test_no_slot_is_ever_released(self):
        """(security) A slot reused for a second uid would leave an in-flight
        request holding a pool that now belongs to somebody else — a
        use-after-free at best and a cross-identity read at worst.  Refcounting
        would be the alternative; not recycling is the cheaper correctness."""
        for name, body in _functions(_code(IDENT_C)).items():
            assert "used     = 0" not in body and "used = 0" not in body, \
                f"{name} releases a slot — slots must not be recycled"

    def test_only_the_builder_and_shutdown_destroy_a_connection(self):
        """(security) Everything else in the file may only ever hand a slot's
        pool/mgr out.  A teardown anywhere else frees connections some other
        thread is mid-request on."""
        allowed = ("ident_build", "xfs_ident_shutdown")
        for name, body in _functions(_code(IDENT_C)).items():
            if name in allowed:
                continue
            hit = [d for d in ("brix_pool_destroy", "brix_mgr_destroy")
                   if d in body]
            assert not hit, f"{name} tears down a live identity: {hit}"

    def test_a_rolled_back_slot_is_poisoned_not_reopened(self):
        """(error) ident_build's rollback is the one destroy on a slot a caller
        could still be told about.  It must leave the slot unusable rather than
        holding a freed pointer: clear the field and mark the slot failed."""
        build = _functions(_code(IDENT_C))["ident_build"]
        for destroy in ("brix_pool_destroy(e->pool)", "brix_mgr_destroy(e->mgr)"):
            if destroy not in build:
                continue
            after = build[build.index(destroy):]
            assert "NULL" in after, f"{destroy} leaves a freed pointer in the slot"
        assert "e->failed = 1" in build, \
            "a rolled-back slot is not marked failed and would be handed out"

    def test_shutdown_still_frees_the_table(self):
        """(success) The one place teardown belongs must still do it, or every
        identity's connections leak for the life of the mount."""
        shutdown = _functions(_code(IDENT_C))["xfs_ident_shutdown"]
        assert "brix_pool_destroy" in shutdown and "brix_mgr_destroy" in shutdown, \
            "shutdown stopped freeing the table's connections"

    def test_the_connect_happens_outside_the_table_lock(self):
        """(error) Building a pool means a TCP connect and an auth round trip.
        Holding the table mutex across it would make one user's slow or
        blackholed server stall every other user's metadata op on the mount.
        The `creating` flag is what keeps other threads off the slot instead."""
        fns = _functions(_code(IDENT_C))
        build = fns["ident_build"]
        for lock in ("pthread_mutex_lock", "pthread_mutex_unlock"):
            assert lock not in build, \
                f"ident_build takes the table lock ({lock}) around a connect"
        get = fns["ident_get"]
        assert "creating" in get and "pthread_cond" in get, \
            "the creating/condvar handshake that replaces the lock is gone"
        assert "pthread_mutex_unlock" in get[:get.index("ident_build(")], \
            "ident_build is called while the table lock is still held"

    def test_the_table_is_bounded(self):
        """(error) One pool per caller uid on a shared mount is unbounded
        without a cap; the cap is what turns exhaustion into -EMFILE rather
        than into fd starvation."""
        code = _code(IDENT_C)
        assert "g_ident_max" in code, "the identity table lost its cap"
        init = _functions(code)["xfs_ident_init"]
        assert "g_ident_max" in init, "the cap is not applied at init"


class TestIdentityCoversTheDataPlane:
    """Mapping metadata alone would be theatre."""

    def test_open_resolves_the_caller_identity_too(self):
        """(security) kXR_open is where the server decides whether this
        principal may have the bytes.  If only stat/readdir carried the
        caller's identity, every actual read and write would still run as the
        mount owner — the authz bypass would be the default."""
        io = _code(XFS_IO_C)
        assert "xfs_ident_get(" in io, \
            "the data plane no longer resolves the caller's identity"
        assert "brix_mgr_pick(" in io, "the open path changed shape"
        opn = _functions(io).get("afh_open", io)
        assert opn.index("xfs_ident_get(") < opn.index("brix_mgr_pick("), \
            "the identity is resolved after the manager is picked"

    def test_the_metadata_plane_resolves_it_as_well(self):
        """(success) Both metadata entry points go through the same lookup, so
        there is one decision point rather than one per operation."""
        fns = _functions(_code(XFS_C))
        entries = [n for n in ("xfs_meta", "xfs_meta_idem") if n in fns]
        assert entries == ["xfs_meta", "xfs_meta_idem"], \
            f"the metadata entry points moved or were renamed: {entries}"
        for name in entries:
            assert "xfs_ident_get(" in fns[name], \
                f"{name} runs as the mount owner, not the caller"

    def test_the_module_is_registered_in_the_client_build(self):
        """(error) An app-shard .o missing from the link list leaves
        xfs_ident_get undefined — or, worse, leaves a stale object in place."""
        assert "xrootdfs_identity.o" in _read(MAKEFILE), \
            "xrootdfs_identity.o is missing from XROOTDFS_SPLIT"
        assert "xfs_ident_get" in _read(XFS_INT_H), \
            "xfs_ident_get is not declared for the other shards"
