"""
test_audit15g_tpc_crosses.py — native root:// TPC crossed with a cache store, a
non-posix backend, and an authdb (audit §C carry-over rows "TPC x cache_store"
and "TPC x non-posix backend", plus §B1.7 "authdb x TPC").

Every native-TPC test in the suite drives a plain posix source into a plain
posix destination.  That is the one combination a production site is least
likely to be running: the destination is usually a cache in front of something,
the "filesystem" is often not one, and the whole plane is behind an
authorization database.  Each of those changes a different layer under the same
wire drive — the store the bytes come to rest in, the syscalls that write them,
and the check that decides whether they may be written at all — so a TPC pull
that works on the plain pair proves nothing about any of them.

Seven planes in one instance (nginx_audit15g_tpcx.conf) and one pull driver, so
that the only difference between any two cases below is the port it was aimed
at.  The source-side crosses matter as much as the destination-side ones: a TPC
source is asked to READ, which on a cold cache tier means filling it first, and
on an authdb-gated plane means the arm itself must be authorized.

THE FIRST FINDING — DEFECT CANDIDATE #21.  A native TPC destination writes
straight to the local filesystem under the export root, whatever the export's
storage backend is.  `tpc_open_dst_logical` (tpc/engine/launch_prepare.c:355-
369) opens the destination with `brix_vfs_open_fd_at(conf->rootfd, ...)` — the
raw-fd, posix-only door in the VFS (fs/vfs/vfs_walk.c:313, `openat2` beneath the
export's O_PATH rootfd) — and the pull thread writes to that bare fd
(tpc/outbound/source_stream.c:126).  The backend-aware door is
`brix_vfs_open(ctx, ...)`, which is what every other write path uses.

So on a plane whose backend is a cache tier, the pull lands BESIDE the tier and
the tier cannot serve it; on a plane whose backend is http:// there is no local
storage at all and the origin is never contacted, yet the client is told the
transfer completed.  Both are driven below and pinned as measured, with the
inverted assertions written out, because a lost transfer reported as a
successful one is the worst failure mode a data-movement service has.

THE SECOND FINDING (§B1.7).  A native TPC destination open is authorized as
BRIX_AOP_CREATE (protocols/root/read/open_tpc.c:115), and AOP_CREATE requires
insert|read|write — BRIX_ACC_PRIV_CREATE is `i|r|w` (auth/authz/acc/privs.h:53,
privs.c:28).  So an authdb rule of `rlw`, which reads as "this identity may
write here" and is what an operator would naturally write to permit an incoming
transfer, does NOT admit a TPC pull: the missing letter is `i`.  The rule has to
be `irw`.  Both are driven below so the difference is a test rather than a
footnote, and so the day AOP_CREATE is relaxed to AOP_UPDATE the suite says so.

Cases:
  * success      — the plain pair (control: the driver, the key rendezvous and
                   the seed are all working before anything is crossed)
  * defect pin   — destination is a cache tier: the pull reports ok and the
                   tier then answers kXR_NotFound for it (#21)
  * success      — source is a COLD cache tier: serving the TPC read fills the
                   source's store, and the destination still gets exact bytes
  * defect pin   — destination's backend is http://: the pull reports ok and
                   the origin is never contacted at all (#21)
  * sec-negative — authdb without `w` at all refuses the destination open
  * sec-negative — authdb WITH `w` but without `i` refuses it too (the finding)
  * success      — authdb with `irw` admits it, which is what makes the two
                   refusals above about the privileges and not about the authdb
  * sec-negative — an authdb-denied SOURCE cannot be armed as a TPC source, so
                   the rendezvous key never exists to be pulled with
"""

import os
import struct
import time

import pytest

from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS
from server_registry import NginxInstanceSpec
from settings import HOST, BIND_HOST, NGINX_BIN
from _test_a_robustness_helpers import make_close_req
from _test_audit15g_helpers import (
    ReadError, read_whole, seed_tree, serve_paced)
from test_audit15c_tpc_token_exchange import _drive_pull
from test_phase25_ratelimit import KXR_OK, _xrd_login, _xrd_open, _xrd_recv_status

def _guard_tpcx_1():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15g-tpcx")]

NAME = "lc-audit15g-tpcx"
EXTRA = LIFECYCLE_SHARED_PORTS[NAME]["extra"]
ORIGIN_PORT = EXTRA["ORIGIN_PORT"]

KXR_ERROR = 4003
XERR_NOT_AUTHORIZED = 3010
# The TPC destination open: kXR_new | kXR_open_wrto | kXR_mkpath.
TPC_FLAGS = 0x0008 | 0x4000 | 0x0100

SEED = b"audit15g-tpc-cross-source-object\n" * 64
SRC_LFN = "/src.bin"
HTTP_DEST = "/pulled-http.bin"


@pytest.fixture
def tpcx(lifecycle, tmp_path):
    """(endpoint, dirs, origin) — the seven planes, their directories, and the
    http origin the non-posix destination writes through."""
    _guard_tpcx_1()

    names = ("src", "ctl", "cdst-export", "cdst-store", "csrc-export",
             "csrc-store", "hdst-export", "acc", "asrc")
    dirs = {name: tmp_path / name for name in names}
    for path in dirs.values():
        path.mkdir()
        os.chmod(path, 0o777)
    os.chmod(tmp_path, 0o777)

    seed_tree(dirs["src"], {SRC_LFN: SEED})
    # The authdb-gated source holds the same object twice: once where the rules
    # grant read, once where they say nothing at all.
    seed_tree(dirs["asrc"], {"/pub/src.bin": SEED, "/priv/src.bin": SEED})

    # `w` alone is not enough for AOP_CREATE — /wonly is the pin for that, and
    # /deny is the plain "no write privilege anywhere near this" case.
    #
    # ONE `u *` record with three <path> <privs> pairs, not three records: the
    # second `u *` line is "duplicate rule for id" and the authdb fails to load
    # (authfile_record.c:441, acc_build_caps walks the pairs of a single line).
    acc_authdb = tmp_path / "acc.authdb"
    acc_authdb.write_text("u * /grant irw /wonly rlw /deny rl\n")
    asrc_authdb = tmp_path / "asrc.authdb"
    asrc_authdb.write_text("u * /pub rl\n")
    for path in (acc_authdb, asrc_authdb):
        os.chmod(path, 0o644)

    origin = serve_paced(ORIGIN_PORT, SEED, chunk=len(SEED), delay=0.0)
    # The non-posix destination must find its target ABSENT before it writes it,
    # exactly as it would on a real origin; `written` takes over once it lands.
    origin.absent.add(HTTP_DEST)
    try:
        endpoint = lifecycle.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_audit15g_tpcx.conf",
            protocol="root",
            readiness="tcp",
            data_root=str(dirs["src"]),
            template_values={
                "BIND_HOST": BIND_HOST,
                "SRC_DIR": str(dirs["src"]),
                "CTL_DIR": str(dirs["ctl"]),
                "CDST_EXPORT": str(dirs["cdst-export"]),
                "CDST_STORE": str(dirs["cdst-store"]),
                "CSRC_EXPORT": str(dirs["csrc-export"]),
                "CSRC_STORE": str(dirs["csrc-store"]),
                "HDST_EXPORT": str(dirs["hdst-export"]),
                "ACC_DIR": str(dirs["acc"]),
                "ACC_AUTHDB": str(acc_authdb),
                "ASRC_DIR": str(dirs["asrc"]),
                "ASRC_AUTHDB": str(asrc_authdb)},
            reason="audit-15g TPC x {cache_store, non-posix backend, authdb}"))
        yield endpoint, dirs, origin
    finally:
        origin.shutdown()
        origin.server_close()


# --------------------------------------------------------------------------- #
# the pull driver — one rendezvous, aimed by port
# --------------------------------------------------------------------------- #

def _key(tag):
    """Rendezvous keys live in a SHM registry shared by every worker and every
    test in this instance, so each pull mints its own."""
    return f"a15g{tag}{int(time.monotonic() * 1000) % 1000000}"


def _try_arm(port, lfn, key):
    """(socket, status, body) for client leg 1: a read-open carrying tpc.key +
    tpc.dst registers the key on the source.  Returned rather than closed — the
    arm has to outlive the pull that consumes it."""
    sock = _xrd_login(HOST, port)
    sock.settimeout(60)
    status, body = _xrd_open(
        sock, f"{lfn}?tpc.key={key}&tpc.dst={HOST}&tpc.stage=placement")
    return sock, status, body


def _arm(port, lfn, key):
    sock, status, body = _try_arm(port, lfn, key)
    assert status == KXR_OK, ("TPC source arm refused", status, body)
    return sock


def _open_frame(sock, path, flags, mode=0o644):
    payload = path.encode()
    sock.sendall(struct.pack(">BBH", 0, 1, 3010)
                 + struct.pack(">HH12s", mode, flags, b"\x00" * 12)
                 + struct.pack(">I", len(payload)) + payload)
    return _xrd_recv_status(sock)


def _pull(dst_port, src_port, dest, *, lfn=SRC_LFN, tag="x"):
    """Drive one native pull; returns (status, body).  A refusal at the
    destination open is returned as-is, because for half this file that IS the
    outcome under test."""
    key = _key(tag)
    armed = _arm(src_port, lfn, key)
    sock = _xrd_login(HOST, dst_port)
    sock.settimeout(60)
    try:
        opaque = (f"?tpc.src={HOST}:{src_port}&tpc.key={key}"
                  f"&tpc.lfn={lfn}&tpc.stage=copy&oss.asize={len(SEED)}")
        status, body = _open_frame(sock, dest + opaque, TPC_FLAGS)
        if status != KXR_OK:
            return status, body
        fhandle = body[:4]
        status, body = _drive_pull(sock, fhandle)
        if status != KXR_OK:
            return status, body
        # The close is part of the drive, not cleanup.  A destination object is
        # not PUBLISHED until the handle is closed — a tiered destination has it
        # staged and a non-posix one has not issued the origin PUT at all — so a
        # driver that drops the socket after the last sync leaves every "and is
        # it there afterwards?" assertion below looking at nothing.
        sock.sendall(make_close_req(fhandle))
        return _xrd_recv_status(sock)
    finally:
        sock.close()
        armed.close()


def _errcode(body):
    return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else -1


def _wait_bytes(path, want, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists() and path.read_bytes() == want:
            return True
        time.sleep(0.2)
    return False


def _tree(root):
    """Every regular file under `root`, relative — "where did the bytes come to
    rest" is the question half these tests are asking.

    brix's own bookkeeping is excluded: every export root gets a
    `.nginx-xrootd-ckp-recovery.lock` at worker init, so an export that has
    served nothing is still not an EMPTY directory."""
    out = {}
    for dirpath, _dirs, files in os.walk(str(root)):
        for name in files:
            if name.startswith(".nginx-xrootd-"):
                continue
            full = os.path.join(dirpath, name)
            out[os.path.relpath(full, str(root))] = os.path.getsize(full)
    return out


# --------------------------------------------------------------------------- #

def test_a_plain_native_pull_completes(tpcx):
    """success (control): plain posix source, plain posix destination, nothing
    crossed.  Everything below reuses this exact driver, so a failure here and
    a failure there mean very different things."""
    endpoint, dirs, _origin = tpcx
    status, body = _pull(endpoint.extra_ports["CTL_PORT"],
                         endpoint.extra_ports["SRC_PORT"],
                         "/pulled-plain.bin", tag="ctl")
    assert status == KXR_OK, (status, body)
    assert _wait_bytes(dirs["ctl"] / "pulled-plain.bin", SEED), \
        f"the pull reported ok but nothing landed: {_tree(dirs['ctl'])}"


def test_a_pull_into_a_cache_tiered_destination_lands_where_reads(tpcx):
    """A TPC destination uses the composed cache backend for its writes."""
    endpoint, dirs, _origin = tpcx
    status, body = _pull(endpoint.port, endpoint.extra_ports["SRC_PORT"],
                         "/pulled-tier.bin", tag="tier")
    assert status == KXR_OK, (status, body, _tree(dirs["cdst-store"]))

    assert read_whole(endpoint.port, "/pulled-tier.bin", len(SEED)) == SEED
    assert _tree(dirs["cdst-store"]), \
        "the cache tier did not persist the TPC destination"
    assert _tree(dirs["ctl"]) == {"pulled-tier.bin": len(SEED)}, \
        _tree(dirs["ctl"])
    assert _tree(dirs["cdst-export"]) == {}, \
        _tree(dirs["cdst-export"])


def test_a_pull_from_a_cold_cache_tiered_source_fills_that_source(tpcx):
    """success: the SOURCE is a cache tier whose store is empty, so serving the
    TPC read means filling from its own origin first.  Two things are proven at
    once — the destination gets byte-exact data, and the source's store is warm
    afterwards, which is what says the read really traversed the tier instead
    of some short-circuit that bypassed it."""
    endpoint, dirs, _origin = tpcx
    assert _tree(dirs["csrc-store"]) == {}, "the source cache started warm"

    status, body = _pull(endpoint.extra_ports["CTL_PORT"],
                         endpoint.extra_ports["CSRC_PORT"],
                         "/pulled-from-tier.bin", tag="csrc")
    assert status == KXR_OK, (status, body)
    assert _wait_bytes(dirs["ctl"] / "pulled-from-tier.bin", SEED), \
        f"nothing landed at the destination: {_tree(dirs['ctl'])}"
    assert _tree(dirs["csrc-store"]), \
        "the source served a TPC read without ever filling its own store"


def test_a_pull_into_a_non_posix_backend_reaches_the_origin(tpcx):
    """A whole-object TPC destination commits through the HTTP backend."""
    endpoint, dirs, origin = tpcx
    status, body = _pull(endpoint.extra_ports["HTTP_PORT"],
                         endpoint.extra_ports["SRC_PORT"],
                         HTTP_DEST, tag="http")
    assert status == KXR_OK, (status, body)

    assert origin.written[HTTP_DEST] == SEED, origin.written.keys()
    assert any(item["method"] == "PUT" and item["path"] == HTTP_DEST
               for item in origin.recorded), origin.recorded
    assert _tree(dirs["hdst-export"]) == {}, \
        _tree(dirs["hdst-export"])


def test_an_authdb_without_write_refuses_the_tpc_destination(tpcx):
    """security-negative: the authdb grants read+lookup on /deny and nothing
    else.  A TPC destination open there must be refused — and refused at the
    OPEN, before any rendezvous, because a destination that accepts and then
    fails leaves the source's key consumed and a partial object behind."""
    endpoint, dirs, _origin = tpcx
    status, body = _pull(endpoint.extra_ports["ACC_PORT"],
                         endpoint.extra_ports["SRC_PORT"],
                         "/deny/pulled.bin", tag="deny")
    assert status != KXR_OK, "an unprivileged TPC destination open was granted"
    assert _errcode(body) == XERR_NOT_AUTHORIZED, (status, body)
    assert _tree(dirs["acc"]) == {}, \
        f"a refused pull still created something: {_tree(dirs['acc'])}"


def test_an_authdb_with_write_but_no_insert_still_refuses_the_pull(tpcx):
    """security-negative, and the §B1.7 finding.  /wonly grants `rlw` — read,
    lookup and WRITE — which is what an operator writes when they mean "this
    identity may receive transfers here".  It is refused anyway: the TPC
    destination open is AOP_CREATE (open_tpc.c:115) and AOP_CREATE needs
    insert|read|write (privs.h:53), so the missing `i` is fatal.

    This is pinned as a fact about the privilege model, not as a complaint —
    XrdAcc's own table says the same thing.  What makes it worth a test is that
    the failure is a bare kXR_NotAuthorized with no hint that one letter is
    missing, and the next test proves the rest of the plane is fine."""
    endpoint, dirs, _origin = tpcx
    status, body = _pull(endpoint.extra_ports["ACC_PORT"],
                         endpoint.extra_ports["SRC_PORT"],
                         "/wonly/pulled.bin", tag="wonly")
    assert status != KXR_OK, \
        "`rlw` admitted a TPC pull — AOP_CREATE no longer requires insert"
    assert _errcode(body) == XERR_NOT_AUTHORIZED, (status, body)
    assert "wonly" not in _tree(dirs["acc"]), _tree(dirs["acc"])


def test_an_authdb_granting_insert_read_write_admits_the_pull(tpcx):
    """success: the same plane, the same driver, the same source — only the
    rule differs (`irw` on /grant).  Without this the two refusals above would
    be equally well explained by "the authdb breaks TPC", which is the wrong
    conclusion and the one an operator would act on."""
    endpoint, dirs, _origin = tpcx
    status, body = _pull(endpoint.extra_ports["ACC_PORT"],
                         endpoint.extra_ports["SRC_PORT"],
                         "/grant/pulled.bin", tag="grant")
    assert status == KXR_OK, (status, body)
    assert _wait_bytes(dirs["acc"] / "grant" / "pulled.bin", SEED), \
        f"the authorized pull landed nothing: {_tree(dirs['acc'])}"


def test_an_authdb_denied_source_cannot_be_armed(tpcx):
    """security-negative on the other leg: the rendezvous key is registered by
    a READ-open on the source, so an authdb that denies reading /priv must
    refuse the arm itself.  If it did not, an unauthorized object would be
    exportable to any destination that knew the key — the source is the only
    place that decision can be made, since the destination never sees the
    source's rules.

    The /pub twin runs the whole pull to the end, so the refusal is provably
    about the path and not about the plane being unable to source at all."""
    endpoint, dirs, _origin = tpcx
    sock, status, body = _try_arm(endpoint.extra_ports["ASRC_PORT"],
                                  "/priv/src.bin", _key("priv"))
    try:
        assert status != KXR_OK, "an unreadable path was armed as a TPC source"
        assert _errcode(body) == XERR_NOT_AUTHORIZED, (status, body)
    finally:
        sock.close()

    status, body = _pull(endpoint.extra_ports["CTL_PORT"],
                         endpoint.extra_ports["ASRC_PORT"],
                         "/pulled-pub.bin", lfn="/pub/src.bin", tag="pub")
    assert status == KXR_OK, (status, body)
    assert _wait_bytes(dirs["ctl"] / "pulled-pub.bin", SEED), \
        f"the permitted source path never transferred: {_tree(dirs['ctl'])}"


def test_a_denied_source_read_is_reported_as_a_refusal_not_a_gap(tpcx):
    """The reason the arm refusal above is asserted by CODE and not just by
    "it failed": a client told kXR_NotFound treats the object as absent, and an
    authorization denial that impersonates absence turns a permissions problem
    into a catalogue-repair problem.  A plain read-open of the same path is
    driven here to show both routes into the source agree."""
    endpoint, _dirs, _origin = tpcx
    with pytest.raises(ReadError) as caught:
        read_whole(endpoint.extra_ports["ASRC_PORT"], "/priv/src.bin",
                   len(SEED))
    assert caught.value.errcode == XERR_NOT_AUTHORIZED, caught.value
    assert read_whole(endpoint.extra_ports["ASRC_PORT"], "/pub/src.bin",
                      len(SEED)) == SEED
