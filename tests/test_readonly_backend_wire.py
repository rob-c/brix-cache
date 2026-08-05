"""
Capability-gated namespace ops on an s3:// backend, proven over the native
root:// wire — one test per side of the sd_remote capability word.

The VFS dispatch guards are pure capability checks, so what an op answers is
decided entirely by what the backend advertises (sd_remote.c:376):

  * kXR_mkdir    -> kXR_ok           (CAP_DIRS_WRITE: `path/` marker object)
  * kXR_mv       -> kXR_ok           (CAP_DIRS_WRITE: copy + delete)
  * kXR_truncate -> kXR_Unsupported  (vfs_sync.c  !CAP_TRUNCATE -> ENOTSUP)

and the same backend must still SERVE READS, so a failure here is the
capability gate, not a dead backend.  Data-plane writes are intentionally out
of scope: they route through the phase-70 staged writer and are covered by
test_pgwrite_staged_sync_gate.py against this very topology.

History: written for phase-71, when sd_remote advertised CAP_RANGE_READ |
CAP_MEMFILE only and BOTH catalog ops answered kXR_NotAuthorized (EPERM).
Phase-92 added marker-based namespace mutation, so the mkdir/mv assertions were
inverted (and an end-to-end observability test added, since the phase-92 path
had no wire coverage at all).  Truncate is unchanged: whole-object stores still
have no CAP_TRUNCATE, and it remains the negative leg proving the gate is real
rather than universally permissive.

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_readonly_backend_wire.py -v
"""

import os
import socket
import struct
import time

import pytest

from settings import BIND_HOST, HOST, NGINX_BIN, SERVER_HOST
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

from test_pgwrite_cse import (
    _handshake_login,
    _read_response,
    _close,
    kXR_ok,
    kXR_error,
)

pytestmark = [pytest.mark.serial, pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-readonly-wire")]

kXR_open, kXR_read = 3010, 3013
kXR_mkdir, kXR_mv, kXR_truncate = 3008, 3009, 3028
kXR_oksofar = 4000
kXR_open_read = 0x0010

# kXR error codes the phase-71 gates map to (errno -> kXR, error_mapping.c).
kXR_NotAuthorized = 3010     # EPERM
kXR_Unsupported = 3013       # ENOTSUP

S3_AK = "AKIDREADONLYWIRE01"
S3_SK = "cmVhZC1vbmx5LWJhY2tlbmQtd2lyZS1zZWNyZXQtdGVzdA"


def _port_up(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def node(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    # brix_s3 over a posix root stores objects FLAT under the root (the posix
    # root IS the bucket root) — seed one committed object for the read leg.
    s3_dir = tmp_path_factory.mktemp("s3store")
    (s3_dir / "testbucket").mkdir()
    seed = os.urandom(4096)
    (s3_dir / "seeded.bin").write_bytes(seed)
    harness = LifecycleHarness()
    endpoint = harness.start(NginxInstanceSpec(
        name="root-s3-readonly-wire",
        template="nginx_root_s3_staged.conf",
        protocol="root",
        readiness="tcp",
        template_values={"BIND_HOST": BIND_HOST,
                         "S3_DIR": str(s3_dir),
                         "S3_ACCESS_KEY": S3_AK,
                         "S3_SECRET_KEY": S3_SK},
    ))
    # S3_PORT is a second embedded listen owned by the lifecycle ledger
    # (fleet_lifecycle_ports.root-s3-readonly-wire); read it back post-start.
    s3_port = endpoint.extra_ports["S3_PORT"]
    for _ in range(50):
        if _port_up(HOST, s3_port):
            break
        time.sleep(0.1)

    yield {"port": endpoint.port, "seed": seed}
    harness.close()


def _login(node):
    return _handshake_login(host=SERVER_HOST, port=node["port"])


def _errcode(status, body):
    return (struct.unpack("!I", body[:4])[0]
            if (status == kXR_error and len(body) >= 4) else None)


def _mkdir(sock, path: bytes, mode=0o755):
    sock.sendall(struct.pack("!2sHB13sHI", b"\x00\x11", kXR_mkdir,
                             0, b"\x00" * 13, mode, len(path)) + path)
    status, body = _read_response(sock)
    return status, _errcode(status, body), body


def _mv(sock, src: bytes, dst: bytes):
    payload = src + b" " + dst
    sock.sendall(struct.pack("!2sH14sHI", b"\x00\x12", kXR_mv,
                             b"\x00" * 14, len(src), len(payload)) + payload)
    status, body = _read_response(sock)
    return status, _errcode(status, body), body


def _truncate_path(sock, path: bytes, length=0):
    sock.sendall(struct.pack("!2sH4sq4sI", b"\x00\x13", kXR_truncate,
                             b"\x00" * 4, length, b"\x00" * 4, len(path)) + path)
    status, body = _read_response(sock)
    return status, _errcode(status, body), body


def _open_read(sock, path: bytes):
    sock.sendall(struct.pack("!2sHHH2s6s4sI", b"\x00\x02", kXR_open,
                             0, kXR_open_read, b"\x00\x00", b"\x00" * 6,
                             b"\x00" * 4, len(path)) + path)
    status, body = _read_response(sock)
    assert status == kXR_ok, f"read-open {path} failed: st={status} body={body!r}"
    return body[:4]


def _read_all(sock, fhandle, offset, rlen):
    sock.sendall(struct.pack("!2sH4sqiI", b"\x00\x06", kXR_read,
                             fhandle, offset, rlen, 0))
    data = b""
    while True:
        status, body = _read_response(sock)
        if status not in (kXR_ok, kXR_oksofar):
            return status, data
        data += body
        if status == kXR_ok:
            return status, data


def test_read_path_serves_bytes(node):
    """Success leg: the caps sd_remote DOES advertise (range read) work — the
    seeded object comes back byte-exact, so the gate failures below cannot be a
    dead backend."""
    sock = _login(node)
    try:
        fh = _open_read(sock, b"/seeded.bin")
        st, data = _read_all(sock, fh, 0, len(node["seed"]))
        assert st == kXR_ok and data == node["seed"], \
            "read over the s3 backend must be byte-exact"
        _close(sock, fh)
    finally:
        sock.close()


def test_mkdir_granted_over_markers(node):
    """CAP_DIRS_WRITE (phase-92): kXR_mkdir is GRANTED on an s3:// backend and
    realised as a `path/` marker object, not refused at the VFS cap gate.

    Regression note: this assertion is INVERTED from its phase-71 original.
    sd_remote.c then advertised CAP_RANGE_READ|CAP_MEMFILE only, so vfs_mkdir.c's
    cap check answered EPERM -> kXR_NotAuthorized. Phase-92 added
    BRIX_SD_CAP_DIRS_WRITE plus real marker-based .mkdir/.rename slots
    (sd_remote.c:376), and the gate at vfs_mkdir.c:182 is a pure cap check — so
    the op now succeeds. The old assertion silently described retired behaviour
    and had gone red; see docs/refactor/
    testsuite-combinatorial-coverage-audit-2026-08-04.md §2.1.

    Restoring this test also exposed the other half of the marker path: the S3
    ORIGIN 500'd on the marker PUT (a trailing-slash key fell into the
    object-write path and EINVAL'd on publish), so the driver reported EIO ->
    kXR_IOError. Fixed by the folder-marker branch in s3/put_inner.c and covered
    on the HTTP plane by test_s3_folder_marker_put.py.
    """
    sock = _login(node)
    try:
        st, err, body = _mkdir(sock, b"/newdir")
        assert st == kXR_ok, \
            f"mkdir must be granted via CAP_DIRS_WRITE, got st={st} err={err} body={body!r}"
    finally:
        sock.close()


def test_rename_granted_over_markers(node):
    """CAP_DIRS_WRITE (phase-92): kXR_mv is GRANTED on an s3:// backend and
    realised as a copy+delete of the underlying object.

    Inverted from the phase-71 original for the same reason as
    test_mkdir_granted_over_markers. The destination is INSIDE the directory the
    previous test created, so a pass also proves that mkdir produced a usable
    prefix and not just a 200. The rename is then proven REAL (not merely
    accepted) by test_rename_is_observable_end_to_end below — a status code alone
    would not distinguish a granted rename from a silently-dropped one.
    """
    sock = _login(node)
    try:
        st, err, body = _mv(sock, b"/seeded.bin", b"/newdir/seeded.bin")
        assert st == kXR_ok, \
            f"mv must be granted via CAP_DIRS_WRITE, got st={st} err={err} body={body!r}"
    finally:
        sock.close()


def test_rename_is_observable_end_to_end(node):
    """The granted rename actually MOVED the object: the new name serves the
    original bytes and the old name is gone.

    This is the positive phase-92 wire contract that had no test at all — the
    marker/copy mutation path was previously exercised only as a side effect of
    the (stale, failing) negative assertions above. Ordering: this runs after
    test_rename_granted_over_markers within the module-scoped `node` fixture, so
    /seeded.bin now lives at /newdir/seeded.bin.
    """
    sock = _login(node)
    try:
        fh = _open_read(sock, b"/newdir/seeded.bin")
        st, data = _read_all(sock, fh, 0, len(node["seed"]))
        assert st == kXR_ok and data == node["seed"], \
            "the renamed object must serve the original bytes byte-exact"
        _close(sock, fh)
    finally:
        sock.close()

    # The source name must no longer resolve — a rename that merely COPIED would
    # leave it readable and pass the assertion above.
    sock = _login(node)
    try:
        sock.sendall(struct.pack("!2sHHH2s6s4sI", b"\x00\x02", kXR_open,
                                 0, kXR_open_read, b"\x00\x00", b"\x00" * 6,
                                 b"\x00" * 4, len(b"/seeded.bin")) + b"/seeded.bin")
        status, body = _read_response(sock)
        assert status == kXR_error, \
            f"the pre-rename name must be gone, but open() returned st={status}"
    finally:
        sock.close()


def test_truncate_denied_enotsup(node):
    """No CAP_TRUNCATE: path-form truncate is refused with ENOTSUP ->
    kXR_Unsupported (the op does not exist for whole-object stores; distinct
    from the EPERM the catalog gates return)."""
    sock = _login(node)
    try:
        st, err, body = _truncate_path(sock, b"/newdir/seeded.bin", 100)
        assert st == kXR_error, f"truncate must fail on an object store, got {st}"
        assert err == kXR_Unsupported, \
            f"expected kXR_Unsupported(ENOTSUP), got {err} body={body!r}"
    finally:
        sock.close()
