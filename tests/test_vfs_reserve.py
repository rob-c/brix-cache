"""Phase-107 C5 — the declared-final-size reserve, live over the wire.

A create-open that carries the client's declared final size (`oss.asize` on
root://, Content-Length on PUT, ALLO on GridFTP) dispatches the new
object-keyed `reserve` slot ONCE, before the first byte — and the staged plane
forwards the same declaration as `staged_open`'s `declared_size`, from which
`remote` derives a legal S3 multipart part size (pre-C5 the 16 MiB constant
silently made anything past 160 GB unfinishable).  The contract
(docs/refactor/phase-107-vfs-mutation-surface-completion.md §C5/A.4): ENOSPC/
EDQUOT fail the OPEN; every other reserve failure is advisory; no declaration
means no reserve at all.

The six contract rows, over the raw kXR wire (instance topology in
tests/configs/nginx_p107_reserve.conf):

  success   a declared 8 MiB on `posix` preallocates (st_blocks) while the
            4 KiB actually written lands byte-exact — the declaration is a
            hint, never a truncation;
  success   a 200 GB declaration over a `remote` (s3://) export opens, writes
            and commits byte-exact — the multipart part size scales with the
            declaration (its 3-fold legality: >= 16 MiB floor, MiB-aligned,
            <= 10 000 parts — incl. the 5 TB case — is pinned hermetically by
            tests/c/test_sd_remote_part_size.c);
  success   no declared size => no reserve call at all (no preallocation, no
            advisory log line);
  error     an `oss.asize` beyond the filesystem's free space refuses the
            OPEN with kXR_NoSpace — and releases the partial allocation a
            non-atomic ext4 fallocate leaves behind (observed live: one
            refused call parked 66 GB of invisible st_size-0 allocation);
  sec-neg   a declaration of 0 or one far below the bytes actually written
            does NOT move the `brix_oss_maxsize` boundary — the hint is
            advisory in both directions;
  sec-neg   a read-only front refuses with kXR_fsReadOnly BEFORE the reserve
            is reachable — its export root stays empty.

The EOPNOTSUPP-advisory arm cannot be reached from a live fleet (every
exportable filesystem here implements fallocate), so its shape is pinned
statically against vfs_open.c / sd_cache_forward.c below.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_vfs_reserve.py -v
"""
import os
import pathlib
import socket
import struct

import pytest

from server_launcher import LifecycleHarness, NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN

pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p107-reserve")]

SPEC = "lc-p107-reserve"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIB = 1024 * 1024

S3_AK = "AKIDP107RESERVETST1"
S3_SK = "cDEwNy1yZXNlcnZlLWRlY2xhcmVkLXNpemUtc2VjcmV0"

# wire constants
kXR_protocol, kXR_login, kXR_open, kXR_write, kXR_close = \
    3006, 3007, 3010, 3019, 3003
kXR_ok, kXR_error = 0, 4003
kXR_NoSpace, kXR_overQuota, kXR_fsReadOnly = 3009, 3021, 3025
kXR_open_updt, kXR_new, kXR_delete = 0x0020, 0x0008, 0x0002


@pytest.fixture(scope="module")
def reserve_srv(tmp_path_factory):
    """One instance, four fronts + the s3 origin (nginx_p107_reserve.conf)."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    base = tmp_path_factory.mktemp("p107-reserve")
    dirs = {name: base / name for name in (
        "posix_root", "quota_root", "ro_root", "exp_remote", "s3store")}
    for d in dirs.values():
        d.mkdir()
    harness = LifecycleHarness()
    try:
        ep = harness.start(NginxInstanceSpec(
            name=SPEC,
            template="nginx_p107_reserve.conf",
            protocol="root",
            data_root=str(dirs["posix_root"]),
            template_values={
                "BIND_HOST": BIND_HOST,
                "QUOTA_ROOT": str(dirs["quota_root"]),
                "RO_ROOT": str(dirs["ro_root"]),
                "REMOTE_EXPORT": str(dirs["exp_remote"]),
                "S3_DIR": str(dirs["s3store"]),
                "S3_ACCESS_KEY": S3_AK,
                "S3_SECRET_KEY": S3_SK,
            },
            reason="phase-107 C5 declared-size reserve postures"))
        yield {"port": ep.port, "extras": ep.extra_ports, "dirs": dirs,
               "error_log": pathlib.Path(ep.prefix) / "logs" / "error.log"}
    finally:
        harness.close()


# --------------------------------------------------------------------------- #
# raw-wire helpers
# --------------------------------------------------------------------------- #

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _resp(sock):
    hdr = _recv_exact(sock, 8)
    assert hdr is not None, "connection closed mid-response"
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[4:8])[0]
    return status, (_recv_exact(sock, dlen) or b"") if dlen else b""


def _send(sock, streamid, reqid, body=b"", payload=b""):
    hdr = bytes(streamid[:2]) + struct.pack(">H", reqid)
    hdr += body.ljust(16, b"\x00") + struct.pack(">I", len(payload))
    sock.sendall(hdr + payload)
    return _resp(sock)


def _connect(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((HOST, port))
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    assert _recv_exact(sock, 16) is not None
    status, _ = _send(sock, b"\x00\x01", kXR_protocol)
    assert status == kXR_ok
    status, _ = _send(sock, b"\x00\x01", kXR_login, payload=b"anonymous\x00")
    assert status == kXR_ok
    return sock


def _open_w(sock, xrd_path):
    """Create/trunc write open; returns (status, body) WITHOUT asserting —
    half the rows here are about the open refusing."""
    flags = kXR_open_updt | kXR_new | kXR_delete
    body = struct.pack(">HH", 0o644, flags) + b"\x00" * 12
    return _send(sock, b"\x00\x01", kXR_open, body=body,
                 payload=xrd_path.encode() + b"\x00")


def _open_ok(sock, xrd_path):
    status, rbody = _open_w(sock, xrd_path)
    assert status == kXR_ok, (
        f"open {xrd_path!r} failed: {status} "
        f"code={_err_code(rbody)} msg={rbody[4:130]!r}")
    return rbody[:4]


def _write_at(sock, fh, offset, data):
    body = fh + struct.pack(">q", offset) + b"\x00" * 4
    return _send(sock, b"\x00\x02", kXR_write, body=body, payload=data)


def _close(sock, fh):
    status, _ = _send(sock, b"\x00\x03", kXR_close, body=fh)
    assert status == kXR_ok, "close/commit failed"


def _err_code(body):
    return struct.unpack(">I", body[:4])[0] if len(body) >= 4 else None


def _bytes(n, seed):
    """Deterministic non-repeating payload (a constant pattern would let a
    misplaced extent pass unnoticed)."""
    return bytes(((i * 41) + (i >> 12) * 7 + seed) & 0xFF for i in range(n))


def _advisory_lines(error_log):
    if not error_log.exists():
        return []
    return [ln for ln in error_log.read_text(errors="replace").splitlines()
            if "advisory reserve" in ln]


# --------------------------------------------------------------------------- #
# success
# --------------------------------------------------------------------------- #

def test_declared_size_preallocates_posix(reserve_srv):
    """(success) a declared 8 MiB preallocates the blocks up front
    (fallocate KEEP_SIZE: st_blocks grows, st_size does not) while the 4 KiB
    actually written lands byte-exact — the declaration is a hint that must
    never truncate, extend or corrupt the object."""
    payload = _bytes(4096, 3)
    sock = _connect(reserve_srv["port"])
    try:
        fh = _open_ok(sock, f"/prealloc.bin?oss.asize={8 * MIB}")
        status, _ = _write_at(sock, fh, 0, payload)
        assert status == kXR_ok
        _close(sock, fh)
    finally:
        sock.close()
    f = reserve_srv["dirs"]["posix_root"] / "prealloc.bin"
    assert f.read_bytes() == payload, "declared-size upload not byte-exact"
    st = f.stat()
    assert st.st_size == 4096, "the declaration must not change st_size"
    assert st.st_blocks * 512 >= 8 * MIB, (
        f"declared 8 MiB but only {st.st_blocks * 512} bytes allocated — "
        "the reserve never reached fallocate")


def test_no_declaration_reserves_nothing(reserve_srv):
    """(success) no declared size => no reserve dispatch at all: the file's
    allocation matches the bytes written, and no advisory-reserve line was
    logged (a reserve called with 0 would fail EINVAL and log one)."""
    payload = _bytes(4096, 5)
    sock = _connect(reserve_srv["port"])
    try:
        fh = _open_ok(sock, "/plain.bin")
        status, _ = _write_at(sock, fh, 0, payload)
        assert status == kXR_ok
        _close(sock, fh)
    finally:
        sock.close()
    f = reserve_srv["dirs"]["posix_root"] / "plain.bin"
    assert f.read_bytes() == payload
    assert f.stat().st_blocks * 512 < MIB, (
        "an undeclared open preallocated — reserve dispatched without a "
        "declaration")
    assert _advisory_lines(reserve_srv["error_log"]) == [], (
        "an advisory-reserve failure was logged on the undeclared plane")


def test_remote_200gb_declaration_completes(reserve_srv):
    """(success) a 200 GB `oss.asize` over the `remote` (s3://) export opens,
    writes and commits byte-exact.  Pre-C5 the 16 MiB part constant made any
    object past 160 GB unfinishable at part 10 000; the declaration now sizes
    the parts (>= 20 MiB here).  The part-size legality itself — floor,
    MiB-alignment, <= 10 000 parts, up to 5 TB — is pinned hermetically by
    tests/c/test_sd_remote_part_size.c (`sd_remote_part_size` unit)."""
    declared = 200 * 1000 * 1000 * 1000          # 200 GB, decimal, like a VO
    payload = _bytes(4 * MIB, 9)
    sock = _connect(reserve_srv["extras"]["REMOTE_PORT"])
    try:
        fh = _open_ok(sock, f"/big.bin?oss.asize={declared}")
        for off in range(0, len(payload), MIB):
            status, body = _write_at(sock, fh, off, payload[off:off + MIB])
            assert status == kXR_ok, (
                f"declared-200GB write at {off} refused: {_err_code(body)}")
        _close(sock, fh)
    finally:
        sock.close()
    # the brix_s3 origin maps the bucket onto its export root
    obj = reserve_srv["dirs"]["s3store"] / "big.bin"
    assert obj.exists(), "the declared upload never committed to the origin"
    assert obj.read_bytes() == payload, "declared-200GB upload not byte-exact"


# --------------------------------------------------------------------------- #
# error
# --------------------------------------------------------------------------- #

def test_oversized_declaration_fails_open_and_releases(reserve_srv):
    """(error) an `oss.asize` beyond the filesystem's free space refuses the
    OPEN with kXR_NoSpace — not the eventual write — AND releases the partial
    allocation ext4's non-atomic fallocate leaves behind (one refused call
    was observed parking 66 GB of invisible st_size-0 allocation: without the
    release, repeating this open IS a full-disk DoS)."""
    root = reserve_srv["dirs"]["posix_root"]
    sv = os.statvfs(root)
    free_before = sv.f_bavail * sv.f_frsize
    declared = free_before + 64 * 1024 * MIB     # free + 64 GiB
    sock = _connect(reserve_srv["port"])
    try:
        status, body = _open_w(sock, f"/toolarge.bin?oss.asize={declared}")
        assert status == kXR_error, (
            "an unsatisfiable declaration did not refuse the open")
        assert _err_code(body) == kXR_NoSpace, (
            f"expected kXR_NoSpace(3009), got {_err_code(body)}")
    finally:
        sock.close()
    leftover = root / "toolarge.bin"
    if leftover.exists():
        assert leftover.stat().st_blocks * 512 < MIB, (
            f"{leftover.stat().st_blocks * 512} bytes still allocated behind "
            "the refused open — the partial-reservation release regressed")
    sv = os.statvfs(root)
    assert sv.f_bavail * sv.f_frsize > free_before - 1024 * MIB, (
        "free space did not recover after the refused reservation")


def test_advisory_contract_is_pinned():
    """(error, static) the EOPNOTSUPP-advisory arm is unreachable from a live
    fleet (every exportable fs here implements fallocate), so pin its shape:
    ONLY ENOSPC/EDQUOT fail the open, everything else logs at info and
    proceeds — at both dispatch sites — and the cache decorator's parity slot
    answers a direct dispatch honestly instead of pretending to reserve."""
    vfs_open = pathlib.Path(
        REPO, "src/fs/vfs/vfs_open.c").read_text()
    assert vfs_open.count("advisory reserve") == 2, (
        "one of the two reserve dispatch sites lost its advisory arm")
    assert vfs_open.count("errno == ENOSPC || errno == EDQUOT") == 2, (
        "a reserve dispatch site widened (or lost) its fatal-errno set")
    cache = pathlib.Path(
        REPO, "src/fs/backend/cache/sd_cache_forward.c").read_text()
    assert "sd_cache_reserve" in cache and "EOPNOTSUPP" in cache, (
        "the cache parity slot no longer answers EOPNOTSUPP")
    posix_io = pathlib.Path(
        REPO, "src/fs/backend/posix/sd_posix_io.c").read_text()
    assert "ftruncate(obj->fd, st.st_size)" in posix_io, (
        "sd_posix_reserve lost the partial-allocation release — a refused "
        "oversized declaration parks the filesystem's free space again")


# --------------------------------------------------------------------------- #
# security-neg
# --------------------------------------------------------------------------- #

def test_lying_declaration_does_not_move_quota(reserve_srv):
    """(security-neg) `brix_oss_maxsize 64k` front: a declaration of 0 or one
    far below the bytes actually written does NOT raise the quota ceiling —
    the write still refuses kXR_overQuota at the real boundary.  (The other
    direction — a declaration far ABOVE the bytes written neither truncates
    nor extends — is test_declared_size_preallocates_posix.)"""
    port = reserve_srv["extras"]["QUOTA_PORT"]
    for name, asize in (("q_zero.bin", 0), ("q_small.bin", 32 * 1024)):
        sock = _connect(port)
        try:
            fh = _open_ok(sock, f"/{name}?oss.asize={asize}")
            status, body = _write_at(sock, fh, 0, b"x" * (64 * 1024 + 1))
            assert status == kXR_error, (
                f"asize={asize} lifted the 64k quota cap")
            assert _err_code(body) == kXR_overQuota, (
                f"expected kXR_overQuota(3021), got {_err_code(body)}")
        finally:
            sock.close()


def test_read_only_front_refuses_before_reserve(reserve_srv):
    """(security-neg) a read-only front refuses the write open with
    kXR_fsReadOnly (EROFS, phase-105 gate) BEFORE the reserve is reachable:
    no file, no allocation, nothing in the export root."""
    sock = _connect(reserve_srv["extras"]["RO_PORT"])
    try:
        status, body = _open_w(sock, f"/ro.bin?oss.asize={8 * MIB}")
        assert status == kXR_error, "read-only front accepted a write open"
        assert _err_code(body) == kXR_fsReadOnly, (
            f"expected kXR_fsReadOnly(3025), got {_err_code(body)}")
    finally:
        sock.close()
    ro = reserve_srv["dirs"]["ro_root"]
    # The instance plants its own .nginx-xrootd-* bookkeeping (checkpoint
    # recovery lock) at startup — only entries carrying the requested name,
    # or any visible file, would be the refused open's leak.
    leaked = [e.name for e in ro.iterdir()
              if "ro.bin" in e.name or not e.name.startswith(".")]
    assert leaked == [], (
        f"the refused open left {leaked} in the read-only export — the "
        "reserve (or the create) ran before the phase-105 gate")
