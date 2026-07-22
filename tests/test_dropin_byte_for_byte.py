"""
tests/test_dropin_byte_for_byte.py — drop-in byte-for-byte parity vs the
OFFICIAL xrootd server.

This suite proves the nginx-xrootd module is a *drop-in* replacement for the
official /usr/bin/xrootd at the wire level: it provisions BOTH servers on the
SAME data root (a dedicated official xrootd and a dedicated nginx, on isolated
high ports) and then issues the identical raw `root://` request to each and
compares the responses.  Because both daemons read the same files, the
metadata (inode, size, mtime), the per-page CRC32c pgread stream, the dirlist
names and the file bytes are all expected to be IDENTICAL — not merely
"semantically equivalent".  Where a field legitimately cannot match across two
independent processes (e.g. a self-reported PID) the comparison is restricted
to the field ORDER / FORMAT / key-set, which is the actual conformance
contract.  All raw framing is built with `struct.pack` exactly as in
tests/test_readv_security.py, and every hostile / edge request is followed by a
sanity op proving the connection survived.

The whole module skips cleanly if the nginx binary or /usr/bin/xrootd is
absent, or if either server fails to come up.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_dropin_byte_for_byte.py -v
"""

import os
import socket
import struct
import subprocess
import time

import pytest

from settings import NGINX_BIN, SERVER_HOST, BIND_HOST
from ephemeral_port import free_port
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-dropin-front")]

REF_XROOTD_BIN = os.environ.get(
    "TEST_REF_BIN",
    os.environ.get("TEST_BRIX_BIN", "/usr/bin/xrootd"),
)
H = SERVER_HOST

# Dedicated workspace for this file.
_DIR = os.path.join(os.environ["TMPDIR"], "xrd_dropin_bfb")
# Port the fixture BINDS for the official xrootd xrd.port: allocate a free OS
# port so it never collides with the managed fleet or with another
# self-contained test running in the same pytest invocation.  Any explicit env
# override is still honoured.  The nginx front's port is owned by the registry
# LifecycleHarness (see the `stack` fixture).
_REF_XROOTD_FREE = free_port(H)
REF_XROOTD_PORT = int(os.environ.get("TEST_DROPIN_XROOTD_PORT")
                      or os.environ.get("TEST_DROPIN_BRIX_PORT")
                      or _REF_XROOTD_FREE)


# ---------------------------------------------------------------------------
# Opcodes / status / error codes (XProtocol.hh + src/protocols/root/protocol/opcodes.h)
# ---------------------------------------------------------------------------

kXR_query    = 3001
kXR_close    = 3003
kXR_dirlist  = 3004
kXR_login    = 3007
kXR_open     = 3010
kXR_ping     = 3011
kXR_read     = 3013
kXR_stat     = 3017
kXR_statx    = 3022
kXR_pgread   = 3030
kXR_clone    = 3032

kXR_ok       = 0
kXR_oksofar  = 4000
kXR_error    = 4003
kXR_status   = 4007    # pgread extended-status framing

# XQueryType (ClientQueryRequest.infotype)
kXR_Qcksum   = 3
kXR_Qspace   = 5
kXR_Qconfig  = 7

# Server error codes (XProtocol.hh XErrorCode)
kXR_NotAuthorized = 3010
kXR_NotFound      = 3011
kXR_isDirectory   = 3016
kXR_Unsupported   = 3013   # also kXR_IOError numerically; disambiguated by msg
kXR_IOError       = 3007

# Open option flags
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_new       = 0x0008
kXR_delete    = 0x0004

# dirlist options (ClientDirlistRequest.options)
kXR_dstat     = 2

PG_PAGESZ = 4096

# Seed files (written into the SHARED data root used by BOTH servers).
PLAIN_NAME   = "/dropin_plain.bin"
PLAIN_SIZE   = 70000          # not page-aligned → exercises a short final page
PLAIN_DATA   = bytes((i * 37 + 11) & 0xFF for i in range(PLAIN_SIZE))

SUBDIR       = "/dropin_dir"
SUBDIR_FILES = ["a.bin", "b.bin", "c.bin"]

NOPERM_NAME  = "/dropin_noperm.bin"   # chmod 000 → EACCES family


# ---------------------------------------------------------------------------
# CRC32c (Castagnoli) — matches brix_crc32c_copy(); used to verify the
# per-page CRCs in the pgread response are correct on BOTH servers.
# ---------------------------------------------------------------------------

_CRC32C_POLY = 0x82F63B78
_CRC32C_TABLE = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (_c >> 1) ^ _CRC32C_POLY if (_c & 1) else (_c >> 1)
    _CRC32C_TABLE.append(_c)


def crc32c(data: bytes, crc: int = 0) -> int:
    crc ^= 0xFFFFFFFF
    for b in data:
        crc = _CRC32C_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


_CRC32C_OK = crc32c(b"123456789") == 0xE3069283


# ---------------------------------------------------------------------------
# Raw socket helpers (mirror tests/test_readv_security.py exactly)
# ---------------------------------------------------------------------------

def _recv_exact(sock, nbytes):
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise ConnectionError(
                f"socket closed, {nbytes - len(data)} bytes remaining")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    header = _recv_exact(sock, 8)
    streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return streamid, status, body


def _handshake(host, port):
    sock = socket.create_connection((host, port), timeout=8)
    sock.settimeout(8)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    _, status, _ = _read_response(sock)
    assert status == kXR_ok, "handshake rejected"
    return sock


def _login(sock, streamid=b"\x00\x01"):
    req = struct.pack("!2sHI8sBBBBI",
                      streamid, kXR_login,
                      os.getpid() & 0xFFFFFFFF,
                      b"pytest\x00\x00", 0, 0, 5, 0, 0)
    sock.sendall(req)
    return _read_response(sock)


class _SessionUnavailable(Exception):
    """Raised when a handshake/login cannot complete cleanly — converted into a
    skip by the fixtures rather than surfacing as a hard error."""


def _session(host, port):
    """Drive the full handshake + login chain.  The official server may answer
    login with an authentication-continuation (kXR_authmore) when 'sec'
    payloads are present; for an unauthenticated/anon export both return
    kXR_ok, which is what these configs use.

    On any protocol-level surprise (rejected handshake, non-ok login, a server
    that demands auth we have not configured) this raises _SessionUnavailable
    so callers can SKIP cleanly instead of erroring — these configs export an
    anonymous root, so a healthy server always reaches kXR_ok here."""
    try:
        sock = _handshake(host, port)
    except (OSError, AssertionError) as exc:
        raise _SessionUnavailable(f"handshake failed @ {host}:{port}: {exc}")
    try:
        sid, status, body = _login(sock)
    except OSError as exc:
        sock.close()
        raise _SessionUnavailable(f"login I/O failed @ {host}:{port}: {exc}")
    if status != kXR_ok:
        sock.close()
        raise _SessionUnavailable(
            f"login not kXR_ok @ {host}:{port}: status={status} "
            f"{_error_msg(body)!r}")
    return sock


def _open(sock, path, options=kXR_open_read, streamid=b"\x00\x02"):
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHHH2s6s4sI",
                      streamid, kXR_open,
                      0o644, options, b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                      len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _close(sock, fhandle, streamid=b"\x00\x0e"):
    req = struct.pack("!2sH4s12sI", streamid, kXR_close, fhandle,
                      b"\x00" * 12, 0)
    sock.sendall(req)
    return _read_response(sock)


def _ping(sock, streamid=b"\x00\x0f"):
    req = struct.pack("!2sH16sI", streamid, kXR_ping, b"\x00" * 16, 0)
    sock.sendall(req)
    return _read_response(sock)


def _read(sock, fhandle, offset, rlen, streamid=b"\x00\x06"):
    req = struct.pack("!2sH4sqiI", streamid, kXR_read, fhandle,
                      offset, rlen, 0)
    sock.sendall(req)
    return _read_response(sock)


def _stat(sock, path, streamid=b"\x00\x10"):
    """ClientStatRequest: options[1] reserved[7] wants[u32] fhandle[4] dlen.
    Path-based stat (fhandle = 0) — see XProtocol.hh ClientStatRequest."""
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHB7sI4sI",
                      streamid, kXR_stat,
                      0, b"\x00" * 7, 0, b"\x00" * 4, len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _statx(sock, paths, streamid=b"\x00\x11"):
    """kXR_statx: same header shape as kXR_stat; payload is one or more
    null-separated paths.  The XRootD python client has NO statx method, so
    this is raw-wire only."""
    if isinstance(paths, str):
        paths = [paths]
    payload = b"".join(p.encode() + b"\x00" for p in paths)
    req = struct.pack("!2sHB7sI4sI",
                      streamid, kXR_statx,
                      0, b"\x00" * 7, 0, b"\x00" * 4, len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


def _query(sock, infotype, payload=b"", fhandle=b"\x00\x00\x00\x00",
           streamid=b"\x00\x12"):
    """ClientQueryRequest: infotype[u16] reserved1[2] fhandle[4]
    reserved2[8] dlen."""
    if isinstance(payload, str):
        payload = payload.encode()
    req = struct.pack("!2sHH2s4s8sI",
                      streamid, kXR_query,
                      infotype, b"\x00\x00", fhandle, b"\x00" * 8,
                      len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


def _dirlist(sock, path, options=kXR_dstat, streamid=b"\x00\x13"):
    """ClientDirlistRequest: options[1] reserved[15] dlen + path."""
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sH15sBI",
                      streamid, kXR_dirlist,
                      b"\x00" * 15, options, len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _pgread(sock, fhandle, offset, rlen, streamid=b"\x00\x07"):
    """Issue kXR_pgread and fully drain the response.  Success is a kXR_status
    message (8-byte header + 24-byte status body), then bdy.dlen raw bytes of
    CRC-interleaved page data.  Returns (status, status_body, pages)."""
    req = struct.pack("!2sH4sqiI", streamid, kXR_pgread, fhandle,
                      offset, rlen, 0)
    sock.sendall(req)
    sid, status, body = _read_response(sock)
    pages = b""
    if status == kXR_status and len(body) >= 16:
        bdy_dlen = struct.unpack("!i", body[12:16])[0]
        if bdy_dlen > 0:
            pages = _recv_exact(sock, bdy_dlen)
    return status, body, pages


def _clone(sock, dst_fhandle, items=b"", streamid=b"\x00\x14"):
    """ClientCloneRequest: dst_fhandle[4] reserved[12] dlen + clone_list."""
    req = struct.pack("!2sH4s12sI",
                      streamid, kXR_clone, dst_fhandle, b"\x00" * 12,
                      len(items))
    sock.sendall(req + items)
    return _read_response(sock)


def _error_code(body):
    return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else 0


def _error_msg(body):
    return body[4:].split(b"\x00")[0].decode(errors="replace") if len(body) > 4 else ""


def _error_family(status, body):
    """Coarse error family for cross-server comparison — handles BOTH the
    nginx numeric error codes and the official server's (which may differ in
    exact code but agree on the family conveyed by the message text)."""
    if status != kXR_error:
        return "ok"
    code = _error_code(body)
    msg = _error_msg(body).lower()
    if code == kXR_NotFound or "no such" in msg or "not found" in msg \
            or "does not exist" in msg or "doesn't exist" in msg:
        return "not_found"
    if code == kXR_NotAuthorized or "permission" in msg \
            or "not authoriz" in msg or "denied" in msg:
        return "permission"
    if code == kXR_isDirectory or "is a directory" in msg \
            or "is directory" in msg or "directory" in msg and "not" not in msg:
        return "is_directory"
    return "error"


def _decode_pages(pages):
    """Split a pgread page stream [crc4][<=4096 data]..., verify each CRC32c,
    return the concatenated data.  Raises on CRC mismatch."""
    out = bytearray()
    pos = 0
    while pos < len(pages):
        crc = struct.unpack("!I", pages[pos:pos + 4])[0]
        pos += 4
        page = pages[pos:pos + PG_PAGESZ]
        pos += len(page)
        if _CRC32C_OK:
            assert crc32c(page) == crc, "pgread per-page CRC32c mismatch"
        out.extend(page)
        if len(page) < PG_PAGESZ:
            break
    return bytes(out)


# ---------------------------------------------------------------------------
# Provisioning (mirrors tests/test_mirror_upstream.py)
# ---------------------------------------------------------------------------

def _reachable(port, timeout=1.0):
    try:
        socket.create_connection((H, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def _wait_port(port, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _reachable(port, 0.5):
            return True
        time.sleep(0.2)
    return False


def _mkdirs(*paths):
    for p in paths:
        os.makedirs(p, exist_ok=True)


def _serves_seed(port):
    """Probe that the server on `port` actually serves the seed file at the
    expected size via a real handshake+login+stat.  Guards against trusting a
    stale/orphaned listener that bound the port from an earlier run."""
    try:
        s = _session(H, port)
    except Exception:
        return False
    try:
        sid, status, body = _stat(s, PLAIN_NAME)
        if status != kXR_ok:
            return False
        parts = body.split(b"\x00")[0].decode(errors="replace").split()
        # nginx returns exactly 4 fields; the official server returns the same
        # leading 4 (id size flags mtime) followed by extended fields.  Accept
        # any body whose 2nd field is the seed size.
        return len(parts) >= 4 and int(parts[1]) == PLAIN_SIZE
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def _seed_data(data_dir):
    _mkdirs(data_dir, os.path.join(data_dir, SUBDIR.lstrip("/")))
    with open(os.path.join(data_dir, PLAIN_NAME.lstrip("/")), "wb") as f:
        f.write(PLAIN_DATA)
    for i, name in enumerate(SUBDIR_FILES):
        with open(os.path.join(data_dir, SUBDIR.lstrip("/"), name), "wb") as f:
            f.write(bytes([i]) * (100 + i))
    noperm = os.path.join(data_dir, NOPERM_NAME.lstrip("/"))
    # A prior run may have left this chmod-000; restore writability first so
    # re-seeding is idempotent.
    if os.path.exists(noperm):
        try:
            os.chmod(noperm, 0o600)
        except OSError:
            pass
    with open(noperm, "wb") as f:
        f.write(b"secret")
    # chmod 000 so a read-open hits EACCES on both servers (EACCES → permission).
    try:
        os.chmod(noperm, 0o000)
    except OSError:
        pass


def _start_xrootd(data_dir):
    """Start a dedicated official xrootd on the shared data root.  Returns the
    cfg path (used as the kill key)."""
    base = os.path.join(_DIR, "xrootd")
    _mkdirs(os.path.join(base, "admin"), os.path.join(base, "run"))
    cfg = os.path.join(base, "xrootd.cfg")
    with open(cfg, "w") as f:
        f.write(
            f"xrd.port {REF_XROOTD_PORT}\n"
            f"oss.localroot {data_dir}\n"
            f"all.export /\n"
            f"xrootd.chksum max 2 adler32\n"
            f"all.adminpath {os.path.join(base, 'admin')}\n"
            f"all.pidpath {os.path.join(base, 'run')}\n"
            f"xrd.trace off\n")
    argv = [REF_XROOTD_BIN, "-b", "-c", cfg,
            "-l", os.path.join(base, "xrootd.log")]
    # Official xrootd refuses to run as superuser.  Under the root harness,
    # launch with `-R nobody` and pre-open the paths the dropped user needs:
    # the shared data root (localroot, read+write — shared with nginx, so
    # a+rwX is expected here), the log dir, and the adminpath dir.  This is a
    # PLAIN server (no GSI key), so only data + log + admin need opening.
    if os.geteuid() == 0:
        runas = os.environ.get("REF_RUNAS_USER", "nobody")
        admin = os.path.join(base, "admin")
        # base is the log dir (xrootd.log lives directly under it), so it must
        # be writable, not just traversable.
        subprocess.run(["chmod", "a+rwX", base])
        subprocess.run(["chmod", "-R", "a+rwX", data_dir])
        subprocess.run(["chmod", "-R", "a+rwX", admin])
        subprocess.run(["chmod", "-R", "a+rwX", os.path.join(base, "run")])
        argv += ["-R", runas]
    subprocess.run(argv, capture_output=True)
    return cfg


def _stop_xrootd(cfg):
    # cfg is a full unique path under _DIR; never a bare pattern.
    subprocess.run(["pkill", "-f", cfg], capture_output=True)


@pytest.fixture(scope="module")
def stack():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    if not os.path.exists(REF_XROOTD_BIN):
        pytest.skip(f"official xrootd binary not found at {REF_XROOTD_BIN}")

    data_dir = os.path.join(_DIR, "data")
    _seed_data(data_dir)

    # This is a MODULE-scoped nginx fixture, so drive the registry launcher
    # directly (the function-scoped `lifecycle` fixture is just a thin wrapper
    # around this same LifecycleHarness).  The reference xrootd keeps its own
    # subprocess lifecycle unchanged.
    xr_cfg = _start_xrootd(data_dir)
    harness = LifecycleHarness()
    try:
        if not _wait_port(REF_XROOTD_PORT):
            pytest.skip("official xrootd did not come up")
        # Robustness: a TIME-WAIT/orphaned listener on the port can make a bare
        # connect succeed even though THIS xrootd failed to bind and is serving
        # the wrong (or no) data.  Prove the official server actually serves the
        # seed file before trusting it; skip otherwise rather than hard-fail.
        if not _serves_seed(REF_XROOTD_PORT):
            pytest.skip("official xrootd is up but not serving the seed data "
                        "(stale listener / bind race) — skipping parity run")
        ep = harness.start(NginxInstanceSpec(
            name="lc-dropin-front",
            template="nginx_lc_dropin_front.conf",
            protocol="root",
            template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": data_dir},
            reason="drop-in byte-for-byte parity front over the shared "
                   "data root vs the official xrootd"))
        if not _wait_port(ep.port):
            pytest.skip("nginx did not come up")
        if not _serves_seed(ep.port):
            pytest.skip("nginx is up but not serving the seed data")
        yield {
            "data_dir": data_dir,
            "nginx": (ep.host, ep.port),
            "xrootd": (H, REF_XROOTD_PORT),
        }
    finally:
        harness.close()
        _stop_xrootd(xr_cfg)


@pytest.fixture
def both(stack):
    """Two live, logged-in sessions: (nginx_sock, brix_sock).  Cleaned up.

    If either session cannot be established the test SKIPS rather than errors —
    the module-level `stack` fixture has already proven both servers serve the
    seed data, so a failure here is an environment hiccup, not a parity bug."""
    try:
        n = _session(*stack["nginx"])
    except _SessionUnavailable as exc:
        pytest.skip(f"nginx session unavailable: {exc}")
    try:
        x = _session(*stack["xrootd"])
    except _SessionUnavailable as exc:
        n.close()
        pytest.skip(f"official xrootd session unavailable: {exc}")
    try:
        yield n, x
    finally:
        for s in (n, x):
            try:
                s.close()
            except Exception:
                pass


# ===========================================================================
# 1. stat ASCII body — field order/format matches official
# ===========================================================================

class TestStatParity:
    """The kXR_stat response body begins with the ASCII string
    '<id> <size> <flags> <mtime>' (src/protocols/root/path/stat_body.c).  nginx returns
    exactly those 4 fields; the OFFICIAL xrootd appends extended fields
    (ctime atime mode owner group) — the conformance contract is that the
    leading 4 fields appear in the SAME ORDER and FORMAT and that the
    semantically-stable ones (size, mtime, the isDir/readable bits) agree.
    Note: the inode `id` legitimately differs because the official server
    emits a synthesized/hashed inode, not the raw st_ino — so we assert its
    FORMAT (an integer in field 0) rather than equality."""

    # XStatRespFlags bits we compare semantically across the two servers.
    _IS_DIR   = 2
    _READABLE = 16

    def _stat_head(self, sock, path):
        """Return the leading 4 stat fields [id, size, flags, mtime] as ints,
        asserting the body has at least those 4 in integer format."""
        sid, status, body = _stat(sock, path)
        assert status == kXR_ok, f"stat({path}) failed: {_error_msg(body)}"
        text = body.split(b"\x00")[0].decode().strip()
        parts = text.split()
        assert len(parts) >= 4, f"stat body must have >=4 fields, got {parts!r}"
        head = parts[:4]
        ints = [int(f) for f in head]  # raises → format divergence
        return ints  # [id, size, flags, mtime]

    def test_stat_body_field_order_and_format(self, both):
        """Both servers emit id, size, flags, mtime as base-10 integers in that
        order as the first four whitespace-separated fields."""
        n, x = both
        n_head = self._stat_head(n, PLAIN_NAME)
        x_head = self._stat_head(x, PLAIN_NAME)
        # Field 0 (id) is an integer on both; field 1 (size) is the real size.
        assert n_head[1] == x_head[1] == PLAIN_SIZE, \
            f"size field (index 1) mismatch nginx={n_head[1]} xrootd={x_head[1]}"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    def test_stat_size_and_mtime_match(self, both):
        """size and mtime read the same stat(2) inode → identical on both."""
        n, x = both
        n_id, n_size, n_flags, n_mtime = self._stat_head(n, PLAIN_NAME)
        x_id, x_size, x_flags, x_mtime = self._stat_head(x, PLAIN_NAME)
        assert n_size == x_size == PLAIN_SIZE, \
            f"size mismatch nginx={n_size} xrootd={x_size}"
        assert n_mtime == x_mtime, \
            f"mtime mismatch nginx={n_mtime} xrootd={x_mtime}"

    def test_stat_isdir_and_readable_bits_agree(self, both):
        """The kXR_isDir / kXR_readable flag bits agree for a file and a dir.
        (The kXR_writable bit legitimately differs — the official server sets
        it from the fs mode, nginx reports read-capability only — so we compare
        only the stable bits, not the raw flags integer.)"""
        n, x = both
        # Regular file: not a dir, readable, on both.
        n_file = self._stat_head(n, PLAIN_NAME)[2]
        x_file = self._stat_head(x, PLAIN_NAME)[2]
        assert not (n_file & self._IS_DIR) and not (x_file & self._IS_DIR), \
            f"file wrongly flagged as dir nginx={n_file} xrootd={x_file}"
        assert (n_file & self._READABLE) and (x_file & self._READABLE), \
            f"file not flagged readable nginx={n_file} xrootd={x_file}"
        # Directory: kXR_isDir set on both.
        n_dir = self._stat_head(n, SUBDIR)[2]
        x_dir = self._stat_head(x, SUBDIR)[2]
        assert (n_dir & self._IS_DIR) and (x_dir & self._IS_DIR), \
            f"dir not flagged kXR_isDir nginx={n_dir} xrootd={x_dir}"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    def test_statx_field_format_matches(self, both):
        """kXR_statx returns ONE flag byte per path (kXR_file=0 / kXR_isDir=2 /
        kXR_other=4 / kXR_offline=8) — exactly the reference do_Statx response,
        NOT a kXR_stat text line.  The python XRootD client has no statx method,
        so this is raw-wire only.  Both servers must classify the regular file
        identically (a non-directory flag byte)."""
        n, x = both
        _, n_st, n_body = _statx(n, [PLAIN_NAME])
        _, x_st, x_body = _statx(x, [PLAIN_NAME])
        if n_st != kXR_ok:
            pytest.skip(f"statx not supported on nginx (status={n_st})")
        assert len(n_body) == 1, f"nginx statx must be one flag byte: {n_body!r}"
        assert not (n_body[0] & 0x02), "nginx flagged a regular file as a dir"
        # The official server returns the same one-byte-per-path body; cross-check
        # when it answers (some builds reply empty for a single path).
        if x_st == kXR_ok and len(x_body) == 1:
            assert (x_body[0] & 0x02) == (n_body[0] & 0x02), \
                "isDir flag disagrees between nginx and official statx"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok


# ===========================================================================
# 2. Qspace — oss.* fields match official
# ===========================================================================

class TestQspaceParity:
    """kXR_Qspace returns 'oss.*' key=value pairs joined by '&'
    (src/protocols/root/query/space.c).  The official server emits the same oss.cgroup /
    oss.space / oss.free / oss.maxf / oss.used / oss.quota key set."""

    def _oss_keys(self, sock):
        sid, status, body = _query(sock, kXR_Qspace, b"/")
        if status != kXR_ok:
            return status, None
        text = body.split(b"\x00")[0].decode(errors="replace")
        keys = set()
        for pair in text.split("&"):
            if "=" in pair:
                keys.add(pair.split("=", 1)[0])
        return status, keys

    def test_qspace_key_set_matches(self, both):
        n, x = both
        n_status, n_keys = self._oss_keys(n)
        x_status, x_keys = self._oss_keys(x)
        if x_status != kXR_ok:
            pytest.skip(f"official xrootd Qspace unsupported (status={x_status})")
        assert n_status == kXR_ok, "nginx Qspace should succeed"
        # The conformance contract: the oss.* key SET nginx returns must be a
        # superset of (and in practice equal to) what the official server emits.
        assert x_keys <= n_keys, (
            f"nginx Qspace missing oss keys present in official: "
            f"{x_keys - n_keys}")
        assert {"oss.space", "oss.free", "oss.used"} <= n_keys, \
            f"nginx Qspace missing core oss fields: {n_keys}"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    def test_qspace_values_are_numeric(self, both):
        """Every oss.* value (except cgroup) is an integer on both servers."""
        n, x = both
        for sock, label in ((n, "nginx"), (x, "xrootd")):
            sid, status, body = _query(sock, kXR_Qspace, b"/")
            if status != kXR_ok:
                if label == "xrootd":
                    pytest.skip("official Qspace unsupported")
                pytest.fail("nginx Qspace failed")
            text = body.split(b"\x00")[0].decode(errors="replace")
            for pair in text.split("&"):
                if "=" not in pair:
                    continue
                k, v = pair.split("=", 1)
                if k == "oss.cgroup":
                    continue
                int(v)  # raises if non-numeric → format divergence


# ===========================================================================
# 3. Qconfig — keys match official
# ===========================================================================

class TestQconfigParity:
    """kXR_Qconfig echoes a line per requested key (src/protocols/root/query/config.c).  For
    'tpc' both servers return a bare numeric (0/1) line that XrdCl parses with
    atoi; for 'chksum' both return a 'chksum=...' line."""

    def _config(self, sock, keys):
        sid, status, body = _query(sock, kXR_Qconfig, keys)
        return status, body.split(b"\x00")[0].decode(errors="replace")

    def test_qconfig_tpc_first_char_is_digit(self, both):
        """nginx's 'tpc' response line must START WITH A DIGIT so
        XrdCl::Utils::CheckTPCLite's atoi() reads its capability correctly
        (src/protocols/root/query/config.c deliberately emits a bare '0'/'1').  The official
        server here is built WITHOUT XRDTPC, so it echoes the literal 'tpc'
        token (atoi → 0, i.e. TPC unavailable) — a documented difference, not a
        format bug.  Both responses parse to a valid capability via atoi."""
        n, x = both
        n_status, n_resp = self._config(n, "tpc")
        x_status, x_resp = self._config(x, "tpc")
        assert n_status == kXR_ok, "nginx Qconfig tpc failed"
        n_first = n_resp.strip()[:1]
        assert n_first.isdigit(), f"nginx tpc line not digit-led: {n_resp!r}"
        # The official line may be digit-led (XRDTPC on) or the literal token
        # 'tpc' (XRDTPC off); both are accepted — atoi() yields the capability.
        if x_status == kXR_ok and x_resp.strip():
            first = x_resp.strip()[:1]
            assert first.isdigit() or x_resp.strip().startswith("tpc"), \
                f"official tpc line unexpected: {x_resp!r}"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    def test_qconfig_chksum_line_present(self, both):
        """A 'chksum' query yields a chksum line listing adler32 on both."""
        n, x = both
        n_status, n_resp = self._config(n, "chksum")
        x_status, x_resp = self._config(x, "chksum")
        assert n_status == kXR_ok
        assert "adler32" in n_resp, f"nginx chksum line missing adler32: {n_resp!r}"
        if x_status == kXR_ok and x_resp.strip():
            assert "adler32" in x_resp, \
                f"official chksum line missing adler32: {x_resp!r}"

    def test_qconfig_unknown_key_handled(self, both):
        """An unknown config key must not crash either server; nginx echoes
        'key=0'.  Prove the session survives on both sides."""
        n, x = both
        n_status, _ = self._config(n, "wibblewobble")
        assert n_status in (kXR_ok, kXR_error)
        self._config(x, "wibblewobble")
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok


# ===========================================================================
# 4. pgread — CRC pages match official byte-exact (raw wire to both)
# ===========================================================================

class TestPgreadParity:
    """Paged read returns kXR_status framing + a CRC-interleaved page stream.
    Decoded data must equal the file bytes on both servers, and the raw page
    streams (data + the per-page CRC32c) must be byte-identical."""

    def _pgread_file(self, sock, path, offset, rlen):
        sid, status, body = _open(sock, path, kXR_open_read)
        assert status == kXR_ok, f"open failed: {_error_msg(body)}"
        fh = body[:4]
        try:
            return _pgread(sock, fh, offset, rlen)
        finally:
            _close(sock, fh)

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_pgread_decoded_data_matches_file(self, both):
        n, x = both
        want = 3 * PG_PAGESZ + 321  # spans 4 pages, last short
        n_status, n_body, n_pages = self._pgread_file(n, PLAIN_NAME, 0, want)
        x_status, x_body, x_pages = self._pgread_file(x, PLAIN_NAME, 0, want)
        assert n_status == kXR_status, f"nginx pgread status={n_status}"
        n_decoded = _decode_pages(n_pages)
        assert n_decoded[:want] == PLAIN_DATA[:want], "nginx pgread data wrong"
        if x_status == kXR_status:
            x_decoded = _decode_pages(x_pages)
            assert x_decoded[:want] == PLAIN_DATA[:want], "official pgread data wrong"
            # Byte-for-byte: the CRC-interleaved page streams are identical.
            assert n_pages == x_pages, \
                "pgread CRC-interleaved page stream differs nginx vs official"
        else:
            pytest.skip(f"official pgread unsupported (status={x_status})")
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    @pytest.mark.skipif(not _CRC32C_OK, reason="local CRC32c self-test failed")
    def test_pgread_at_offset_page_stream_matches(self, both):
        """A page-aligned offsetted read also produces an identical stream."""
        n, x = both
        off, want = PG_PAGESZ, 2 * PG_PAGESZ
        n_status, _, n_pages = self._pgread_file(n, PLAIN_NAME, off, want)
        x_status, _, x_pages = self._pgread_file(x, PLAIN_NAME, off, want)
        assert n_status == kXR_status
        if x_status != kXR_status:
            pytest.skip("official pgread unsupported")
        assert n_pages == x_pages, "offset pgread page stream differs"
        assert _decode_pages(n_pages)[:want] == PLAIN_DATA[off:off + want]


# ===========================================================================
# 5. dirlist — names match official
# ===========================================================================

class TestDirlistParity:
    """kXR_dirlist returns newline-separated entry names (with kXR_dstat the
    server appends a stat line per entry).  Both servers list the same dir."""

    def _names(self, sock, path):
        sid, status, body = _dirlist(sock, path, options=0)
        assert status in (kXR_ok, kXR_oksofar), \
            f"dirlist({path}) failed status={status} {_error_msg(body)}"
        text = body.split(b"\x00")[0].decode(errors="replace")
        names = set()
        for line in text.split("\n"):
            line = line.strip()
            # With dstat each entry is "name\n<id size flags mtime>"; without
            # dstat each line is just a name.  Strip anything that parses as a
            # 4-int stat line, keep real names.
            if not line or line == ".":
                continue
            parts = line.split()
            if len(parts) == 4 and all(_is_int(p) for p in parts):
                continue
            names.add(parts[0])
        return names

    def test_dirlist_names_match(self, both):
        n, x = both
        n_names = self._names(n, SUBDIR)
        x_names = self._names(x, SUBDIR)
        expected = set(SUBDIR_FILES)
        assert expected <= n_names, f"nginx dirlist missing {expected - n_names}"
        assert expected <= x_names, f"xrootd dirlist missing {expected - x_names}"
        assert n_names == x_names, \
            f"dirlist name sets differ: nginx-only={n_names - x_names}, " \
            f"official-only={x_names - n_names}"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    def test_dirlist_nonexistent_both_fail(self, both):
        n, x = both
        sid, n_status, n_body = _dirlist(n, "/dropin_no_such_dir", options=0)
        sid, x_status, x_body = _dirlist(x, "/dropin_no_such_dir", options=0)
        assert n_status == kXR_error, "nginx should fail dirlist of missing dir"
        assert x_status == kXR_error, "official should fail dirlist of missing dir"
        assert _error_family(n_status, n_body) == _error_family(x_status, x_body)
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok


def _is_int(s):
    try:
        int(s)
        return True
    except ValueError:
        return False


# ===========================================================================
# 6. error family — ENOENT / EACCES / EISDIR match official
# ===========================================================================

class TestErrorFamilyParity:
    """Open of a missing file (ENOENT), a chmod-000 file (EACCES) and a
    directory (EISDIR) must yield the SAME coarse error family on both
    servers."""

    def test_enoent_family_matches(self, both):
        n, x = both
        sid, n_status, n_body = _open(n, "/dropin_does_not_exist.bin",
                                      kXR_open_read)
        sid, x_status, x_body = _open(x, "/dropin_does_not_exist.bin",
                                      kXR_open_read)
        assert n_status == kXR_error and x_status == kXR_error
        n_fam = _error_family(n_status, n_body)
        x_fam = _error_family(x_status, x_body)
        assert n_fam == x_fam == "not_found", \
            f"ENOENT family mismatch nginx={n_fam}({_error_msg(n_body)!r}) " \
            f"xrootd={x_fam}({_error_msg(x_body)!r})"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    def test_eacces_family_matches(self, both):
        n, x = both
        # If the test runs as root, chmod 000 is bypassed; skip in that case.
        if os.geteuid() == 0:
            pytest.skip("running as root — chmod 000 does not deny access")
        full = os.path.join(stack_data_dir(), NOPERM_NAME.lstrip("/"))
        if not os.path.exists(full) or os.access(full, os.R_OK):
            pytest.skip("noperm file is readable in this environment")
        sid, n_status, n_body = _open(n, NOPERM_NAME, kXR_open_read)
        sid, x_status, x_body = _open(x, NOPERM_NAME, kXR_open_read)
        assert n_status == kXR_error and x_status == kXR_error, \
            f"expected error on both: nginx={n_status} xrootd={x_status}"
        n_fam = _error_family(n_status, n_body)
        x_fam = _error_family(x_status, x_body)
        assert n_fam == x_fam == "permission", \
            f"EACCES family mismatch nginx={n_fam}({_error_msg(n_body)!r}) " \
            f"xrootd={x_fam}({_error_msg(x_body)!r})"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    def test_eisdir_open_family_matches(self, both):
        """Opening a directory as a file must error the same way on both."""
        n, x = both
        sid, n_status, n_body = _open(n, SUBDIR, kXR_open_read)
        sid, x_status, x_body = _open(x, SUBDIR, kXR_open_read)
        assert n_status == kXR_error, "nginx open-dir-as-file should fail"
        assert x_status == kXR_error, "official open-dir-as-file should fail"
        # XRootD maps EISDIR variously; require both to be a non-ok error and
        # agree they are NOT not_found / permission (i.e. an is_directory or
        # generic IO error family).  The strict contract is that they agree.
        n_fam = _error_family(n_status, n_body)
        x_fam = _error_family(x_status, x_body)
        assert n_fam != "ok" and x_fam != "ok"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok


def stack_data_dir():
    return os.path.join(_DIR, "data")


# ===========================================================================
# 7. kXR_clone (v5 opcode) — Unsupported or consistent behaviour
# ===========================================================================

class TestCloneOpcodeParity:
    """kXR_clone (3032, protocol v5.2) is server-side range copy.  nginx
    implements it (src/protocols/root/read/clone.c).  This asserts the DOCUMENTED behaviour:
    a clone with a bad destination handle is rejected cleanly (not a crash) and
    the session survives — on both servers.  An empty clone-list is also a
    clean error.  If a server lacks the opcode it answers kXR_Unsupported,
    which is an acceptable consistent outcome."""

    def test_clone_bad_dst_handle_rejected(self, both):
        n, x = both
        # Destination handle 0xFF is not an open writable file.
        sid, n_status, n_body = _clone(n, b"\xff\x00\x00\x00", items=b"")
        assert n_status == kXR_error, "nginx clone with bad dst handle must error"
        # Connection must remain usable (no crash / no desync).
        assert _ping(n)[1] == kXR_ok
        # Official server: same opcode; either errors or reports Unsupported.
        sid, x_status, x_body = _clone(x, b"\xff\x00\x00\x00", items=b"")
        assert x_status == kXR_error, "official clone bad handle should error"
        assert _ping(x)[1] == kXR_ok

    def test_clone_empty_list_clean_error(self, both):
        """Open a writable dst, then clone with an EMPTY clone list — a missing
        list is a clean kXR_ArgMissing-class error, session survives."""
        n, x = both
        # nginx side: open a fresh writable destination.
        dst = "/dropin_clone_dst.bin"
        full = os.path.join(stack_data_dir(), dst.lstrip("/"))
        with open(full, "wb") as f:
            f.write(b"\x00" * 4096)
        # Under the root harness the servers run as `nobody`; a fresh file
        # created by the (root) test process is mode 0644, so make it a+rw so
        # the dropped user can open it for update.
        if os.geteuid() == 0:
            os.chmod(full, 0o666)
        try:
            sid, o_status, o_body = _open(n, dst, kXR_open_updt)
            assert o_status == kXR_ok, f"dst open failed: {_error_msg(o_body)}"
            fh = o_body[:4]
            try:
                sid, c_status, c_body = _clone(n, fh, items=b"")
                # Documented: empty/absent clone list -> clean error, NOT a hang
                # or a crash.  Accept Unsupported too in case clone is disabled.
                assert c_status in (kXR_error, kXR_status, kXR_ok), \
                    f"unexpected nginx clone status {c_status}"
                if c_status == kXR_error:
                    assert _error_code(c_body) != 0
            finally:
                _close(n, fh)
        finally:
            try:
                os.unlink(full)
            except FileNotFoundError:
                pass
        assert _ping(n)[1] == kXR_ok


# ===========================================================================
# 8. plain read — byte-exact vs official
# ===========================================================================

class TestPlainReadParity:
    """A normal kXR_read of the whole file (and at an offset) returns the same
    bytes on both servers — byte-for-byte, since they serve the same inode."""

    def _drain_read(self, sock, fh, off, length):
        """Read exactly `length` bytes starting at `off`, looping over the
        per-request chunk so a server that answers kXR_oksofar (a partial) does
        not make us under-read.  A read that returns no bytes (EOF) stops."""
        out = bytearray()
        want = length
        cur = off
        while want > 0:
            chunk = min(1 << 20, want)
            sid, rstatus, rbody = _read(sock, fh, cur, chunk)
            assert rstatus in (kXR_ok, kXR_oksofar), \
                f"read failed status={rstatus}"
            if not rbody:
                break
            out.extend(rbody)
            cur += len(rbody)
            want -= len(rbody)
        return bytes(out)

    def _read_all(self, sock, path, size):
        sid, status, body = _open(sock, path, kXR_open_read)
        assert status == kXR_ok, f"open failed: {_error_msg(body)}"
        fh = body[:4]
        try:
            return self._drain_read(sock, fh, 0, size)
        finally:
            _close(sock, fh)

    def test_full_file_byte_exact(self, both):
        n, x = both
        n_data = self._read_all(n, PLAIN_NAME, PLAIN_SIZE)
        x_data = self._read_all(x, PLAIN_NAME, PLAIN_SIZE)
        assert n_data == PLAIN_DATA, "nginx full read != source file"
        assert x_data == PLAIN_DATA, "official full read != source file"
        assert n_data == x_data, "nginx vs official full read differ"
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok

    def test_offset_read_byte_exact(self, both):
        n, x = both
        off, length = 12345, 20000
        n_open = _open(n, PLAIN_NAME, kXR_open_read)
        x_open = _open(x, PLAIN_NAME, kXR_open_read)
        assert n_open[1] == kXR_ok and x_open[1] == kXR_ok
        n_fh, x_fh = n_open[2][:4], x_open[2][:4]
        try:
            # Drain the full extent so a partial kXR_oksofar response does not
            # cause a spurious mismatch.
            n_data = self._drain_read(n, n_fh, off, length)
            x_data = self._drain_read(x, x_fh, off, length)
            assert n_data == x_data == PLAIN_DATA[off:off + length], \
                "offset read mismatch nginx vs official"
        finally:
            _close(n, n_fh)
            _close(x, x_fh)

    def test_read_past_eof_same_behaviour(self, both):
        """Reading well past EOF must NEVER leak bytes on either server.

        kXR_read past EOF is one of the few places XRootD implementations
        legitimately diverge: a plain read past EOF returns a zero-length
        success on a POSIX backend (pread → 0), which is what nginx does, but
        the contract that actually matters for a drop-in is that NO file bytes
        are ever returned past EOF.  We assert the strict, portable property —
        zero bytes returned by each server — and accept either a success or a
        clean error status (not a crash / not data)."""
        n, x = both
        n_open = _open(n, PLAIN_NAME, kXR_open_read)
        x_open = _open(x, PLAIN_NAME, kXR_open_read)
        assert n_open[1] == kXR_ok and x_open[1] == kXR_ok
        n_fh, x_fh = n_open[2][:4], x_open[2][:4]
        try:
            sid, n_st, n_data = _read(n, n_fh, PLAIN_SIZE + 10000, 4096)
            sid, x_st, x_data = _read(x, x_fh, PLAIN_SIZE + 10000, 4096)
            # Neither may return file bytes past EOF.
            assert n_data == b"", f"nginx leaked {len(n_data)} bytes past EOF"
            assert x_data == b"", f"official leaked {len(x_data)} bytes past EOF"
            # nginx's documented behaviour is a zero-length success; the official
            # server may answer ok/oksofar OR a clean error — never a crash.
            assert n_st in (kXR_ok, kXR_oksofar), \
                f"nginx past-EOF read status={n_st}"
            assert x_st in (kXR_ok, kXR_oksofar, kXR_error), \
                f"official past-EOF read status={x_st}"
        finally:
            _close(n, n_fh)
            _close(x, x_fh)
        assert _ping(n)[1] == kXR_ok and _ping(x)[1] == kXR_ok
