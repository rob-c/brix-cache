"""
tests/test_open_flags_lifecycle.py — raw-wire conformance for kXR_open flags
and the open/close file-handle lifecycle.

This suite drives kXR_open at the wire level (the Python XRootD client
sanitises flags before they reach the wire, so we frame ClientOpenRequest by
hand exactly like tests/test_readv_security.py) to assert the documented
XRootD open semantics implemented in src/protocols/root/read/open_request.c and
src/protocols/root/read/open_resolved_file.c:

  * kXR_new on an existing path -> O_EXCL -> EEXIST -> kXR_ItExists
  * kXR_delete truncates an existing file to zero (O_CREAT|O_TRUNC)
  * kXR_open_apnd appends (O_WRONLY|O_APPEND)
  * kXR_mkpath creates missing parent directories
  * kXR_retstat returns the inline stat string appended to ServerOpenBody
  * an invalid flag combination (kXR_open_apnd|kXR_delete) is handled cleanly
  * kXR_posc on a clean close persists the staged file to its final name
  * kXR_posc on an aborted (disconnect) close leaves NO final file
  * opening more than BRIX_MAX_FILES (16) handles -> clean kXR_ServerError
  * closing an already-closed handle -> kXR_FileNotOpen
  * writing to a read-only handle -> kXR_NotAuthorized

Read/flag-only cases run against the shared anon fleet (root://localhost:11094)
and skip cleanly if it is unreachable.  Create/POSC/exhaustion cases need
writable storage, so they provision their OWN dedicated nginx-xrootd stream
server (brix_allow_write on) on a dedicated high port (>=12950) with its own
data root, pid and error log, and tear it down with `nginx -s stop`.  Every
hostile or edge request is followed by a sanity op (kXR_ping / kXR_open)
proving the session survived.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_open_flags_lifecycle.py -v
"""

import os
import shutil
import socket
import struct
import time

import pytest

from settings import (
    DATA_ROOT,
    NGINX_ANON_PORT,
    OPEN_FLAGS_LIFECYCLE_DATA_ROOT,
    OPEN_FLAGS_LIFECYCLE_NGINX_PORT,
    SERVER_HOST,
)


# ---------------------------------------------------------------------------
# Opcodes / status / error codes (XProtocol.hh)
# ---------------------------------------------------------------------------

kXR_login = 3007
kXR_open  = 3010
kXR_ping  = 3011
kXR_read  = 3013
kXR_write = 3019
kXR_close = 3003

kXR_ok    = 0
kXR_error = 4003

# XErrorCode (XProtocol.hh)
kXR_ArgInvalid    = 3000
kXR_FileLocked    = 3003
kXR_FileNotOpen   = 3004
kXR_IOError       = 3007
kXR_NotAuthorized = 3010
kXR_NotFound      = 3011
kXR_ServerError   = 3012
kXR_Unsupported   = 3013
kXR_ItExists      = 3018

# An exclusive-create over an existing file (EEXIST).  The canonical XRootD
# mapping (XProtocol::mapError) returns kXR_ItExists (3018); nginx-xrootd's
# open handler (src/protocols/root/read/open_resolved_file.c) currently maps EEXIST to
# kXR_FileLocked (3003) with message "file already exists".  Both communicate
# the same EEXIST semantic to the client, so we accept either to remain a
# conformance check rather than pinning an implementation detail.
_EEXIST_CODES = (kXR_ItExists, kXR_FileLocked)

# XOpenRequestOption (XProtocol.hh)
kXR_delete    = 0x0002
kXR_new       = 0x0008
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_mkpath    = 0x0100
kXR_open_apnd = 0x0200
kXR_retstat   = 0x0400
kXR_posc      = 0x1000

# BRIX_MAX_FILES (src/core/types/tunables.h) — handles are a single wire byte.
BRIX_MAX_FILES = 16

# ServerOpenBody is fhandle[4] + cpsize[4] + cptype[4] = 12 bytes; with
# kXR_retstat a null-terminated stat string is appended after it.
OPEN_BODY_LEN = 12

ANON_HOST = SERVER_HOST
ANON_PORT = NGINX_ANON_PORT


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


def _session(host=ANON_HOST, port=ANON_PORT):
    sock = _handshake(host, port)
    _, status, _ = _login(sock)
    assert status == kXR_ok, "login rejected"
    return sock


def _open(sock, path, options=kXR_open_read, mode=0o644, streamid=b"\x00\x02"):
    """Frame ClientOpenRequest by hand: mode(u16) options(u16) optiont(u16)
    reserved[6] fhtemplt[4] dlen(i32), then the null-terminated path."""
    p = path.encode() + b"\x00" if isinstance(path, str) else path
    req = struct.pack("!2sHHH2s6s4sI",
                      streamid, kXR_open,
                      mode, options, b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                      len(p))
    sock.sendall(req + p)
    return _read_response(sock)


def _close(sock, fhandle, streamid=b"\x00\x0e"):
    req = struct.pack("!2sH4s12sI", streamid, kXR_close, fhandle,
                      b"\x00" * 12, 0)
    sock.sendall(req)
    return _read_response(sock)


def _write(sock, fhandle, offset, payload, streamid=b"\x00\x09"):
    """ClientWriteRequest: fhandle[4] offset(i64) pathid(1) reserved[3] dlen."""
    req = struct.pack("!2sH4sqB3sI", streamid, kXR_write, fhandle,
                      offset, 0, b"\x00\x00\x00", len(payload))
    sock.sendall(req + payload)
    return _read_response(sock)


def _read(sock, fhandle, offset, rlen, streamid=b"\x00\x06"):
    req = struct.pack("!2sH4sqiI", streamid, kXR_read, fhandle,
                      offset, rlen, 0)
    sock.sendall(req)
    return _read_response(sock)


def _ping(sock, streamid=b"\x00\x0f"):
    req = struct.pack("!2sH16sI", streamid, kXR_ping, b"\x00" * 16, 0)
    sock.sendall(req)
    return _read_response(sock)


def _error_code(body):
    return struct.unpack("!I", body[:4])[0] if len(body) >= 4 else 0


# ---------------------------------------------------------------------------
# Writable-server access — the server is a pre-started dedicated instance
# ---------------------------------------------------------------------------

H = SERVER_HOST

# The writable stream server is now a dedicated instance pre-started by
# manage_test_servers.sh start-all ("open-flags-lifecycle" on port 12980,
# serving data-open-flags-lifecycle); the wr_stack fixture just connects to it.
WR_NGINX_PORT = OPEN_FLAGS_LIFECYCLE_NGINX_PORT


def _reachable(host, port, timeout=1.0):
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


# NOTE: the writable server is no longer spawned here — it is the pre-started
# "open-flags-lifecycle" dedicated instance (see manage_test_servers.sh
# start-all). The former _writable_nginx_conf/_start_nginx/_stop_nginx/_wait_port
# helpers were removed with that migration; wr_stack now just connects.


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def anon():
    """Require the shared anon stream fleet for read/flag-only cases; skip if
    unreachable, exactly like test_readv_security.py's _require_server."""
    if not _reachable(ANON_HOST, ANON_PORT, 3):
        pytest.skip(f"anon stream server {ANON_HOST}:{ANON_PORT} unreachable")
    return (ANON_HOST, ANON_PORT)


@pytest.fixture(scope="module")
def wr_stack():
    """Connect to the dedicated WRITABLE nginx xrootd server pre-started by
    manage_test_servers.sh start-all (the "open-flags-lifecycle" instance,
    brix_allow_write on, serving OPEN_FLAGS_LIFECYCLE_DATA_ROOT).  Used for
    create/truncate/append/mkpath/POSC/exhaustion cases.  Skips cleanly if that
    dedicated instance is not running.  The server and this test share the local
    filesystem, so files seeded into data_dir are visible to the server and the
    server's writes are visible to the test's assertions."""
    data_dir = OPEN_FLAGS_LIFECYCLE_DATA_ROOT
    os.makedirs(data_dir, exist_ok=True)
    if not _reachable(H, WR_NGINX_PORT, 3):
        pytest.skip(
            f"dedicated writable nginx not reachable on {H}:{WR_NGINX_PORT} — "
            f"run tests/manage_test_servers.sh start-all")
    return {"host": H, "port": WR_NGINX_PORT, "data_dir": data_dir}


@pytest.fixture(scope="module")
def ro_data(anon):
    """A known read-only data file under the shared anon data root."""
    name = "/test_open_flags_ro.bin"
    os.makedirs(DATA_ROOT, exist_ok=True)
    full = os.path.join(DATA_ROOT, name.lstrip("/"))
    with open(full, "wb") as f:
        f.write(b"OPEN-FLAGS-RO-" * 64)
    return name


def _wr_seed(wr_stack, rel, data):
    """Materialise a file directly under the writable server's data root."""
    full = os.path.join(wr_stack["data_dir"], rel.lstrip("/"))
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as f:
        f.write(data)
    return full


def _wr_full(wr_stack, rel):
    return os.path.join(wr_stack["data_dir"], rel.lstrip("/"))


# ===========================================================================
# kXR_open flag semantics
# ===========================================================================

class TestOpenFlagSemantics:
    """Each open flag is asserted against the documented handler behavior, with
    a sanity op afterwards proving the connection survived."""

    def test_new_on_existing_itexists(self, wr_stack):
        """kXR_new on an EXISTING path maps to O_EXCL -> EEXIST -> already-exists.

        kXR_new without kXR_delete sets O_EXCL (open_resolved_file.c), so the
        create must fail with an EEXIST code (canonically kXR_ItExists; this
        server returns kXR_FileLocked) rather than truncating the file."""
        rel = "/new_existing.bin"
        _wr_seed(wr_stack, rel, b"PRECIOUS-DO-NOT-CLOBBER")
        sock = _session(wr_stack["host"], wr_stack["port"])
        try:
            _, status, body = _open(sock, rel, kXR_new)
            assert status == kXR_error, "kXR_new on existing must fail"
            assert _error_code(body) in _EEXIST_CODES, (
                f"expected an EEXIST code {_EEXIST_CODES}, "
                f"got {_error_code(body)}")
            # Original content must be untouched by the failed exclusive create.
            with open(_wr_full(wr_stack, rel), "rb") as f:
                assert f.read() == b"PRECIOUS-DO-NOT-CLOBBER"
            # Session still usable.
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_delete_truncates_to_zero(self, wr_stack):
        """kXR_delete on an existing file maps to O_CREAT|O_TRUNC: the file is
        truncated to zero length on open."""
        rel = "/delete_trunc.bin"
        _wr_seed(wr_stack, rel, b"X" * 4096)
        sock = _session(wr_stack["host"], wr_stack["port"])
        try:
            _, status, body = _open(sock, rel, kXR_delete)
            assert status == kXR_ok, _error_code(body)
            fh = body[:4]
            _close(sock, fh)
            assert os.path.getsize(_wr_full(wr_stack, rel)) == 0, (
                "kXR_delete must truncate the file to zero")
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_apnd_appends(self, wr_stack):
        """kXR_open_apnd maps to O_WRONLY|O_APPEND: a write lands at EOF,
        preserving existing content regardless of the requested offset."""
        rel = "/append.bin"
        seed = b"HEAD-"
        _wr_seed(wr_stack, rel, seed)
        sock = _session(wr_stack["host"], wr_stack["port"])
        try:
            _, status, body = _open(sock, rel, kXR_open_apnd)
            assert status == kXR_ok, _error_code(body)
            fh = body[:4]
            tail = b"TAIL"
            # offset 0 is ignored under O_APPEND; the write goes to EOF.
            _, wstatus, wbody = _write(sock, fh, 0, tail)
            assert wstatus == kXR_ok, _error_code(wbody)
            _close(sock, fh)
            with open(_wr_full(wr_stack, rel), "rb") as f:
                final = f.read()
            assert final == seed + tail, f"append produced {final!r}"
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_mkpath_creates_parents(self, wr_stack):
        """kXR_mkpath creates missing parent directories before the create."""
        rel = "/mkpath_a/mkpath_b/leaf.bin"
        # Idempotent: the persistent /tmp data dir may carry over a prior run.
        shutil.rmtree(_wr_full(wr_stack, "/mkpath_a"), ignore_errors=True)
        parent = os.path.dirname(_wr_full(wr_stack, rel))
        assert not os.path.exists(parent), "precondition: parents absent"
        sock = _session(wr_stack["host"], wr_stack["port"])
        try:
            _, status, body = _open(sock, rel, kXR_new | kXR_mkpath)
            assert status == kXR_ok, (
                f"kXR_mkpath open failed: {_error_code(body)}")
            fh = body[:4]
            _close(sock, fh)
            assert os.path.isdir(parent), "kXR_mkpath did not create parents"
            assert os.path.exists(_wr_full(wr_stack, rel))
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_mkpath_absent_without_flag(self, wr_stack):
        """Without kXR_mkpath, a create under a missing parent must fail
        cleanly (ENOENT -> kXR_NotFound), not silently create dirs."""
        rel = "/no_mkpath_x/no_mkpath_y/leaf.bin"
        shutil.rmtree(_wr_full(wr_stack, "/no_mkpath_x"), ignore_errors=True)
        parent = os.path.dirname(_wr_full(wr_stack, rel))
        assert not os.path.exists(parent)
        sock = _session(wr_stack["host"], wr_stack["port"])
        try:
            _, status, body = _open(sock, rel, kXR_new)
            assert status == kXR_error, "create under missing parent must fail"
            assert _error_code(body) in (kXR_NotFound, kXR_IOError,
                                         kXR_ServerError), _error_code(body)
            assert not os.path.exists(parent), (
                "parent must NOT be created without kXR_mkpath")
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_retstat_returns_inline_stat(self, ro_data, anon):
        """kXR_retstat appends a null-terminated stat string after the 12-byte
        ServerOpenBody; the size field must match the on-disk file size."""
        full = os.path.join(DATA_ROOT, ro_data.lstrip("/"))
        expected_size = os.path.getsize(full)
        sock = _session(*anon)
        try:
            _, status, body = _open(sock, ro_data,
                                    kXR_open_read | kXR_retstat)
            assert status == kXR_ok, _error_code(body)
            assert len(body) > OPEN_BODY_LEN, (
                "kXR_retstat must append an inline stat after ServerOpenBody")
            stat_str = body[OPEN_BODY_LEN:].split(b"\x00", 1)[0].decode()
            # Format is "<id> <size> <flags> <mtime>" (open_resolved_file.c).
            fields = stat_str.split()
            assert len(fields) >= 4, f"malformed inline stat: {stat_str!r}"
            assert int(fields[1]) == expected_size, (
                f"inline stat size {fields[1]} != actual {expected_size}")
            _close(sock, body[:4])
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_invalid_flag_combo_apnd_delete(self, wr_stack):
        """kXR_open_apnd|kXR_delete is a contradictory combination (append vs
        truncate).  The handler must produce a deterministic, clean result —
        never crash or hang — and the session must survive.

        The implementation evaluates kXR_open_updt/apnd for oflags and
        kXR_delete for O_CREAT|O_TRUNC, so it resolves to a concrete open; we
        assert it returns a well-formed protocol message either way."""
        rel = "/apnd_delete.bin"
        _wr_seed(wr_stack, rel, b"SEED-CONTENT")
        sock = _session(wr_stack["host"], wr_stack["port"])
        try:
            _, status, body = _open(sock, rel, kXR_open_apnd | kXR_delete)
            assert status in (kXR_ok, kXR_error), (
                f"unexpected status for contradictory flags: {status}")
            if status == kXR_ok:
                _close(sock, body[:4])
            else:
                # An explicit rejection must carry a sane error code.
                assert _error_code(body) in (
                    kXR_ArgInvalid, kXR_IOError, kXR_NotAuthorized,
                    kXR_ServerError, kXR_Unsupported), _error_code(body)
            # The connection must remain usable after the odd request.
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()


# ===========================================================================
# POSC (persist-on-successful-close) lifecycle
# ===========================================================================

class TestPoscLifecycle:
    """kXR_posc stages writes to a temp file; a clean kXR_close renames it to
    the final name, while a disconnect/abort unlinks the temp and leaves NO
    final file (open_resolved_file.c + close.c + fd_table.c free_fhandle)."""

    def test_posc_clean_close_persists(self, wr_stack):
        rel = "/posc_clean.bin"
        final = _wr_full(wr_stack, rel)
        if os.path.exists(final):
            os.unlink(final)
        sock = _session(wr_stack["host"], wr_stack["port"])
        try:
            _, status, body = _open(sock, rel, kXR_new | kXR_posc)
            assert status == kXR_ok, f"POSC open failed: {_error_code(body)}"
            fh = body[:4]
            payload = b"POSC-PERSISTED-PAYLOAD"
            _, wstatus, wbody = _write(sock, fh, 0, payload)
            assert wstatus == kXR_ok, _error_code(wbody)
            _, cstatus, _ = _close(sock, fh)
            assert cstatus == kXR_ok, "clean POSC close should succeed"
            # The final file must now exist with the written content.
            assert os.path.exists(final), "POSC clean close must persist file"
            with open(final, "rb") as f:
                assert f.read() == payload
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_posc_abort_leaves_no_final_file(self, wr_stack):
        """A POSC open that is written to but never cleanly closed (the client
        just drops the connection) must leave NO final file: the staging temp
        is unlinked on session teardown."""
        rel = "/posc_aborted.bin"
        final = _wr_full(wr_stack, rel)
        if os.path.exists(final):
            os.unlink(final)
        data_dir = wr_stack["data_dir"]
        before = set(os.listdir(data_dir))

        sock = _session(wr_stack["host"], wr_stack["port"])
        try:
            _, status, body = _open(sock, rel, kXR_new | kXR_posc)
            assert status == kXR_ok, f"POSC open failed: {_error_code(body)}"
            fh = body[:4]
            _, wstatus, _ = _write(sock, fh, 0, b"PARTIAL-UPLOAD-WILL-VANISH")
            assert wstatus == kXR_ok
        finally:
            # Abort: hard-drop the connection WITHOUT closing the handle. Done
            # in finally so an early assertion still drops the socket (which is
            # itself a valid abort) instead of leaking the fd to later tests.
            sock.close()

        # The abort is processed asynchronously by the server event loop:
        # the dropped socket surfaces as a readable EOF, which drives
        # on_disconnect -> close_all_files -> free_fhandle -> unlink(temp).
        # That teardown is prompt (~tens of ms) but NOT synchronous with our
        # sock.close(), so poll for both invariants to settle rather than
        # checking once and racing the event loop.  POSC staging uses
        # brix_make_tmp_path(), producing a "<base>.xrd-tmp.<pid>.<random>"
        # sibling (src/core/compat/tmp_path.c), so the orphan marker is ".xrd-tmp.".
        def _orphan_temps():
            return {n for n in (set(os.listdir(data_dir)) - before)
                    if ".xrd-tmp." in n}

        deadline = time.time() + 5.0
        while (time.time() < deadline
               and (os.path.exists(final) or _orphan_temps())):
            time.sleep(0.05)

        assert not os.path.exists(final), (
            "aborted POSC upload must NOT produce the final file")
        leaked = _orphan_temps()
        assert not leaked, f"orphan POSC temp files left behind: {leaked}"

        # A fresh session still works after the abort.
        sock2 = _session(wr_stack["host"], wr_stack["port"])
        try:
            assert _ping(sock2)[1] == kXR_ok
        finally:
            sock2.close()


# ===========================================================================
# File-handle lifecycle: exhaustion + double-close + capability
# ===========================================================================

class TestHandleLifecycle:

    def test_handle_exhaustion_clean_error(self, wr_stack):
        """Opening more than BRIX_MAX_FILES (16) handles on one session must
        return a clean kXR_ServerError ('too many open files'), not crash; and
        after closing one handle a subsequent open must succeed again."""
        rel = "/exhaust.bin"
        _wr_seed(wr_stack, rel, b"EXHAUST")
        sock = _session(wr_stack["host"], wr_stack["port"])
        handles = []
        try:
            # Fill every slot.
            for i in range(BRIX_MAX_FILES):
                sid = struct.pack("!H", 0x100 + i)
                _, status, body = _open(sock, rel, kXR_open_read, streamid=sid)
                assert status == kXR_ok, (
                    f"open #{i} failed unexpectedly: {_error_code(body)}")
                handles.append(body[:4])
            # The (MAX+1)th open must be rejected cleanly.
            _, status, body = _open(sock, rel, kXR_open_read,
                                    streamid=b"\x0f\xff")
            assert status == kXR_error, "over-cap open should be rejected"
            assert _error_code(body) == kXR_ServerError, (
                f"expected kXR_ServerError, got {_error_code(body)}")
            # Session still alive; the cap is graceful, not fatal.
            assert _ping(sock)[1] == kXR_ok
            # Free one slot -> a new open must succeed (slot reuse).
            _, cstatus, _ = _close(sock, handles.pop())
            assert cstatus == kXR_ok
            _, status, body = _open(sock, rel, kXR_open_read,
                                    streamid=b"\x0f\xfe")
            assert status == kXR_ok, (
                f"open after freeing a slot failed: {_error_code(body)}")
            handles.append(body[:4])
        finally:
            for fh in handles:
                try:
                    _close(sock, fh)
                except Exception:
                    pass
            sock.close()

    def test_double_close_rejected(self, wr_stack):
        """Closing a handle twice: the first close succeeds, the second must be
        rejected with kXR_FileNotOpen (the slot's fd is now -1)."""
        rel = "/double_close.bin"
        _wr_seed(wr_stack, rel, b"DOUBLE-CLOSE")
        sock = _session(wr_stack["host"], wr_stack["port"])
        try:
            _, status, body = _open(sock, rel, kXR_open_read)
            assert status == kXR_ok, _error_code(body)
            fh = body[:4]
            _, c1, _ = _close(sock, fh)
            assert c1 == kXR_ok, "first close should succeed"
            _, c2, b2 = _close(sock, fh)
            assert c2 == kXR_error, "second close must be rejected"
            assert _error_code(b2) == kXR_FileNotOpen, (
                f"expected kXR_FileNotOpen, got {_error_code(b2)}")
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()

    def test_readonly_handle_write_rejected(self, ro_data, anon):
        """Opening a file read-only (kXR_open_read) then issuing kXR_write must
        be rejected with kXR_NotAuthorized — the writable capability flag was
        never set at open time (fd_table.c validate_write_handle)."""
        sock = _session(*anon)
        try:
            _, status, body = _open(sock, ro_data, kXR_open_read)
            assert status == kXR_ok, _error_code(body)
            fh = body[:4]
            _, wstatus, wbody = _write(sock, fh, 0, b"SHOULD-NOT-BE-WRITTEN")
            assert wstatus == kXR_error, "write on read-only handle must fail"
            assert _error_code(wbody) == kXR_NotAuthorized, (
                f"expected kXR_NotAuthorized, got {_error_code(wbody)}")
            # A legitimate read on the same handle still works.
            _, rstatus, rbody = _read(sock, fh, 0, 8)
            assert rstatus == kXR_ok, _error_code(rbody)
            _close(sock, fh)
            assert _ping(sock)[1] == kXR_ok
        finally:
            sock.close()
