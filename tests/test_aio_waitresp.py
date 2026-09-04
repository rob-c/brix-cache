"""
Async-engine deferred-reply handling (client/lib/aio_io.c):
the aio dispatch must understand kXR_waitresp → kXR_attn(asynresp), the flow
XRootD uses to defer a reply (async TPC, tape recall, ...). The synchronous
path (frame.c) and the server's own TPC-pull client already handle it; this
suite pins the aio engine's handling.

nginx-xrootd answers every request synchronously, so this path can only be
exercised against a *deferring* server. Each test stands up a minimal mock
XRootD server (handshake + login, then a scripted deferral scenario) and
drives the aio_waitresp C driver (one kXR_ping via brix_aio_call) at it.

Covered:
  * waitresp → asynresp(kXR_ok)         — op succeeds via the deferred reply
  * waitresp → asynresp(kXR_error)      — the embedded error is surfaced (bounded)
  * waitresp → waitresp → asynresp      — a re-armed wait still resolves
  * hostile pushes between defer+reply  — asyncms / malformed / lying-edlen attn
                                          frames are ignored, real reply still wins
  * nested attn inside asynresp         — rejected cleanly (no recursion, no crash)
  * deadline extension                  — waitresp extends the request deadline by
                                          the advertised delay (reply after the
                                          original deadline still succeeds)

Run:
    PYTHONPATH=tests pytest tests/test_aio_waitresp.py -v
"""

import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import threading
import tempfile
import time

import pytest

from settings import HOST, BIND_HOST

pytestmark = pytest.mark.timeout(60)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
DRIVER = os.path.join(CLIENT_DIR, "bin", "aio_waitresp")

kXR_ok = 0
kXR_attn = 4001
kXR_error = 4003
kXR_waitresp = 4006
kXR_asyncms = 5002
kXR_asynresp = 5008


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionResetError(f"closed: wanted {n}, got {len(buf)}")
        buf += chunk
    return buf


def _hdr(streamid, status, dlen):
    return struct.pack(">2sHI", streamid, status, dlen)


def _bootstrap_login_ok(conn):
    """Handshake + kXR_protocol + kXR_login → kXR_ok (anonymous)."""
    _recv_exact(conn, 20)
    conn.sendall(_hdr(b"\x00\x00", kXR_ok, 8) + struct.pack(">II", 0x00000520, 1))
    hdr = _recv_exact(conn, 24)
    conn.sendall(_hdr(hdr[:2], kXR_ok, 8) + struct.pack(">II", 0x00000520, 1))
    hdr = _recv_exact(conn, 24)
    dlen = struct.unpack(">I", hdr[20:24])[0]
    if dlen:
        _recv_exact(conn, dlen)
    conn.sendall(_hdr(hdr[:2], kXR_ok, 16) + b"\x01" * 16)


def _read_request(conn):
    """Read one 24-byte request header (+ payload); return its stream id."""
    hdr = _recv_exact(conn, 24)
    dlen = struct.unpack(">I", hdr[20:24])[0]
    if dlen:
        _recv_exact(conn, dlen)
    return hdr[:2]


def _waitresp_frame(sid, secs=0):
    return _hdr(sid, kXR_waitresp, 4) + struct.pack(">I", secs)


def _asynresp_frame(req_sid, inner_status, inner_data=b"", inner_dlen=None,
                    outer_sid=None):
    """A kXR_attn frame whose body is an asynresp envelope:
    actnum[4]=kXR_asynresp, reserved[4], inner ServerResponseHdr[8], data.
    inner_dlen lets a test LIE about the inner length (over-read guard);
    outer_sid defaults to mirroring the deferred stream id."""
    if inner_dlen is None:
        inner_dlen = len(inner_data)
    if outer_sid is None:
        outer_sid = req_sid
    inner_hdr = _hdr(req_sid, inner_status, inner_dlen)
    body = struct.pack(">I", kXR_asynresp) + b"\x00\x00\x00\x00" + inner_hdr + inner_data
    return _hdr(outer_sid, kXR_attn, len(body)) + body


def _asyncms_frame(sid, text=b"[!] server notice"):
    """An unsolicited server-push text notification (must be ignored)."""
    body = struct.pack(">I", kXR_asyncms) + text
    return _hdr(sid, kXR_attn, len(body)) + body


def _scripted_frames(scenario, sid):
    """The frame sequence (with optional inter-frame sleeps) for one scenario.
    Returns a list of bytes-or-float items (float = sleep seconds)."""
    if scenario == "ok":
        return [_waitresp_frame(sid), _asynresp_frame(sid, kXR_ok)]
    if scenario == "error":
        # NOT NUL-terminated on purpose: the inner error message fills the frame
        # exactly, so a naive %s would over-read past the buffer (the client must
        # bound it with %.*s).
        err = struct.pack(">I", 3011) + b"deferred op failed"
        return [_waitresp_frame(sid), _asynresp_frame(sid, kXR_error, err)]
    if scenario == "double_wait":
        return [_waitresp_frame(sid), _waitresp_frame(sid),
                _asynresp_frame(sid, kXR_ok)]
    if scenario == "hostile_junk_then_ok":
        # Between the deferral and the real reply, a hostile/chatty server pushes:
        # an asyncms mirroring the request sid, a truncated asynresp envelope,
        # and an asynresp whose inner header lies about its length (edlen way
        # past the frame). None may complete/fail the request or over-read;
        # the well-formed reply must still win.
        short = _hdr(sid, kXR_attn, 8) + struct.pack(">I", kXR_asynresp) + b"\x00" * 4
        lying = _asynresp_frame(sid, kXR_ok, b"xy", inner_dlen=0x00FFFFFF)
        return [_waitresp_frame(sid), _asyncms_frame(sid), short, lying]
    if scenario == "nested_attn":
        # asynresp whose inner status is itself kXR_attn: unwrapping must not
        # recurse; the request fails cleanly as a protocol error.
        inner = struct.pack(">I", kXR_asynresp) + b"\x00" * 12
        return [_waitresp_frame(sid), _asynresp_frame(sid, kXR_attn, inner)]
    if scenario == "deadline_extension":
        # Advertise a 30 s deferral, reply after 4 s. The driver's own deadline
        # is 2.5 s, so this only succeeds if waitresp extended it.
        return [_waitresp_frame(sid, secs=30), 4.0, _asynresp_frame(sid, kXR_ok)]
    raise ValueError(scenario)


def _listener(port):
    """Bind and listen on `port`, in the CALLER's thread.

    Binding used to happen inside the server thread, which left the port chosen
    but unowned for as long as the thread took to start, and — worse — made a
    bind failure fatal in silence: the thread died before `ready.set()`, the
    driver then connected to whatever else held the port, and the test failed
    as an opaque "connection closed by peer" naming neither the port nor the
    real error.  Owning the socket before the thread exists removes both.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BIND_HOST, port))
    srv.listen(1)
    return srv


def _serve_once(srv, scenario, ready, notes):
    """Serve one scripted session on the already-bound listener `srv`.

    `notes` collects what only this thread can see.  A mid-session OSError stays
    swallowed — several scenarios END with the driver hanging up on us, so a
    write failing is expected — but anything that means the session never got
    off the ground is recorded for `_run_mock` to raise on.
    """
    srv.settimeout(30)
    ready.set()
    try:
        conn, _ = srv.accept()
    except socket.timeout:
        notes.append("mock server: driver never connected (30s accept timeout)")
        srv.close()
        return
    try:
        _bootstrap_login_ok(conn)
        sid = _read_request(conn)
        for item in _scripted_frames(scenario, sid):
            if isinstance(item, (int, float)):
                time.sleep(item)
            else:
                conn.sendall(item)
        # drain anything the client sends afterwards until it closes
        conn.settimeout(10)
        try:
            while conn.recv(4096):
                pass
        except OSError:
            pass
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass                        # the driver hung up on us — several
                                    # scenarios end exactly that way
    except Exception as exc:        # noqa: BLE001 - a mock bug, not a driver one
        notes.append(f"mock server: {type(exc).__name__}: {exc}")
    finally:
        conn.close()
        srv.close()


def _free_port():
    from ephemeral_port import free_port
    return free_port(BIND_HOST)


def _same_file_version(before, after):
    return (before.st_size, before.st_mtime_ns) == \
           (after.st_size, after.st_mtime_ns)


def _snapshot_driver(directory, source=DRIVER):
    """Copy one complete driver version outside the mutable build tree."""
    source = Path(source)
    target_dir = Path(directory)
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / source.name
    for _ in range(8):
        try:
            before = source.stat()
            shutil.copy2(source, target)
            after = source.stat()
        except OSError:
            time.sleep(0.05)
            continue
        if before.st_size and _same_file_version(before, after):
            target.chmod(0o755)
            return target
        time.sleep(0.05)
    raise RuntimeError(f"could not snapshot stable test driver: {source}")


def _ensure_driver():
    """Build the driver on demand; skip when it cannot be built."""
    if os.path.exists(DRIVER):
        return
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler / aio_waitresp not built")
    subprocess.run(["make", "-C", CLIENT_DIR, "aio-waitresp"],
                   capture_output=True, text=True, timeout=240)
    if not os.path.exists(DRIVER):
        pytest.skip("aio_waitresp build failed")


def _run_mock(scenario, deadline_ms=30000):
    _ensure_driver()
    port = _free_port()
    srv = _listener(port)
    ready = threading.Event()
    notes = []
    t = threading.Thread(target=_serve_once, args=(srv, scenario, ready, notes),
                         daemon=True)
    t.start()
    ready.wait(5)
    url = f"root://{HOST}:{port}"
    with tempfile.TemporaryDirectory(prefix="aio-waitresp-") as directory:
        driver = _snapshot_driver(directory)
        p = subprocess.run([driver, url, str(deadline_ms)],
                           capture_output=True, text=True, timeout=45)
    t.join(15)
    if notes:
        raise AssertionError(
            f"{scenario} on port {port}: " + "; ".join(notes)
            + f" (driver rc={p.returncode} stderr={p.stderr!r})")
    return p


def test_driver_snapshot_is_executable_and_independent(tmp_path):
    source = tmp_path / "driver"
    source.write_text("#!/bin/sh\nprintf 'original\\n'\n", encoding="utf-8")
    source.chmod(0o755)

    captured = _snapshot_driver(tmp_path / "captured", source)
    source.write_text("#!/bin/sh\nprintf 'rebuilt\\n'\n", encoding="utf-8")

    result = subprocess.run([captured], capture_output=True, text=True)
    assert result.stdout.strip() == "original"


def test_waitresp_asynresp_ok():
    """waitresp → asynresp(kXR_ok): the op resolves via the deferred reply."""
    p = _run_mock("ok")
    assert p.returncode == 0, f"stdout={p.stdout!r} stderr={p.stderr!r}"


def test_waitresp_asynresp_error():
    """waitresp → asynresp(kXR_error): the embedded error is surfaced cleanly."""
    p = _run_mock("error")
    assert p.returncode == 1, f"stdout={p.stdout!r} stderr={p.stderr!r}"
    assert "deferred op failed" in p.stderr, p.stderr


def test_double_waitresp_then_asynresp():
    """A re-armed wait (waitresp → waitresp → asynresp) still resolves to success."""
    p = _run_mock("double_wait")
    assert p.returncode == 0, f"stdout={p.stdout!r} stderr={p.stderr!r}"


def test_hostile_pushes_ignored_real_reply_wins():
    """Security-neg: asyncms + malformed + length-lying attn frames between the
    deferral and the reply neither complete nor fail the request (and cannot
    over-read); the well-formed asynresp still succeeds."""
    p = _run_mock("hostile_junk_then_ok")
    assert p.returncode == 0, f"stdout={p.stdout!r} stderr={p.stderr!r}"


def test_nested_attn_rejected_cleanly():
    """Security-neg: an asynresp wrapping another kXR_attn must not recurse; the
    request fails as a clean protocol error (no crash, no hang)."""
    p = _run_mock("nested_attn")
    assert p.returncode == 1, f"stdout={p.stdout!r} stderr={p.stderr!r}"
    # the WAITRESP must have been accepted; the failure is the nested attn itself
    assert "unexpected response status 4001" in p.stderr, p.stderr


def test_waitresp_extends_deadline():
    """waitresp advertising a delay extends the request deadline: a reply that
    lands after the original deadline (but within the advertised window) wins."""
    p = _run_mock("deadline_extension", deadline_ms=2500)
    assert p.returncode == 0, f"stdout={p.stdout!r} stderr={p.stderr!r}"
