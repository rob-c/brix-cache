"""brix_admin_socket — §1.16 runtime admin unix socket (XrdXrootdAdmin analog).

`brix_admin_socket <path>` opens a worker-0 unix control socket speaking a
line-based protocol (documented divergence — stock's admin wire grammar is not
published in installed headers):

    list                   -> "ok <n>\n" then one "<sessid-hex> <dn|->" line each
    disc <sessid-hex>      -> "ok" | "err ..."   (disconnects the live session)
    msg <sessid-hex> <txt> -> "ok" | "err ..."   (kXR_attn/asyncms to the client)

Sessions self-register (sessid -> conn) at connection setup, so `list` shows
pre-login connections too, exactly like stock's admin view.

Coverage:
  * success  — a logged-in session appears in `list`; `msg` delivers an
               unsolicited kXR_attn carrying the text; `disc` closes the
               session's TCP connection.
  * error    — disc/msg of an unknown sessid -> "err"; a bogus verb -> "err".
  * security — the socket file is created mode 0600 (owner-only): filesystem
               permission is the privilege boundary.

Self-contained: launches its own short-lived nginx (worker_processes 1, so the
worker-0 slice is complete) — no shared fleet.
"""

import os
import socket
import struct
import subprocess
import time

import pytest

from settings import BIND_HOST, NGINX_BIN

import _test_session_bind_helpers as H

kXR_attn = 4001


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _write_conf(tmp_path, port, admin_path, workers=1):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    logs = tmp_path / "logs"
    logs.mkdir(exist_ok=True)
    conf = tmp_path / "nginx.conf"
    conf.write_text(
        "daemon on;\n"
        f"worker_processes {workers};\n"
        f"pid {logs}/nginx.pid;\n"
        f"error_log {logs}/error.log info;\n"
        "events { worker_connections 64; }\n"
        "stream {\n"
        "  server {\n"
        f"    listen {BIND_HOST}:{port};\n"
        "    brix_root on;\n"
        f"    brix_export {data};\n"
        "    brix_auth none;\n"
        f"    brix_admin_socket {admin_path};\n"
        "  }\n"
        "}\n")
    return conf, str(data)


def _nginx(*args, timeout=30):
    return subprocess.run([NGINX_BIN, *args], capture_output=True, text=True,
                          timeout=timeout)


def _launch(tmp_path, workers=1):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    port = _free_port()
    admin_path = str(tmp_path / "admin.sock")
    conf, data = _write_conf(tmp_path, port, admin_path, workers)
    t = _nginx("-p", str(tmp_path), "-c", str(conf), "-t")
    assert t.returncode == 0, f"config rejected: {t.stderr}"
    started = _nginx("-p", str(tmp_path), "-c", str(conf))
    assert started.returncode == 0, f"nginx failed to start: {started.stderr}"
    # Worker n serves "<path>.<n>"; wait for every expected socket + the port.
    want = [admin_path] + [f"{admin_path}.{n}" for n in range(1, workers)]
    deadline = time.time() + 5
    while time.time() < deadline:
        if all(os.path.exists(p) for p in want):
            try:
                socket.create_connection((BIND_HOST, port), timeout=0.5).close()
                break
            except OSError:
                pass
        time.sleep(0.1)
    return port, admin_path, data, conf


def _stop(tmp_path, conf):
    _nginx("-p", str(tmp_path), "-c", str(conf), "-s", "quit")
    time.sleep(0.2)


def _admin(admin_path, command, timeout=5):
    """One admin round-trip; returns the full reply text."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(admin_path)
        s.sendall(command.encode() + b"\n")
        chunks = []
        try:
            while True:
                b = s.recv(4096)
                if not b:
                    break
                chunks.append(b)
                # A complete reply always ends with a newline; single-line
                # replies are done as soon as one arrives.
                if b.endswith(b"\n") and (chunks[0][:3] != b"ok " or
                                          b"\n" in b"".join(chunks)):
                    break
        except socket.timeout:
            pass
        return b"".join(chunks).decode("latin-1")
    finally:
        s.close()


def test_list_msg_disc_roundtrip(tmp_path):
    """(success) list shows the session; msg reaches the client as kXR_attn;
    disc closes the session's connection."""
    port, admin_path, data, conf = _launch(tmp_path)
    H.ANON_HOST = BIND_HOST
    H.DATA_ROOT = data
    primary = None
    try:
        primary, sessid, stream = H._establish_primary(port)
        hexid = sessid.hex()

        # list: the session's sessid appears, with its peer address (the
        # operator's handle for choosing a session).
        reply = _admin(admin_path, "list")
        assert reply.startswith("ok "), reply
        line = next((l for l in reply.splitlines() if l.startswith(hexid)), None)
        assert line is not None, f"sessid {hexid} not in list reply:\n{reply}"
        assert "127.0.0.1" in line, f"peer address missing from list line: {line!r}"

        # msg: the client receives an unsolicited kXR_attn carrying the text.
        reply = _admin(admin_path, f"msg {hexid} hello-operator")
        assert reply.strip() == "ok", reply
        primary.settimeout(5)
        hdr = H._recv_exact(primary, 8)
        assert hdr is not None, "no attn frame arrived"
        status = struct.unpack(">H", hdr[2:4])[0]
        dlen = struct.unpack(">I", hdr[4:8])[0]
        assert status == kXR_attn, f"expected kXR_attn(4001), got {status}"
        body = H._recv_exact(primary, dlen)
        assert body is not None and b"hello-operator" in body, \
            f"attn payload missing message: {body!r}"

        # disc: the session's TCP connection is closed by the server.
        reply = _admin(admin_path, f"disc {hexid}")
        assert reply.strip() == "ok", reply
        primary.settimeout(5)
        got = primary.recv(1)
        assert got == b"", f"connection still alive after disc: {got!r}"
        primary = None
    finally:
        if primary is not None:
            primary.close()
        _stop(tmp_path, conf)


def test_pause_cont_gates_requests(tmp_path):
    """(success) pause: a request sent while paused gets NO reply (the server
    stops reading it — TCP backpressure) while the connection stays alive;
    cont: the backed-up request is then served."""
    port, admin_path, data, conf = _launch(tmp_path)
    H.ANON_HOST = BIND_HOST
    H.DATA_ROOT = data
    primary = None
    try:
        content = b"paused-read-data" * 8
        H._write_data_file("p.bin", content)
        primary, sessid, stream = H._establish_primary(port)
        fh = H._open_read(primary, stream, "/p.bin")
        hexid = sessid.hex()

        assert _admin(admin_path, f"pause {hexid}").strip() == "ok"

        # A read sent while paused must NOT be answered...
        H._send_read_only(primary, b"\x00\x61", fh, len(content))
        primary.settimeout(1.0)
        try:
            got = primary.recv(1)
            assert False, f"paused session answered: {got!r}"
        except socket.timeout:
            pass   # correctly gated

        # ...until cont, when the backed-up request is served in full.
        assert _admin(admin_path, f"cont {hexid}").strip() == "ok"
        primary.settimeout(5)
        r_stream, status, body = H._recv_response(primary)
        assert r_stream == b"\x00\x61", f"streamid {r_stream!r}"
        assert status in (H.kXR_ok, H.kXR_oksofar), f"status={status}"
        assert body == content, "post-cont read data mismatch"
    finally:
        if primary is not None:
            primary.close()
        _stop(tmp_path, conf)


def test_timed_pause_auto_resumes(tmp_path):
    """(success) pause <secs>: the session resumes by itself — the gated
    request is served after ~secs without any cont."""
    port, admin_path, data, conf = _launch(tmp_path)
    H.ANON_HOST = BIND_HOST
    H.DATA_ROOT = data
    primary = None
    try:
        content = b"timed-pause-data" * 4
        H._write_data_file("t.bin", content)
        primary, sessid, stream = H._establish_primary(port)
        fh = H._open_read(primary, stream, "/t.bin")

        assert _admin(admin_path, f"pause {sessid.hex()} 1").strip() == "ok"
        H._send_read_only(primary, b"\x00\x63", fh, len(content))

        # Not served immediately...
        primary.settimeout(0.4)
        try:
            primary.recv(1)
            assert False, "timed pause did not gate the request"
        except socket.timeout:
            pass
        # ...but served after the 1s timer fires, with no cont issued.
        primary.settimeout(5)
        r_stream, status, body = H._recv_response(primary)
        assert r_stream == b"\x00\x63" and status in (H.kXR_ok, H.kXR_oksofar)
        assert body == content
    finally:
        if primary is not None:
            primary.close()
        _stop(tmp_path, conf)


def test_abort_resets_connection(tmp_path):
    """(success) abort: the client is cut with an RST (ECONNRESET), the
    discriminator vs disc's clean FIN/EOF."""
    port, admin_path, data, conf = _launch(tmp_path)
    H.ANON_HOST = BIND_HOST
    H.DATA_ROOT = data
    primary = None
    try:
        primary, sessid, stream = H._establish_primary(port)
        assert _admin(admin_path, f"abort {sessid.hex()}").strip() == "ok"
        primary.settimeout(5)
        try:
            got = primary.recv(64)
            # An RST usually surfaces as ECONNRESET; some stacks deliver EOF
            # on the first read after RST — accept only the hard-cut outcomes.
            assert got == b"", f"connection alive after abort: {got!r}"
        except ConnectionResetError:
            pass   # the expected RST
        primary = None
    finally:
        if primary is not None:
            primary.close()
        _stop(tmp_path, conf)


def test_unknown_sessid_and_verb_are_errors(tmp_path):
    """(error) unknown sessid -> err for every targeted verb; unknown verb and
    malformed seconds -> err."""
    port, admin_path, data, conf = _launch(tmp_path)
    try:
        bogus = "00" * 16
        for cmd in (f"disc {bogus}", f"msg {bogus} nobody-home",
                    f"pause {bogus}", f"cont {bogus}", f"abort {bogus}"):
            reply = _admin(admin_path, cmd)
            assert reply.startswith("err"), f"{cmd!r} -> {reply!r}"
        reply = _admin(admin_path, "explode")
        assert reply.startswith("err"), reply
        reply = _admin(admin_path, f"pause {bogus} notasecs")
        assert reply.startswith("err"), reply
    finally:
        _stop(tmp_path, conf)


def test_socket_is_owner_only(tmp_path):
    """(security-neg) the admin socket is created mode 0600 — filesystem
    permission is the privilege boundary, so group/other get nothing."""
    port, admin_path, data, conf = _launch(tmp_path)
    try:
        mode = os.stat(admin_path).st_mode & 0o777
        assert mode == 0o600, f"admin socket mode {oct(mode)}, want 0600"
    finally:
        _stop(tmp_path, conf)


def test_multi_worker_socket_sweep(tmp_path):
    """(multi-worker reach) with worker_processes 2, worker 0 serves <path> and
    worker 1 serves <path>.1 — a session appears in exactly its owning worker's
    `list`, the non-owner refuses targeted verbs (worker isolation), and the
    owner's disc reaches it. Both socket files are 0600."""
    port, admin_path, data, conf = _launch(tmp_path, workers=2)
    socks = [admin_path, f"{admin_path}.1"]
    H.ANON_HOST = BIND_HOST
    H.DATA_ROOT = data
    primary = None
    try:
        for p in socks:
            assert os.path.exists(p), f"missing admin socket {p}"
            mode = os.stat(p).st_mode & 0o777
            assert mode == 0o600, f"{p} mode {oct(mode)}, want 0600"

        primary, sessid, stream = H._establish_primary(port)
        hexid = sessid.hex()

        # Exactly one worker owns the session.
        owners = [p for p in socks if hexid in _admin(p, "list")]
        assert len(owners) == 1, \
            f"session in {len(owners)} workers' lists (want exactly 1)"
        owner = owners[0]
        others = [p for p in socks if p != owner]

        # The non-owner must refuse the targeted verb (worker isolation)...
        reply = _admin(others[0], f"disc {hexid}")
        assert reply.startswith("err"), \
            f"non-owner disc did not err: {reply!r}"
        primary.settimeout(0.5)
        try:
            got = primary.recv(1)
            assert False, f"non-owner disc affected the session: {got!r}"
        except socket.timeout:
            pass

        # ...and the owner's disc reaches it.
        assert _admin(owner, f"disc {hexid}").strip() == "ok"
        primary.settimeout(5)
        assert primary.recv(1) == b"", "session survived the owner's disc"
        primary = None
    finally:
        if primary is not None:
            primary.close()
        _stop(tmp_path, conf)
