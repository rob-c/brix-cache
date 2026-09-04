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
import time
from pathlib import Path

import pytest

from settings import BIND_HOST
from server_registry import NginxInstanceSpec

import _test_session_bind_helpers as H

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-admin-socket")]

_SERVER = "lc-admin-socket"

kXR_attn = 4001


def _launch(lifecycle, workers=1):
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=_SERVER,
        template="nginx_lc_admin_socket.conf",
        template_values={"BIND_HOST": BIND_HOST, "WORKERS": workers},
        reason="runtime admin socket command and worker-isolation coverage"))
    admin_path = str(Path(endpoint.prefix) / "tmp" / "admin.sock")
    _await_admin_ready(endpoint.port, admin_path, workers)
    return endpoint.port, admin_path, endpoint.data_root


def _port_accepts(port):
    """True when a TCP connect to `port` on BIND_HOST succeeds right now."""
    try:
        socket.create_connection((BIND_HOST, port), timeout=0.5).close()
        return True
    except OSError:
        return False


def _await_admin_ready(port, admin_path, workers, deadline_s=5):
    """Wait until every worker's admin socket ("<path>" and "<path>.<n>") exists
    and the data port accepts connections."""
    want = [admin_path] + [f"{admin_path}.{n}" for n in range(1, workers)]
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        if all(os.path.exists(p) for p in want) and _port_accepts(port):
            return
        time.sleep(0.1)


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


def _admin_probe_list(admin_path, hexid):
    """`list` shows the session's sessid with its peer address."""
    reply = _admin(admin_path, "list")
    assert reply.startswith("ok "), reply
    line = next((l for l in reply.splitlines() if l.startswith(hexid)), None)
    assert line is not None, f"sessid {hexid} not in list reply:\n{reply}"
    assert "127.0.0.1" in line, f"peer address missing from list line: {line!r}"  # net-literal-allow: loopback literal is the subject under test


def _admin_probe_msg(admin_path, hexid, primary):
    """`msg` reaches the client as an unsolicited kXR_attn carrying the text."""
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


def _admin_probe_disc(admin_path, hexid, primary):
    """`disc` closes the session's TCP connection server-side."""
    reply = _admin(admin_path, f"disc {hexid}")
    assert reply.strip() == "ok", reply
    primary.settimeout(5)
    got = primary.recv(1)
    assert got == b"", f"connection still alive after disc: {got!r}"


def test_list_msg_disc_roundtrip(lifecycle):
    """(success) list shows the session; msg reaches the client as kXR_attn;
    disc closes the session's connection."""
    port, admin_path, data = _launch(lifecycle)
    H.ANON_HOST = BIND_HOST
    H.DATA_ROOT = data
    primary = None
    try:
        primary, sessid, stream = H._establish_primary(port)
        hexid = sessid.hex()
        _admin_probe_list(admin_path, hexid)
        _admin_probe_msg(admin_path, hexid, primary)
        _admin_probe_disc(admin_path, hexid, primary)
        primary = None
    finally:
        if primary is not None:
            primary.close()


def test_pause_cont_gates_requests(lifecycle):
    """(success) pause: a request sent while paused gets NO reply (the server
    stops reading it — TCP backpressure) while the connection stays alive;
    cont: the backed-up request is then served."""
    port, admin_path, data = _launch(lifecycle)
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


def test_timed_pause_auto_resumes(lifecycle):
    """(success) pause <secs>: the session resumes by itself — the gated
    request is served after ~secs without any cont."""
    port, admin_path, data = _launch(lifecycle)
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


def test_abort_resets_connection(lifecycle):
    """(success) abort: the client is cut with an RST (ECONNRESET), the
    discriminator vs disc's clean FIN/EOF."""
    port, admin_path, data = _launch(lifecycle)
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


def test_unknown_sessid_and_verb_are_errors(lifecycle):
    """(error) unknown sessid -> err for every targeted verb; unknown verb and
    malformed seconds -> err."""
    _port, admin_path, _data = _launch(lifecycle)
    bogus = "00" * 16
    for cmd in (f"disc {bogus}", f"msg {bogus} nobody-home",
                f"pause {bogus}", f"cont {bogus}", f"abort {bogus}"):
        reply = _admin(admin_path, cmd)
        assert reply.startswith("err"), f"{cmd!r} -> {reply!r}"
    assert _admin(admin_path, "explode").startswith("err")
    assert _admin(admin_path, f"pause {bogus} notasecs").startswith("err")


def test_socket_is_owner_only(lifecycle):
    """(security-neg) the admin socket is created mode 0600 — filesystem
    permission is the privilege boundary, so group/other get nothing."""
    _port, admin_path, _data = _launch(lifecycle)
    mode = os.stat(admin_path).st_mode & 0o777
    assert mode == 0o600, f"admin socket mode {oct(mode)}, want 0600"


def test_multi_worker_socket_sweep(lifecycle):
    """(multi-worker reach) with worker_processes 2, worker 0 serves <path> and
    worker 1 serves <path>.1 — a session appears in exactly its owning worker's
    `list`, the non-owner refuses targeted verbs (worker isolation), and the
    owner's disc reaches it. Both socket files are 0600."""
    port, admin_path, data = _launch(lifecycle, workers=2)
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
        owner, others = _sole_owner(socks, hexid)
        _assert_nonowner_disc_isolated(others[0], hexid, primary)

        # ...and the owner's disc reaches it.
        assert _admin(owner, f"disc {hexid}").strip() == "ok"
        primary.settimeout(5)
        assert primary.recv(1) == b"", "session survived the owner's disc"
        primary = None
    finally:
        if primary is not None:
            primary.close()


def _sole_owner(socks, hexid):
    """The one admin socket whose `list` shows the session; returns
    (owner, [non-owners]) and asserts exactly one owner."""
    owners = [p for p in socks if hexid in _admin(p, "list")]
    assert len(owners) == 1, \
        f"session in {len(owners)} workers' lists (want exactly 1)"
    owner = owners[0]
    return owner, [p for p in socks if p != owner]


def _assert_nonowner_disc_isolated(nonowner, hexid, primary):
    """A non-owner worker refuses the targeted disc and cannot affect the
    session (worker isolation)."""
    reply = _admin(nonowner, f"disc {hexid}")
    assert reply.startswith("err"), f"non-owner disc did not err: {reply!r}"
    primary.settimeout(0.5)
    try:
        got = primary.recv(1)
        assert False, f"non-owner disc affected the session: {got!r}"
    except socket.timeout:
        pass
