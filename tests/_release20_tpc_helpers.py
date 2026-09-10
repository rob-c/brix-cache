"""Shared driver for the 2.0 F7 native-TPC suites.

`test_release20_tpc_multihop.py` and `test_release20_tpc_streams.py` need the
same four things: a raw root:// rendezvous pull that carries an arbitrary
opaque, a splice in front of the source that counts connections and can answer
the first kXR_open with a kXR_redirect, error-log deltas, and the wire constants
the assertions read. They live here so neither suite grows a private copy.
"""

import os
import socket
import struct
import threading
import time

import pytest

from _test_a_robustness_helpers import make_close_req
from _test_audit15g_helpers import seed_tree
from _test_release20_metrics_helpers import wait_port
from ephemeral_port import free_port as _free_port
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN
from test_audit15c_tpc_token_exchange import _drive_pull
from test_phase25_ratelimit import KXR_OK, _xrd_login, _xrd_open, _xrd_recv_status

SRC_LFN = "/src.bin"
TPC_FLAGS = 0x0008 | 0x4000 | 0x0100           # kXR_new | kXR_open_wrto | kXR_mkpath

KXR_OPEN = 3010
KXR_REDIRECT = 4004
XERR_NOT_AUTHORIZED = 3010
XERR_SERVER_ERROR = 3012

HANDSHAKE_LEN = 20                             # ClientInitHandShake
REQ_HDR_LEN = 24                               # every other client request header
RESP_HDR_LEN = 8


def free_port():
    return _free_port(BIND_HOST)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _shutdown(sock, how):
    try:
        sock.shutdown(how)
    except OSError:
        pass


class SourceSplice:
    """A TCP splice in front of a root:// source.

    Every accepted connection is counted (`accepted`): a multi-stream pull shows
    up as one primary connection plus one per bound sub-stream. While armed, the
    first kXR_open seen on any connection is answered with a kXR_redirect frame
    instead of being forwarded, and counted (`redirects`). The arm is one-shot,
    so a chain of splices can each redirect exactly once.
    """

    def __init__(self, upstream_port):
        self.upstream_port = upstream_port
        self.listen = free_port()
        self.accepted = 0
        self.redirects = 0
        self._lock = threading.Lock()
        self._redirect = None
        self._stop = threading.Event()
        self._sock = None
        self._thread = None
        self._conns = []

    # -- arming -----------------------------------------------------------

    def arm_redirect(self, host, port, opaque=""):
        with self._lock:
            self._redirect = (host, port, opaque)

    def arm_malformed(self):
        with self._lock:
            self._redirect = ("", 0, None)

    def disarm(self):
        with self._lock:
            self._redirect = None

    def reset(self):
        with self._lock:
            self.accepted = 0
            self.redirects = 0
            self._redirect = None

    def _take_redirect(self, hdr):
        """The redirect frame to answer this request with, or None to forward it."""
        if struct.unpack("!H", hdr[2:4])[0] != KXR_OPEN:
            return None
        with self._lock:
            target = self._redirect
            if target is None:
                return None
            self._redirect = None
            self.redirects += 1
        host, port, opaque = target
        if opaque is None:
            body = b"\x00\x01"                 # shorter than the port field: malformed
        else:
            body = struct.pack("!i", port) + host.encode()
            if opaque:
                body += b"?" + opaque.encode()
        return hdr[:2] + struct.pack("!HI", KXR_REDIRECT, len(body)) + body

    # -- pumps ------------------------------------------------------------

    def _relay_one(self, client, upstream):
        """Forward one framed request; False once the stream ends or a redirect went out."""
        hdr = recv_exact(client, REQ_HDR_LEN)
        if len(hdr) < REQ_HDR_LEN:
            return False
        dlen = struct.unpack("!I", hdr[20:24])[0]
        body = recv_exact(client, dlen)
        if len(body) < dlen:
            return False
        frame = self._take_redirect(hdr)
        if frame is not None:
            client.sendall(frame)
            return False
        upstream.sendall(hdr + body)
        return True

    def _pump_requests(self, client, upstream):
        try:
            head = recv_exact(client, HANDSHAKE_LEN)
            if len(head) == HANDSHAKE_LEN:
                upstream.sendall(head)
                while not self._stop.is_set() and self._relay_one(client, upstream):
                    pass
        except OSError:
            pass
        finally:
            _shutdown(upstream, socket.SHUT_WR)

    def _pump_replies(self, upstream, client):
        try:
            while not self._stop.is_set():
                data = upstream.recv(65536)
                if not data:
                    return
                client.sendall(data)
        except OSError:
            pass
        finally:
            _shutdown(client, socket.SHUT_WR)

    def _handle(self, client):
        try:
            upstream = socket.create_connection((HOST, self.upstream_port), timeout=10)
        except OSError:
            client.close()
            return
        upstream.settimeout(None)
        self._conns.extend((client, upstream))
        for target, args in ((self._pump_requests, (client, upstream)),
                             (self._pump_replies, (upstream, client))):
            threading.Thread(target=target, args=args, daemon=True).start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self.accepted += 1
            self._handle(client)

    # -- lifecycle --------------------------------------------------------

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((BIND_HOST, self.listen))
        self._sock.listen(16)
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        if self._sock is not None:
            self._sock.close()
        for conn in self._conns:
            try:
                conn.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=5)


# -- raw rendezvous pull ----------------------------------------------------


def err_text(body):
    """(errcode, message) from a kXR_error body; (-1, '') when it is not one."""
    if len(body) < 4:
        return -1, ""
    return struct.unpack("!I", body[:4])[0], body[4:].rstrip(b"\0").decode(errors="replace")


def arm(port, key, *, timeout=180):
    """Register `key` on the source at `port`; the returned socket must outlive the pull."""
    sock = _xrd_login(HOST, port)
    sock.settimeout(timeout)
    status, body = _xrd_open(sock, f"{SRC_LFN}?tpc.key={key}&tpc.dst={HOST}&tpc.stage=placement")
    if status != KXR_OK:
        sock.close()
        raise AssertionError(f"arm on :{port} failed: {err_text(body)}")
    return sock


def open_frame(sock, path, flags, mode=0o644):
    payload = path.encode()
    sock.sendall(struct.pack(">BBH", 0, 1, KXR_OPEN)
                 + struct.pack(">HH12s", mode, flags, b"\x00" * 12)
                 + struct.pack(">I", len(payload)) + payload)
    return _xrd_recv_status(sock)


def pull(dst_port, src_port, dest, *, arm_port, size, tag="f7", extra="", timeout=180):
    """Drive one native TPC pull of SRC_LFN from `src_port` into `dest` on `dst_port`.

    The key is armed on `arm_port` (the real source; `src_port` may be a splice
    in front of it). `extra` is appended verbatim to the destination opaque, so a
    caller can add `&tpc.str=N`. Returns the final (status, body) of the pull.
    """
    key = f"{tag}-{os.getpid()}-{time.monotonic_ns()}"
    armed = arm(arm_port, key)
    sock = None
    try:
        sock = _xrd_login(HOST, dst_port)
        sock.settimeout(timeout)
        opaque = (f"?tpc.src={HOST}:{src_port}&tpc.key={key}&tpc.lfn={SRC_LFN}"
                  f"&tpc.stage=copy&oss.asize={size}{extra}")
        status, body = open_frame(sock, dest + opaque, TPC_FLAGS)
        if status != KXR_OK:
            return status, body
        fhandle = body[:4]
        status, body = _drive_pull(sock, fhandle)
        sock.sendall(make_close_req(fhandle))
        _xrd_recv_status(sock)
        return status, body
    finally:
        if sock is not None:
            sock.close()
        armed.close()


def published(root, dest, blob):
    """True once `dest` under `root` holds exactly `blob`."""
    path = os.path.join(str(root), dest.lstrip("/"))
    try:
        with open(path, "rb") as fh:
            return fh.read() == blob
    except OSError:
        return False


# -- error-log deltas -------------------------------------------------------


def log_path(endpoint):
    return os.path.join(endpoint.prefix, "logs", "error.log")


def log_size(endpoint):
    try:
        return os.path.getsize(log_path(endpoint))
    except OSError:
        return 0


def log_since(endpoint, offset):
    try:
        with open(log_path(endpoint), "rb") as fh:
            fh.seek(offset)
            return fh.read().decode(errors="replace")
    except OSError:
        return ""


# -- lab lifecycle ----------------------------------------------------------


def _guard_lab_binary():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")


def _make_roots(base, roots, seed_roots, seed):
    dirs = {}
    for label in roots:
        path = base / label
        path.mkdir()
        path.chmod(0o777)
        dirs[label] = path
    for label in seed_roots:
        seed_tree(str(dirs[label]), {SRC_LFN: seed})
    return dirs


def _await_ports(name, harness, endpoint, ports):
    for key, port in ports.items():
        if not wait_port(port, timeout=30.0):
            tail = log_since(endpoint, 0)[-2000:]
            harness.close()
            pytest.fail(f"{name}: {key}={port} never came up\n{tail}")


def start_lab(tmp_path_factory, *, name, template, roots, seed_roots, seed,
              extra_ports, reason, extra_values=None):
    """Start one lab: one posix root per plane, the sources seeded with SRC_LFN.

    `extra_values` is merged into the template values after the roots, for a
    lab whose faces differ by something other than a port or a data root (the
    F9 SSS labs template one keytab path per face).

    Returns {harness, endpoint, ports, dirs}; the caller owns `harness.close()`.
    """
    _guard_lab_binary()
    dirs = _make_roots(tmp_path_factory.mktemp(name.replace("-", "_")), roots, seed_roots, seed)
    values = {"BIND_HOST": BIND_HOST, "HOST": HOST}
    values.update({f"{label.upper()}_DIR": str(path) for label, path in dirs.items()})
    values.update(extra_values or {})
    harness = LifecycleHarness()
    endpoint = harness.start(NginxInstanceSpec(
        name=name, template=template, protocol="root", readiness="tcp",
        data_root=str(dirs["src"]), template_values=values, reason=reason))
    ports = {"PORT": endpoint.port}
    ports.update({key: endpoint.extra_ports[key] for key in extra_ports})
    _await_ports(name, harness, endpoint, ports)
    return {"harness": harness, "endpoint": endpoint, "ports": ports, "dirs": dirs}
