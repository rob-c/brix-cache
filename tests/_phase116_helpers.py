"""
_phase116_helpers.py — shared fixtures for the phase-116 runtime-DNS suites.

WHAT: A slot-based `nginx -t` probe over the audit-16n parse scaffold, a
      minimal root:// wire client (handshake, login, stat, open), a recording
      TCP sink that stands in for a CMS manager or an upstream, /metrics and
      dashboard readers, and `DnsLab` — the stub nameserver + resolv.conf +
      template values bundle every live suite starts from.
WHY:  Six suites drive the same three lifecycle specs; one helper keeps the
      wire framing and the template contract in one place instead of six.
HOW:  Pure stdlib over the suite's own helpers: config_parse.nginx_t renders
      the scaffold (never bound) and execs the frozen per-session binary; the
      kXR framing is the same as tests/test_acc_residual.py (handshake 20
      bytes, login with a 4-byte "anon" user, 8-byte response header); the
      sink records accept timestamps so a test can prove *which* listener a
      dial reached after a record swap.
"""
from __future__ import annotations

import json
import os
import socket
import struct
import threading
import time
import urllib.request
from pathlib import Path

from settings import HOST, BIND_HOST, NGINX_BIN
from config_parse import nginx_t as _scaffold_nginx_t
from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT
from dns_stub import DnsStub, write_resolv_conf, metric, metric_family
from ephemeral_port import free_port

kXR_login = 3007
kXR_open = 3010
kXR_stat = 3017
kXR_ok = 0
kXR_error = 4003
kXR_redirect = 4004
kXR_wait = 4005

HAVE_NGINX = os.access(NGINX_BIN, os.X_OK)


# ---- nginx -t ----------------------------------------------------------------

SCAFFOLD = "nginx_audit16nparse.conf"
SLOTS = ("LOC_KNOBS", "SRV_KNOBS", "HTTP_KNOBS", "OUTER",
         "STREAM_KNOBS", "STREAM_MAIN", "EXTRA_LOC")


def parse(tmp_path: Path, **placed: str):
    """`nginx -t` over the audit-16n scaffold with directive lines placed in
    the named slots (STREAM_MAIN, STREAM_KNOBS, HTTP_KNOBS, OUTER, ...).
    Multi-line bodies are fine.  Returns (rc, combined_output)."""
    (tmp_path / "logs").mkdir(exist_ok=True)
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    values = {slot: "" for slot in SLOTS}
    for slot, body in placed.items():
        assert slot in SLOTS, slot
        values[slot] = "".join(f"        {line.strip()}\n"
                               for line in body.strip().splitlines())
    r = _scaffold_nginx_t(SCAFFOLD, tmp_path,
                          PORT=SHARED_PARSE_PLACEHOLDER_PORT,
                          STREAM_PORT=SHARED_PARSE_PLACEHOLDER_PORT,
                          LOG_DIR=str(tmp_path / "logs"), DATA=str(data),
                          **values)
    return r.returncode, r.stdout + r.stderr


# ---- root:// wire --------------------------------------------------------------

def recv_exact(s: socket.socket, n: int) -> bytes:
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError("connection closed mid-response")
        b += c
    return b


def read_resp(s: socket.socket):
    _sid, status, dlen = struct.unpack("!2sHI", recv_exact(s, 8))
    return status, (recv_exact(s, dlen) if dlen else b"")


def login(port: int, host: str = HOST, timeout: float = 8.0,
          source: str | None = None) -> socket.socket:
    """Handshake + anonymous login; `source` binds the client's loopback
    address so a server can reverse-resolve a chosen peer IP."""
    s = socket.create_connection((host, port), timeout=timeout,
                                 source_address=(source, 0) if source else None)
    s.settimeout(timeout)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    recv_exact(s, 16)
    s.sendall(struct.pack("!2sHI8sBBBBI", b"\x00\x02", kXR_login, 0x1234,
                          b"anon\x00\x00\x00\x00", 0, 0, 5, 0, 0))
    st, _ = read_resp(s)
    assert st == kXR_ok, f"login failed: {st}"
    return s


def stat(port: int, path: str, **kw) -> int:
    s = login(port, **kw)
    p = path.encode()
    s.sendall(struct.pack("!2sH16sI", b"\x00\x03", kXR_stat, b"\x00" * 16, len(p)) + p)
    st, _ = read_resp(s)
    s.close()
    return st


def open_ro(port: int, path: str, timeout: float = 8.0, **kw):
    """kXR_open read-only; returns (outcome, body, seconds_waited) where the
    outcome is the kXR status, "closed" (server dropped the session) or
    "timeout" — so a hang is distinct from a refusal."""
    s = login(port, timeout=timeout, **kw)
    p = path.encode()
    req = struct.pack("!2sHHHH6s4sI", b"\x00\x03", kXR_open, 0o644, 0, 0,
                      b"\x00" * 6, b"\x00" * 4, len(p)) + p
    t0 = time.monotonic()
    s.sendall(req)
    try:
        st, body = read_resp(s)
    except socket.timeout:
        st, body = "timeout", b""
    except (EOFError, ConnectionError):
        st, body = "closed", b""
    s.close()
    return st, body, time.monotonic() - t0


# ---- recording sink -----------------------------------------------------------

class TcpSink:
    """A loopback listener that accepts, holds and timestamps every dial."""

    def __init__(self, host: str, port: int | None = None):
        self.host, self.port = host, port
        self.fixed_port = port is not None
        self.accepts: list[tuple[float, str]] = []
        self._conns: list[socket.socket] = []
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = False

    def _bind(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(16)
        self._sock.settimeout(0.2)

    def _bind_once(self, last: bool) -> bool:
        """Bind on the current port; False when it was taken from under us and
        another pick is allowed.  A caller-pinned port, or the last attempt,
        raises: there the collision is the finding, not a race to ride out."""
        try:
            self._bind()
            return True
        except OSError:
            if self._sock is not None:
                self._sock.close()
                self._sock = None
            if self.fixed_port or last:
                raise
            self.port = None
            return False

    def start(self, attempts: int = 5) -> "TcpSink":
        """Bind and serve.  free_port() only proves a port was free a moment
        ago, so an unpinned sink re-picks and retries rather than reddening the
        suite on a lost race."""
        for attempt in range(attempts):
            if self.port is None:
                self.port = free_port(self.host)
            if self._bind_once(last=attempt == attempts - 1):
                break
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def _loop(self):
        while not self._stop:
            try:
                c, peer = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            c.setblocking(False)
            self._conns.append(c)
            self.accepts.append((time.monotonic(), peer[0]))

    def wait_for_dial(self, count: int = 1, timeout: float = 20.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if len(self.accepts) >= count:
                return True
            time.sleep(0.05)
        return len(self.accepts) >= count

    def drop_connections(self):
        """Close every held connection so the peer reconnects."""
        for c in self._conns:
            try:
                c.close()
            except OSError:
                pass
        self._conns = []

    def stop(self):
        self._stop = True
        if self._thread:
            self._thread.join(timeout=1)
        self.drop_connections()
        if self._sock:
            self._sock.close()
            self._sock = None


# ---- observation -------------------------------------------------------------

def fetch(url: str, timeout: float = 5.0) -> str:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read().decode()


def metrics_text(http_port: int) -> str:
    return fetch(f"http://{HOST}:{http_port}/metrics")


def dns_panel(http_port: int) -> dict:
    snap = json.loads(fetch(f"http://{HOST}:{http_port}/brix/api/v1/snapshot"))
    return snap["dns"]


def dns_target(http_port: int, host: str) -> dict | None:
    for row in dns_panel(http_port)["targets"]:
        if row["host"] == host:
            return row
    return None


def wait_until(pred, timeout: float = 15.0, step: float = 0.1):
    """Poll `pred` until truthy; returns its last value."""
    deadline = time.monotonic() + timeout
    value = pred()
    while not value and time.monotonic() < deadline:
        time.sleep(step)
        value = pred()
    return value


def wait_for_state(http_port: int, host: str, state: str, timeout: float = 20.0):
    return wait_until(lambda: (lambda t: t if t and t["state"] == state else None)
                      (dns_target(http_port, host)), timeout)


def read_log(prefix: str) -> str:
    try:
        return Path(prefix, "logs", "error.log").read_text()
    except FileNotFoundError:
        return ""


# ---- the lab -------------------------------------------------------------------

class DnsLab:
    """Stub nameserver + resolv.conf + the template values a spec needs."""

    def __init__(self, tmp_path: Path, *, search=(), ndots: int = 1,
                 timeout: int = 1, attempts: int = 1):
        self.stub = DnsStub(host="127.0.0.1").start()  # net-literal-allow: the stub resolver binds loopback on a leased port
        self.resolv_conf = write_resolv_conf(
            tmp_path / "resolv.conf", [(self.stub.host, self.stub.port)],
            search=search, ndots=ndots, timeout=timeout, attempts=attempts)

    def values(self, *, resolver_extra: str = "", retry: str = "200ms 1s",
               **more) -> dict:
        v = {"BIND_HOST": BIND_HOST, "RESOLV_CONF": str(self.resolv_conf),
             "RESOLVER_EXTRA": resolver_extra, "RETRY": retry,
             "STREAM_EXTRA": "", "HTTP_EXTRA": ""}
        v.update(more)
        return v

    def close(self):
        self.stub.stop()


__all__ = ["HAVE_NGINX", "HOST", "BIND_HOST", "NGINX_BIN", "parse",
           "login", "stat", "open_ro", "read_resp",
           "TcpSink", "fetch", "metrics_text", "dns_panel", "dns_target",
           "wait_until", "wait_for_state", "read_log", "DnsLab", "metric",
           "metric_family", "kXR_ok", "kXR_error", "kXR_redirect", "kXR_wait"]
