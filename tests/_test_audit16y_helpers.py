"""A kXR_gotoTLS upstream whose certificate the test chooses.

`test_upstream_tls_verify.py` proved the outbound redirector leg's peer
verification by reading the C, and said why: "the rejection is enforced inside
OpenSSL's handshake — neither is drivable as a live negative from this suite."
It is drivable; it needs an upstream that speaks the four bootstrap frames and
then presents whatever certificate the cell is about.  The fleet's own
`upstream_protocol_stubs.py` stops one frame short — its gotorls handler sends
the kXR_gotoTLS flag and closes, so nothing in the corpus has ever watched the
leg finish a TLS handshake, let alone fail one.

The wire is the same in both directions and worth stating once:
`brix_upstream_build_bootstrap` (net/upstream/bootstrap.c) pre-sends handshake,
kXR_protocol and kXR_login in ONE write, so a stub that reads only the first two
leaves the pre-sent cleartext login in the socket buffer and TLS then reads that
login as the ClientHello.  Draining it is not tidiness; it is what the real
server does ("the server discards the plaintext login that was pre-sent").
"""

import json
import os
import socket
import ssl
import struct
import subprocess
import threading
import time

kXR_ok = 0
kXR_login = 3007
kXR_redirect = 4004
kXR_gotoTLS = 0x40000000

#: Where a satisfied leg is sent once it has authenticated the peer.  Kept
#: identical to upstream_protocol_stubs.py so a redirect that arrives at a
#: client is recognisably the stub's and not a server-synthesised one.
REDIRECT_HOST = "stub.example.org"
REDIRECT_PORT = 1194

#: Every path through a stub connection ends in exactly one of these.
TERMINAL = frozenset({"redirected", "tls-refused", "no-relogin", "error"})


def mint_cert(tmp_path, stem, common_name, san):
    """Self-signed, CA-flagged cert + key: it is both what a stub presents and,
    where a plane is meant to trust it, the CA file that plane is given."""
    cert = tmp_path / f"{stem}.pem"
    key = tmp_path / f"{stem}.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "2",
         "-subj", f"/CN={common_name}",
         "-addext", f"subjectAltName={san}"],
        check=True, capture_output=True)
    return str(cert), str(key)


def _recv_exact(sock, count):
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ConnectionResetError(f"closed with {len(buf)}/{count} bytes")
        buf += chunk
    return buf


def _frame(streamid, status, body=b""):
    return struct.pack(">2sHI", streamid, status, len(body)) + body


class GotoTlsUpstream:
    """One listener that answers the bootstrap, demands TLS, presents `cert`,
    and records every step so a test can say where a leg stopped.

    Records are plain dicts on `.events`; `.kinds(port)` is the ordered list of
    step names, which is what nearly every assertion actually wants.
    """

    def __init__(self, host, port, cert, key):
        self.host = host
        self.port = port
        self.events = []
        self._lock = threading.Lock()
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(cert, key)
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(8)
        self._closed = False
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    # -- recording ---------------------------------------------------------- #
    def _record(self, kind, detail=""):
        with self._lock:
            self.events.append({"kind": kind, "detail": str(detail)[:160]})

    def kinds(self):
        with self._lock:
            return [event["kind"] for event in self.events]

    def details(self, kind):
        with self._lock:
            return [e["detail"] for e in self.events if e["kind"] == kind]

    def reset(self):
        with self._lock:
            self.events = []

    def wait_for_terminal(self, timeout=8.0):
        """Block until this stub has finished with a connection, and return the
        step names in order.

        A test samples the stub the moment the CLIENT has its answer, which is
        earlier than the stub's own last write — an aborted leg learns it failed
        from OpenSSL while the stub is still inside `wrap_socket`.  Every path
        through `_serve` ends in one of TERMINAL, so waiting for one of those is
        waiting for the stub's view to be complete rather than for a duration.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            kinds = self.kinds()
            if TERMINAL.intersection(kinds):
                return kinds
            time.sleep(0.02)
        return self.kinds()

    def settle(self, seconds=0.3):
        """Give a leg that should never have been dialled the chance to prove
        otherwise; returns whatever was recorded in that window."""
        time.sleep(seconds)
        return self.kinds()

    # -- the wire ----------------------------------------------------------- #
    def _accept_loop(self):
        while not self._closed:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            conn.settimeout(15)
            threading.Thread(target=self._serve, args=(conn,),
                             daemon=True).start()

    def _serve(self, conn):
        try:
            self._bootstrap(conn)
        except Exception as exc:                      # noqa: BLE001 — recorded
            self._record("error", repr(exc))
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _bootstrap(self, conn):
        _recv_exact(conn, 20)
        self._record("handshake")
        conn.sendall(_frame(b"\x00\x00", kXR_ok, struct.pack(">II", 0x520, 1)))

        header = _recv_exact(conn, 24)
        streamid = header[:2]
        self._drain_body(conn, header)
        self._record("protocol")

        # The leg pre-sent its cleartext login in the same write; the real
        # server discards it, and TLS cannot start until it is off the socket.
        login = _recv_exact(conn, 24)
        self._drain_body(conn, login)
        self._record("cleartext-login", struct.unpack(">H", login[2:4])[0])

        conn.sendall(_frame(streamid, kXR_ok,
                            struct.pack(">II", 0x520, kXR_gotoTLS)))
        try:
            tls = self._ctx.wrap_socket(conn, server_side=True)
        except OSError as exc:
            self._record("tls-refused", repr(exc))
            return
        self._record("tls-established", tls.version())
        self._after_tls(tls)

    def _after_tls(self, tls):
        try:
            relogin = _recv_exact(tls, 24)
        except (OSError, ConnectionResetError) as exc:
            self._record("no-relogin", repr(exc))
            return
        self._drain_body(tls, relogin)
        self._record("tls-login", struct.unpack(">H", relogin[2:4])[0])
        tls.sendall(_frame(relogin[:2], kXR_ok, b"\x01" * 16))

        forwarded = _recv_exact(tls, 24)
        self._drain_body(tls, forwarded)
        self._record("forwarded-request", struct.unpack(">H", forwarded[2:4])[0])
        body = struct.pack(">I", REDIRECT_PORT) + REDIRECT_HOST.encode()
        tls.sendall(_frame(forwarded[:2], kXR_redirect, body))
        self._record("redirected")

    @staticmethod
    def _drain_body(sock, header):
        dlen = struct.unpack(">I", header[20:24])[0]
        if dlen:
            _recv_exact(sock, dlen)

    # -- lifecycle ---------------------------------------------------------- #
    def close(self):
        self._closed = True
        try:
            self._sock.close()
        except OSError:
            pass


def dump_events(path, stubs):
    """Best-effort artefact for a failing run: what each stub saw, in order."""
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({name: stub.events for name, stub in stubs.items()}, handle,
                  indent=2)
    return os.path.abspath(path)
