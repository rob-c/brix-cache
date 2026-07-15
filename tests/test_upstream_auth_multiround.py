"""phase-57 §F4/W1.4.a gate: the upstream cache-fill bootstrap survives a
MULTI-ROUND kXR_authmore exchange (bounded by XRD_OBA_MAX_ROUNDS).

Before this change `src/net/upstream/bootstrap.c` aborted on the *second* kXR_authmore
("repeated kXR_authmore (not supported)"), so an origin whose sec layer needs more
than one round could never be a read-through cache-fill / redirector source. The
handling is now a single bounded helper (brix_upstream_continue_auth) shared by
the LOGIN and AUTH phases.

Self-contained: a tiny Python stub origin issues TWO kXR_authmore rounds (reading
the forwarded ztn credential each time) before accepting and answering the client's
locate with a redirect; a dedicated nginx redirector forwards to it. The client's
locate must come back as kXR_redirect — proving nginx completed both auth rounds.
"""
import os
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NGINX = "/tmp/nginx-1.28.3/objs/nginx"
HOST = "127.0.0.1"
NGINX_PORT = 21240

kXR_ok, kXR_redirect, kXR_authmore = 0, 4004, 4002
kXR_protocol, kXR_login, kXR_auth, kXR_locate = 3006, 3007, 3000, 3027

AUTH_ROUNDS = 2          # number of kXR_authmore challenges the origin issues


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _hdr(sid, status, dlen):
    return struct.pack(">2sHI", sid, status, dlen)


class StubOrigin(threading.Thread):
    """root:// origin that demands AUTH_ROUNDS kXR_authmore rounds then redirects."""

    def __init__(self):
        super().__init__(daemon=True)
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((HOST, 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self.creds = []                  # ztn payloads received, one per round
        self._stop = False

    def run(self):
        while not self._stop:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def stop(self):
        self._stop = True
        try:
            self.srv.close()
        except OSError:
            pass

    def _serve(self, conn):
        try:
            self._serve_conn(conn)
        except (OSError, struct.error):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _read_req(self, conn):
        hdr = _recv_exact(conn, 24)
        if hdr is None:
            return None, None
        dlen = struct.unpack(">I", hdr[20:24])[0]
        payload = _recv_exact(conn, dlen) if dlen else b""
        return hdr, payload

    def _serve_conn(self, conn):
        # handshake (20) → 16-byte reply
        if _recv_exact(conn, 20) is None:
            return
        conn.sendall(_hdr(b"\x00\x00", kXR_ok, 8) + struct.pack(">II", 0x520, 1))
        # protocol
        hdr, _ = self._read_req(conn)
        if hdr is None:
            return
        sid = hdr[:2]
        conn.sendall(_hdr(sid, kXR_ok, 8) + struct.pack(">II", 0x520, 1))
        # login → first authmore
        hdr, _ = self._read_req(conn)
        if hdr is None:
            return
        sid = hdr[:2]
        conn.sendall(_hdr(sid, kXR_authmore, len(b"&P=ztn,test")) + b"&P=ztn,test")
        # AUTH_ROUNDS kXR_auth → authmore (until the last) → ok
        for rnd in range(AUTH_ROUNDS):
            hdr, cred = self._read_req(conn)
            if hdr is None:
                return
            sid = hdr[:2]
            self.creds.append(cred)
            if rnd < AUTH_ROUNDS - 1:
                conn.sendall(_hdr(sid, kXR_authmore, len(b"&P=ztn,more"))
                             + b"&P=ztn,more")
            else:
                conn.sendall(_hdr(sid, kXR_ok, 16) + b"\x01" * 16)   # session id
        # client's locate → redirect
        hdr, _ = self._read_req(conn)
        if hdr is None:
            return
        sid = hdr[:2]
        body = struct.pack(">I", 1094) + b"storage.example.org"
        conn.sendall(_hdr(sid, kXR_redirect, len(body)) + body)


def _wait_listen(port, tries=80):
    for _ in range(tries):
        if subprocess.run(["bash", "-c",
                           f"ss -tln | grep -q ':{port} '"]).returncode == 0:
            return True
        time.sleep(0.1)
    return False


def _client_handshake_login(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect((HOST, port))
    s.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    s.sendall(struct.pack(">BB H I BB 10x I",
                          0, 1, kXR_protocol, 0x00000520, 0x02, 0x03, 0))
    _recv_exact(s, 16)               # handshake reply
    _read_response(s)                # kXR_protocol reply
    s.sendall(struct.pack(">BB H I 8s BB B B I",
                          0, 1, kXR_login, 0, b"test\x00\x00\x00\x00", 0, 0, 5, 0, 0))
    _read_response(s)                # kXR_login reply
    return s


def _read_response(sock):
    hdr = _recv_exact(sock, 8)
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen = struct.unpack(">I", hdr[4:8])[0]
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _send_locate(sock, path):
    payload = path.encode() + b"\x00"
    sock.sendall(struct.pack(">BB H H 14x I", 0, 1, kXR_locate, 0, len(payload))
                 + payload)


@pytest.fixture
def redirector(tmp_path):
    if not os.path.exists(NGINX):
        pytest.skip("nginx not built")
    origin = StubOrigin()
    origin.start()
    token = tmp_path / "upstream.jwt"
    token.write_text("eyJhbGciOiJSUzI1NiJ9.multiround.sig\n")
    data = tmp_path / "data"
    data.mkdir()
    # nginx master runs as root here, so the worker drops to the built-in
    # 'nobody' user; the checkpoint-recovery lock is written INTO the export, so
    # the export must be writable by that worker (the fleet exports are 0777 for
    # the same reason). Without this the worker fails the lock with EACCES and
    # exits fatally — the master still holds the listen socket (so _wait_listen
    # passes) but no worker answers, and the client handshake times out.
    data.chmod(0o777)
    cfg = tmp_path / "redir.conf"
    cfg.write_text(
        "daemon off;\nworker_processes 1;\n"
        f"error_log {tmp_path}/err.log info;\npid {tmp_path}/nginx.pid;\n"
        "events { worker_connections 64; }\n"
        "stream {\n  server {\n"
        f"    listen {HOST}:{NGINX_PORT};\n    brix_root on;\n"
        f"    brix_storage_backend posix:{data};\n"
        f"    brix_upstream {HOST}:{origin.port};\n"
        f"    brix_upstream_token_file {token};\n  }}\n}}\n")
    subprocess.run(["bash", "-c", f"fuser -k {NGINX_PORT}/tcp 2>/dev/null"])
    proc = subprocess.Popen([NGINX, "-c", str(cfg), "-p", str(tmp_path)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not _wait_listen(NGINX_PORT):
        proc.terminate()
        origin.stop()
        pytest.skip("redirector nginx did not come up")
    yield {"origin": origin, "base": tmp_path}
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    origin.stop()


def test_upstream_multiround_authmore(redirector):
    """nginx completes a 2-round kXR_authmore exchange and forwards the redirect."""
    s = _client_handshake_login(NGINX_PORT)
    _send_locate(s, "/data/file.root")
    status, body = _read_response(s)
    s.close()

    origin = redirector["origin"]
    if status != kXR_redirect:
        tail = ""
        errlog = Path(redirector["base"]) / "err.log"
        if errlog.exists():
            tail = "\n".join(errlog.read_text(errors="replace").splitlines()[-15:])
        pytest.fail(f"expected kXR_redirect after {AUTH_ROUNDS}-round auth, got "
                    f"{status}; origin saw {len(origin.creds)} cred(s)\n{tail}")
    assert struct.unpack(">I", body[:4])[0] == 1094
    assert body[4:].decode() == "storage.example.org"
    # Both rounds must have forwarded the ztn token (proves the loop, not a 1-shot).
    assert len(origin.creds) == AUTH_ROUNDS, \
        f"origin received {len(origin.creds)} creds, expected {AUTH_ROUNDS}"
    for cred in origin.creds:
        assert cred.startswith(b"ztn\x00"), f"bad credtype: {cred[:8]!r}"
