"""W1 / phase-57 §F8 gate: the native TPC destination resolves an ASYNCHRONOUS
kXR_open from the source.

A real XRootD source (EOS/dCache, or any server still completing the TPC
rendezvous) does not always answer the destination's open synchronously — it may
reply:

  * kXR_wait     (4005) — "retry in N s": the dest must sleep and RESEND the open.
  * kXR_waitresp (4006) — "answer comes later, unsolicited": the dest must wait for
                          a deferred kXR_attn(kXR_asynresp) carrying the real reply.

Before §F8 the dest only accepted a synchronous kXR_ok and fast-failed on these.
tpc_open_resolve() (src/tpc/outbound/source.c) now honours both flows, bounded so a silent
source can never hang the pull thread.

This test drives a REAL native xrdcp `--tpc only` pull, with a real nginx-xrootd
DESTINATION pulling from a tiny in-process MOCK SOURCE that speaks just enough of
the root:// wire protocol to (a) accept the client's rendezvous open and (b) answer
the destination's pull open ASYNCHRONOUSLY, then serve the file bytes. The file
must arrive byte-exact at the destination — proving the dest walked the async open
handshake end to end.

    native xrdcp --tpc only
        ├── opens MOCK (src) with tpc.dst=…  → rendezvous (immediate ok)
        └── opens nginx DEST with tpc.src=…  → dest pulls:
                 dest --(handshake/login/open)--> MOCK
                 MOCK answers open with kXR_wait | kXR_waitresp→kXR_attn → kXR_ok
                 dest reads bytes → writes the destination file
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
XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")
DST = 21231

# root:// wire opcodes (XProtocol.hh)
kXR_close, kXR_protocol, kXR_login, kXR_open, kXR_read = 3003, 3006, 3007, 3010, 3013
# response status codes
kXR_ok, kXR_attn, kXR_wait, kXR_waitresp, kXR_asynresp = 0, 4001, 4005, 4006, 5008

PAYLOAD = b"phase-57 F8: async TPC open resolved end-to-end\n"


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _resp(streamid, status, body=b""):
    # ServerResponseHeader: streamid[2] status[2 BE] dlen[4 BE] + body
    return streamid + struct.pack(">Hi", status, len(body)) + body


class MockSource(threading.Thread):
    """Minimal threaded root:// source that answers the destination's pull open
    asynchronously (mode 'waitresp' or 'wait') and serves PAYLOAD."""

    def __init__(self, mode):
        super().__init__(daemon=True)
        self.mode = mode
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self._stop = False
        # records whether a pull open (tpc.org) was ever answered asynchronously
        self.async_open_served = threading.Event()

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

    def _serve_conn(self, conn):
        # 20-byte ClientInitHandShake → 8-byte protocol/flags reply.
        if _recv_exact(conn, 20) is None:
            return
        conn.sendall(_resp(b"\x00\x00", kXR_ok, struct.pack(">ii", 0x520, 1)))

        open_count = 0
        served_data = False
        while True:
            hdr = _recv_exact(conn, 24)            # ClientRequestHdr
            if hdr is None:
                return
            streamid = hdr[0:2]
            reqid = struct.unpack(">H", hdr[2:4])[0]
            dlen = struct.unpack(">i", hdr[20:24])[0]
            payload = _recv_exact(conn, dlen) if dlen > 0 else b""
            if payload is None:
                return

            if reqid == kXR_protocol:
                conn.sendall(_resp(streamid, kXR_ok, struct.pack(">ii", 0x520, 1)))
            elif reqid == kXR_login:
                # 16-byte session id, NO security token → anonymous (dest skips auth)
                conn.sendall(_resp(streamid, kXR_ok, b"\x00" * 16))
            elif reqid == kXR_open:
                is_pull = b"tpc.org" in payload    # dest pull vs client rendezvous
                if not is_pull:
                    conn.sendall(_resp(streamid, kXR_ok, b"\x00\x00\x00\x01"))
                    continue
                open_count += 1
                self._answer_pull_open(conn, streamid, open_count)
            elif reqid == kXR_read:
                if not served_data:
                    served_data = True
                    conn.sendall(_resp(streamid, kXR_ok, PAYLOAD))
                else:
                    conn.sendall(_resp(streamid, kXR_ok, b""))   # EOF
            elif reqid == kXR_close:
                conn.sendall(_resp(streamid, kXR_ok))
            else:
                conn.sendall(_resp(streamid, kXR_ok))            # lenient

    def _answer_pull_open(self, conn, streamid, open_count):
        """Answer the destination's pull open asynchronously, then mark served."""
        fhandle = b"\x00\x00\x00\x01"
        if self.mode == "wait":
            # First open → kXR_wait(1s); the dest must sleep + RESEND; 2nd → ok.
            if open_count == 1:
                conn.sendall(_resp(streamid, kXR_wait, struct.pack(">i", 1)))
                return
            conn.sendall(_resp(streamid, kXR_ok, fhandle))
        else:  # "waitresp" → deferred kXR_attn(asynresp) wrapping kXR_ok
            conn.sendall(_resp(streamid, kXR_waitresp, struct.pack(">i", 1)))
            time.sleep(0.2)
            embedded = streamid + struct.pack(">Hi", kXR_ok, len(fhandle)) + fhandle
            attn = struct.pack(">i", kXR_asynresp) + b"\x00\x00\x00\x00" + embedded
            conn.sendall(_resp(b"\x00\x00", kXR_attn, attn))
        self.async_open_served.set()


def _wait_listen(port, tries=80):
    for _ in range(tries):
        r = subprocess.run(["bash", "-c", f"ss -tln | grep -q ':{port} '"])
        if r.returncode == 0:
            return True
        time.sleep(0.1)
    return False


@pytest.fixture
def dest(tmp_path):
    if not (os.path.exists(NGINX) and os.path.exists(XRDCP)):
        pytest.skip("nginx / xrdcp not built")
    ddata = tmp_path / "dstdata"
    ddata.mkdir()
    # nginx master runs as root here, so the worker drops to the built-in
    # 'nobody' user; the checkpoint-recovery lock is written INTO the export, so
    # the export must be writable by that worker user (the fleet exports are 0777
    # for the same reason). Without this the worker fails the recovery lock with
    # EACCES and exits fatally, and the dest never comes up.
    ddata.chmod(0o777)
    cfg = tmp_path / "dst.conf"
    cfg.write_text(
        "daemon off;\nworker_processes 1;\n"
        f"error_log {tmp_path}/dst-err.log info;\npid {tmp_path}/dst.pid;\n"
        "thread_pool default threads=4 max_queue=65536;\n"
        "events { worker_connections 64; }\n"
        "stream {\n  server {\n"
        f"    listen 127.0.0.1:{DST};\n    brix_root on;\n"
        f"    brix_storage_backend posix:{ddata};\n    brix_auth none;\n"
        "    brix_allow_write on;\n"
        "    brix_tpc_allow_local on;\n    brix_tpc_allow_private on;\n"
        f"    brix_access_log {tmp_path}/dst-acc.log;\n  }}\n}}\n")
    subprocess.run(["bash", "-c", f"fuser -k {DST}/tcp 2>/dev/null"])
    proc = subprocess.Popen([NGINX, "-c", str(cfg), "-p", str(tmp_path)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not _wait_listen(DST):
        proc.terminate()
        pytest.skip("nginx dest did not come up")
    yield {"ddata": ddata, "base": tmp_path}
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.mark.parametrize("mode", ["waitresp", "wait"])
def test_async_open_resolved(dest, mode):
    """The dest pulls a file whose source answers the open asynchronously."""
    src = MockSource(mode)
    src.start()
    try:
        out = Path(dest["ddata"]) / f"pulled_{mode}.txt"
        r = subprocess.run(
            [XRDCP, "-f", "--tpc", "only",
             f"root://127.0.0.1:{src.port}//src.txt",
             f"root://127.0.0.1:{DST}//{out.name}"],
            capture_output=True, text=True, timeout=90)
        if r.returncode != 0 or not out.exists():
            errlog = Path(dest["base"]) / "dst-err.log"
            tail = ""
            if errlog.exists():
                tail = "\n".join(errlog.read_text(errors="replace").splitlines()[-20:])
            pytest.fail(
                f"async-{mode} TPC pull failed rc={r.returncode}: {r.stderr.strip()}"
                f"\n--- dst err ---\n{tail}")
        assert out.read_bytes() == PAYLOAD
        assert src.async_open_served.is_set(), "mock never served the async open"
    finally:
        src.stop()
