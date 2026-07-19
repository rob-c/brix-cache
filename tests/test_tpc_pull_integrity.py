"""
Native TPC pull-leg end-to-end integrity — brix_tpc_verify_checksum + the
always-on source-size completion gate (fault-hardening finding #13).

THE GAP: the native XRootD third-party-copy PULL (the destination opens a remote
source and streams it into local storage) had ZERO end-to-end verification.  Its
only in-band "the whole file arrived" signal is a zero-byte kXR_read reply — a
frame a truncating middlebox (or a source that dies mid-stream) can forge — and
the destination captured no source size and computed no checksum.  So a
STOPPED/TRUNCATED pull committed as COMPLETE, and a byte flipped on the
source->destination hop was written verbatim and committed as good.

THE FIX (two layers):
  * ALWAYS-ON source-size gate — before the pull, kXR_stat the source for its
    authoritative size; after the stream loop's forged/natural EOF, refuse the
    copy unless bytes_written == that size.  A mismatch is unambiguous truncation
    and fails closed on every server (no knob).  brix_tpc_require_source_size
    additionally refuses a source that will not declare a size at all.
  * OPT-IN post-copy checksum — brix_tpc_verify_checksum on: after a size-verified
    pull, kXR_query(kXR_Qcksum) the source and recompute the same algorithm
    (adler32, xrdcp's default) over the written destination; a mismatch fails the
    copy closed.  This is what catches a LENGTH-PRESERVING in-flight bit flip that
    the size gate cannot see.  Off by default (a plain pull carries no checksum,
    matching stock behaviour).

TOPOLOGY (one nginx, two brix_root planes — nginx_tpc_harden.conf; each plane is
both a TPC destination and its own source):

    xrdcp --tpc only  root://PROXY//src  ->  root://DEST//dst
                              |                    |
                       kXR-response-aware     :{PORT}      verify_checksum on
                       fault proxy on the     :{PORT_OFF}  verify_checksum off
                       DEST's pull leg

The proxy frames the source->destination response stream uniformly (every reply,
including the handshake, is an 8-byte ServerResponseHdr + dlen body) and touches
ONLY read replies (the streamid[1]==3 tag our pull sets on kXR_read) — so the
kXR_stat (tag 4) and kXR_Qcksum (tag 5) replies always pass through truthfully.
It offers two deterministic, non-flaky faults (the surgical analogue of
brix-fault-proxy `truncate-at` / `corrupt down`):
  * truncate — shrink the first data frame and forge EOF on the next read, so the
    destination cleanly stops short: a valid frame sequence, fewer bytes than stat.
  * flip     — flip one byte of the first data frame, length preserved.

CONTRACT:
  * clean link,   knob ON            -> copy succeeds, destination byte-exact  [no FP]
  * truncated,    knob ON            -> size gate fails the copy, no poison     [catch]
  * one byte flip, knob ON            -> checksum gate fails the copy, no poison [catch]
  * one byte flip, knob OFF           -> copy "succeeds", corrupt file committed  [gap]

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_tpc_pull_integrity.py -v -p no:xdist
"""

import os
import shutil
import socket
import struct
import subprocess
import threading
import time

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN, XRDCP_BIN, url_host
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.serial, pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness]

# kXR response status codes and the streamid[1] tag src/tpc/outbound sets on
# kXR_read (open/close=2, read=3, stat=4, query=5).  We fault only read replies.
kXR_ok = 0
kXR_oksofar = 4000
READ_TAG = 3


def _free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _port_up(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def _recv_exact(sock, n):
    """Read exactly n bytes (looping over short recv), or fewer only on EOF."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


class _KxrPullFaultProxy:
    """A TCP splice between the brix TPC destination and its source that frames the
    source->destination response stream (uniform 8-byte ServerResponseHdr + dlen
    body) and, while armed, faults ONLY read replies (streamid[1]==3) — leaving the
    handshake, login, open, stat (tag 4) and checksum-query (tag 5) replies
    untouched so the size and source-checksum the destination reads are truthful.

    Modes (one-shot, consumed by the first data-bearing read reply):
      * "flip"     — flip one body byte, length preserved (a wire bit flip the
                     size gate cannot see; the opt-in checksum must).
      * "truncate" — shrink the first data frame to half and force EOF (dlen=0) on
                     every subsequent read reply, so the destination stops short of
                     the stat'd size with a valid frame sequence.
    """

    def __init__(self, target_host, target_port):
        self.target_host = target_host
        self.target_port = target_port
        self.listen = _free_port()
        self._lock = threading.Lock()
        self._mode = None
        self._read_replies = 0
        self._srv = None
        self._stop = threading.Event()

    def arm(self, mode):
        assert mode in ("flip", "truncate")
        with self._lock:
            self._mode = mode
            self._read_replies = 0

    def disarm(self):
        with self._lock:
            self._mode = None
            self._read_replies = 0

    def _fault_read_frame(self, status, body):
        """Return the (possibly rewritten) (status, body) for a streamid[1]==3
        reply, mutating the armed state.  Non-data frames (dlen==0, or a status
        that is neither kXR_ok nor kXR_oksofar) pass through unchanged."""
        with self._lock:
            mode = self._mode
            if mode is None or status not in (kXR_ok, kXR_oksofar) or not body:
                return status, body
            self._read_replies += 1
            n = self._read_replies
            if mode == "flip":
                # First data frame only; consume the arm so later frames are clean.
                self._mode = None
                b = bytearray(body)
                b[0] ^= 0x01
                return status, bytes(b)
            # truncate: first data frame -> half; thereafter -> forged EOF.
            if n == 1:
                keep = max(1, len(body) // 2)
                return status, body[:keep]
            return kXR_ok, b""

    def _pump_up(self, src, dst):
        """destination->source: requests, forwarded raw."""
        try:
            while not self._stop.is_set():
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _pump_down(self, src, dst):
        """source->destination: parse each ServerResponseHdr frame, fault read
        replies, re-emit.  A partial header/body only occurs when the source dies
        mid-frame — forward what arrived and stop (the destination then sees a
        short read, its own recv-failure path)."""
        try:
            while not self._stop.is_set():
                hdr = _recv_exact(src, 8)
                if len(hdr) < 8:
                    if hdr:
                        dst.sendall(hdr)
                    break
                streamid = hdr[:2]
                status = struct.unpack("!H", hdr[2:4])[0]
                dlen = struct.unpack("!I", hdr[4:8])[0]
                body = _recv_exact(src, dlen) if dlen else b""
                if len(body) < dlen:
                    dst.sendall(hdr + body)
                    break

                if streamid[1] == READ_TAG:
                    status, body = self._fault_read_frame(status, body)
                    hdr = streamid + struct.pack("!HI", status, len(body))

                dst.sendall(hdr + body)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _handle(self, client):
        try:
            upstream = socket.create_connection(
                (self.target_host, self.target_port), timeout=5)
        except OSError:
            client.close()
            return
        tu = threading.Thread(target=self._pump_up, args=(client, upstream),
                              daemon=True)
        td = threading.Thread(target=self._pump_down, args=(upstream, client),
                              daemon=True)
        tu.start(); td.start()
        tu.join(); td.join()
        client.close(); upstream.close()

    def _serve(self):
        while not self._stop.is_set():
            try:
                client, _ = self._srv.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client,),
                             daemon=True).start()

    def start(self):
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((BIND_HOST, self.listen))
        self._srv.listen(16)
        threading.Thread(target=self._serve, daemon=True).start()

    def stop(self):
        self._stop.set()
        try:
            self._srv.close()
        except OSError:
            pass


def _anon_env():
    env = os.environ.copy()
    for key in ("X509_CERT_DIR", "X509_USER_PROXY", "X509_USER_CERT",
                "X509_USER_KEY", "XrdSecPROTOCOL", "XRD_SECPROTOCOL"):
        env.pop(key, None)
    return env


def _xrdcp_tpc(src, dst):
    return subprocess.run(
        [XRDCP_BIN, "-f", "-s", "--tpc", "only", src, dst],
        env=_anon_env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=60,
    )


def _name(prefix):
    return f"{prefix}_{os.getpid()}_{time.monotonic_ns()}.dat"


@pytest.fixture(scope="module")
def node(tmp_path_factory):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")
    if shutil.which(XRDCP_BIN) is None and not os.path.isabs(XRDCP_BIN):
        pytest.skip("xrdcp not found")

    on_root = tmp_path_factory.mktemp("on_root")
    off_root = tmp_path_factory.mktemp("off_root")
    port_off = _free_port()

    harness = LifecycleHarness()
    endpoint = harness.start(NginxInstanceSpec(
        name="tpc-harden",
        template="nginx_tpc_harden.conf",
        protocol="root",
        readiness="tcp",
        extra_ports={"PORT_OFF": port_off},
        template_values={"BIND_HOST": BIND_HOST,
                         "ON_ROOT": str(on_root),
                         "OFF_ROOT": str(off_root)},
    ))
    port_on = endpoint.port

    proxy_on = _KxrPullFaultProxy(HOST, port_on)
    proxy_off = _KxrPullFaultProxy(HOST, port_off)
    proxy_on.start()
    proxy_off.start()

    ok = False
    for _ in range(60):
        if (_port_up(HOST, port_on) and _port_up(HOST, port_off)
                and _port_up(HOST, proxy_on.listen)
                and _port_up(HOST, proxy_off.listen)):
            ok = True
            break
        time.sleep(0.1)
    if not ok:
        proxy_on.stop(); proxy_off.stop(); harness.close()
        pytest.fail("tpc-harden planes / fault proxies did not come up")

    yield {"host": url_host(HOST),
           "port_on": port_on, "port_off": port_off,
           "on_root": on_root, "off_root": off_root,
           "proxy_on": proxy_on, "proxy_off": proxy_off}

    proxy_on.stop()
    proxy_off.stop()
    harness.close()


def _seed(root, name, content):
    p = root / name
    p.write_bytes(content)
    return p


# --- tests --------------------------------------------------------------------

def test_clean_pull_is_byte_exact(node):
    """SUCCESS / no false positive: knob ON over a CLEAN link.  The kXR_stat size
    matches the bytes delivered and the source adler32 matches the destination, so
    the copy succeeds and the file is byte-exact.  (A broken stat parse, checksum
    query, or adler32 recompute would fail even this clean pull.)"""
    node["proxy_on"].disarm()
    content = os.urandom(8000)
    src_name = _name("tpc_clean_src")
    dst_name = _name("tpc_clean_dst")
    _seed(node["on_root"], src_name, content)

    src = f"root://{node['host']}:{node['proxy_on'].listen}//{src_name}"
    dst = f"root://{node['host']}:{node['port_on']}//{dst_name}"
    r = _xrdcp_tpc(src, dst)

    assert r.returncode == 0, r.stderr.decode(errors="replace")
    assert (node["on_root"] / dst_name).read_bytes() == content


def test_truncated_pull_refused_no_poison(node):
    """ERROR / the always-on size gate: the proxy delivers half the first frame
    then forges EOF, so the destination stops short with a VALID frame sequence.
    bytes_written != the kXR_stat'd size -> the copy fails closed and the partial
    destination is unlinked (no complete-looking poison)."""
    proxy = node["proxy_on"]
    content = os.urandom(8000)
    src_name = _name("tpc_trunc_src")
    dst_name = _name("tpc_trunc_dst")
    _seed(node["on_root"], src_name, content)

    src = f"root://{node['host']}:{proxy.listen}//{src_name}"
    dst = f"root://{node['host']}:{node['port_on']}//{dst_name}"
    proxy.arm("truncate")
    try:
        r = _xrdcp_tpc(src, dst)
    finally:
        proxy.disarm()

    assert r.returncode != 0, "a truncated pull must fail, not commit as complete"
    dst_path = node["on_root"] / dst_name
    if dst_path.exists():
        assert dst_path.read_bytes() != content, \
            "the size gate must never leave a complete-looking file for a short pull"


def test_knob_on_corruption_refused_no_poison(node):
    """SECURITY-NEG / the opt-in checksum gate: knob ON, one body byte flipped in
    flight (length preserved, so the size gate passes).  The post-copy adler32 of
    the destination disagrees with the source's kXR_Qcksum and the copy fails
    closed — the corrupt file is never committed."""
    proxy = node["proxy_on"]
    content = os.urandom(8000)
    src_name = _name("tpc_flip_on_src")
    dst_name = _name("tpc_flip_on_dst")
    _seed(node["on_root"], src_name, content)

    src = f"root://{node['host']}:{proxy.listen}//{src_name}"
    dst = f"root://{node['host']}:{node['port_on']}//{dst_name}"
    proxy.arm("flip")
    try:
        r = _xrdcp_tpc(src, dst)
    finally:
        proxy.disarm()

    assert r.returncode != 0, \
        "a body-corrupted pull must fail the checksum gate, not commit as complete"
    dst_path = node["on_root"] / dst_name
    if dst_path.exists():
        assert dst_path.read_bytes() != content, \
            "the checksum gate must never leave a corrupt file committed"


def test_knob_off_corruption_commits_silent_poison(node):
    """THE GAP the knob closes: knob OFF, the SAME one-byte flip.  With no checksum
    verification a plain pull carries no integrity, so the size-correct-but-corrupt
    file is committed as complete: silent poison.  This is exactly what
    brix_tpc_verify_checksum (the test above) prevents."""
    proxy = node["proxy_off"]
    content = os.urandom(8000)
    src_name = _name("tpc_flip_off_src")
    dst_name = _name("tpc_flip_off_dst")
    _seed(node["off_root"], src_name, content)

    src = f"root://{node['host']}:{proxy.listen}//{src_name}"
    dst = f"root://{node['host']}:{node['port_off']}//{dst_name}"
    proxy.arm("flip")
    try:
        r = _xrdcp_tpc(src, dst)
    finally:
        proxy.disarm()

    assert r.returncode == 0, \
        f"knob OFF has no integrity check; a length-preserving flip should " \
        f"'succeed': {r.stderr.decode(errors='replace')}"
    committed = (node["off_root"] / dst_name).read_bytes()
    assert committed != content, (
        "knob OFF should have committed SILENT POISON (a corrupt but complete file) "
        "— the pull-leg integrity gap #13 closes; if this is equal the proxy did "
        "not flip a body byte")
    assert len(committed) == len(content), \
        "the flip is a single-byte mutation, not a truncation"
