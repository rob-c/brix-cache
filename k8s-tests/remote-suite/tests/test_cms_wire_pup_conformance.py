"""
tests/test_cms_wire_pup_conformance.py — CMS manager-protocol Pup/frame
wire-conformance tests.

This suite is a byte-level conformance harness for the nginx-xrootd CMS
heartbeat client (src/net/cms/{wire,frame_io,send,recv}.c).  It provisions ONE
dedicated nginx data-node configured with ``brix_cms_manager`` pointing at a
tiny in-process Python "manager" peer that speaks the real XrdCms framing.  The
peer accepts the node's TCP connection, captures the LOGIN/LOAD frames the node
emits, and then drives the node with manager-originated PING / kYR_space /
kYR_state frames — so the *outgoing* encoder (XrdOucPup tagged-vs-bare layout,
4-string login tail, newline path list, empty-string 00 00) and the *incoming*
dispatch (PONG, kYR_avail echoing the space streamid, kYR_have with
CMS_MOD_RAW|HAVE_ONLINE) are both asserted directly against the wire bytes.

The 8-byte big-endian frame header, the >4088 oversize-frame disconnect, and
recv-boundary fragmentation are exercised against the nginx CMS *server*
(``brix_cms_server on``), where a Python data-node peer is the frame source.

Everything is self-contained on dedicated high ports (>=12950).  If the nginx
binary is missing, or the node never dials the peer, the affected tests skip
cleanly rather than hard-fail.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_cms_wire_pup_conformance.py -v
"""

import os
import socket
import struct
import subprocess
import threading
import time

import pytest

from settings import HOST, NGINX_BIN, SERVER_HOST, free_port

H = SERVER_HOST
_DIR = os.path.join(os.environ["TMPDIR"], "xrd_cms_wire_pup")

# Dedicated free OS ports unique to this file to avoid fleet collisions.
# Each is allocated dynamically (or honours its env override) so the full P0
# suite runs collision-free in one pytest invocation regardless of run order.
NODE_DATA_PORT   = int(os.environ.get("TEST_CWP_NODE_DATA_PORT") or free_port())  # node's root:// listen
MGR_PEER_PORT    = int(os.environ.get("TEST_CWP_MGR_PEER_PORT")  or free_port())  # Python manager peer
CMS_SRV_PORT     = int(os.environ.get("TEST_CWP_CMS_SRV_PORT")   or free_port())  # nginx brix_cms_server


# ---------------------------------------------------------------------------
# CMS wire constants — mirror src/net/cms/cms_internal.h + XProtocol/YProtocol.hh
# ---------------------------------------------------------------------------

CMS_RR_LOGIN  = 0
CMS_RR_LOCATE = 2
CMS_RR_AVAIL  = 12
CMS_RR_GONE   = 14
CMS_RR_HAVE   = 15
CMS_RR_LOAD   = 16
CMS_RR_PING   = 17
CMS_RR_PONG   = 18
CMS_RR_SPACE  = 19
CMS_RR_STATE  = 20
CMS_RR_STATFS = 21
CMS_RR_STATUS = 22
CMS_RR_DISC   = 13
CMS_RR_UPDATE = 25
CMS_RR_MKDIR  = 3

# CMS response codes (CmsRspCode) carried in a reply frame's rrCode field.
CMS_RSP_DATA  = 0
CMS_RSP_ERROR = 1

CMS_PT_SHORT  = 0x80   # tagged 2-byte scalar
CMS_PT_INT    = 0xa0   # tagged 4-byte scalar

CMS_MOD_RAW     = 0x20  # kYR_raw — payload is unmarshalled
CMS_HAVE_ONLINE = 0x01  # kYR_have modifier: file is resident/online

CMS_ST_RESUME   = 0x04
CMS_ST_NOSTAGE  = 0x02

CMS_HDR_LEN  = 8
CMS_MAX_FRAME = 4096          # NGX_BRIX_CMS_MAX_FRAME
# A frame whose dlen pushes (dlen + 8) over MAX_FRAME must be rejected; the
# largest *accepted* dlen is therefore 4088.
CMS_MAX_DLEN = CMS_MAX_FRAME - CMS_HDR_LEN   # 4088

CMS_LOGIN_VERSION = 3


# ---------------------------------------------------------------------------
# Raw frame helpers (same struct-framing style as test_readv_security.py)
# ---------------------------------------------------------------------------

def _recv_exact(sock, n):
    """Read exactly n bytes; return None if the peer closes early."""
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def _recv_frame(sock):
    """Read one 8-byte-header CMS frame -> (streamid, code, modifier, payload).
    Returns None on a clean/short close."""
    hdr = _recv_exact(sock, CMS_HDR_LEN)
    if hdr is None:
        return None
    streamid, code, modifier, dlen = struct.unpack(">IBBH", hdr)
    payload = b""
    if dlen:
        payload = _recv_exact(sock, dlen)
        if payload is None:
            return None
    return streamid, code, modifier, payload


def _build_frame(streamid, code, modifier, payload=b""):
    """Build a CMS frame: [streamid:4][code:1][modifier:1][dlen:2][payload]."""
    return struct.pack(">IBBH", streamid, code, modifier, len(payload)) + payload


# --- XrdOucPup decode helpers (the format under test) ---------------------

def _pup_read_scalar(buf, pos):
    """Decode one tagged scalar at buf[pos]: PT_SHORT(0x80)+u16 or PT_INT(0xa0)+u32.
    Returns (value, new_pos).  Raises AssertionError on an unexpected tag or a
    truncated scalar (so a malformed frame fails with a readable message rather
    than an opaque IndexError/struct.error)."""
    assert pos < len(buf), f"Pup scalar tag past end of buffer at {pos}"
    tag = buf[pos]
    if tag == CMS_PT_SHORT:
        assert pos + 3 <= len(buf), f"truncated PT_SHORT scalar at {pos}"
        return struct.unpack(">H", buf[pos + 1:pos + 3])[0], pos + 3
    if tag == CMS_PT_INT:
        assert pos + 5 <= len(buf), f"truncated PT_INT scalar at {pos}"
        return struct.unpack(">I", buf[pos + 1:pos + 5])[0], pos + 5
    raise AssertionError(f"unexpected Pup scalar tag 0x{tag:02x} at {pos}")


def _pup_read_string(buf, pos):
    """Decode one XrdOucPup string: [len:u16][len raw bytes incl trailing NUL].
    An empty string is a bare 00 00 (len 0, no data).  Returns (bytes, new_pos)
    where bytes EXCLUDES the trailing NUL (matching the logical content)."""
    assert pos + 2 <= len(buf), f"truncated Pup string length at {pos}"
    ln = struct.unpack(">H", buf[pos:pos + 2])[0]
    pos += 2
    assert pos + ln <= len(buf), \
        f"Pup string body (len {ln}) runs past end of buffer at {pos}"
    raw = buf[pos:pos + ln]
    pos += ln
    if ln == 0:
        return b"", pos
    # The encoded length includes the trailing NUL.
    assert raw[-1:] == b"\x00", "Pup string must be NUL-terminated"
    return raw[:-1], pos


def _decode_login(payload):
    """Decode a kYR_login payload into a dict matching the CmsLoginData tail.
    Scalars: Version(sh) Mode(int) HoldTime(int) tSpace(int) fSpace(int)
    mSpace(int) fsNum(sh) fsUtil(sh) dPort(sh) sPort(sh), then four Pup
    strings: SID, Paths, ifList, envCGI.

    A truncated payload (which would mean a malformed encoder) surfaces as a
    clear AssertionError rather than an opaque IndexError/struct.error."""
    if len(payload) < 3:
        raise AssertionError(f"login payload too short to decode: {payload!r}")
    p = 0
    out = {}
    out["version"], p = _pup_read_scalar(payload, p)
    out["mode"], p = _pup_read_scalar(payload, p)
    out["holdtime"], p = _pup_read_scalar(payload, p)
    out["tspace"], p = _pup_read_scalar(payload, p)
    out["fspace"], p = _pup_read_scalar(payload, p)
    out["mspace"], p = _pup_read_scalar(payload, p)
    out["fsnum"], p = _pup_read_scalar(payload, p)
    out["fsutil"], p = _pup_read_scalar(payload, p)
    out["dport"], p = _pup_read_scalar(payload, p)
    out["sport"], p = _pup_read_scalar(payload, p)
    out["sid"], p = _pup_read_string(payload, p)
    out["paths"], p = _pup_read_string(payload, p)
    out["iflist"], p = _pup_read_string(payload, p)
    out["envcgi"], p = _pup_read_string(payload, p)
    out["_tail_pos"] = p
    return out


# ---------------------------------------------------------------------------
# In-process Python CMS "manager" peer
#
# Accepts the nginx node's connection, records every frame the node emits, and
# lets a test send manager-originated frames (PING / kYR_space / kYR_state)
# back down the same socket so the node's incoming dispatch can be observed.
# ---------------------------------------------------------------------------

class CmsManagerPeer:
    def __init__(self, port):
        self.port = port
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind the wildcard address (like the nginx peers do): a lingering
        # 127.0.0.1:port TIME-WAIT socket from a prior run can otherwise defeat
        # SO_REUSEADDR on the exact local 4-tuple.  Retry briefly to ride out a
        # transient EADDRINUSE rather than failing the whole module.
        bound = False
        for _ in range(40):
            try:
                self._srv.bind(("0.0.0.0", port))
                bound = True
                break
            except OSError:
                time.sleep(0.25)
        if not bound:
            self._srv.close()
            raise OSError(f"could not bind CMS manager peer port {port}")
        self._srv.listen(4)
        self._lock = threading.Lock()
        self.frames = []            # [(streamid, code, modifier, payload)]
        self.conn = None
        self._stop = False
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self):
        while not self._stop:
            try:
                self._srv.settimeout(1.0)
                conn, _ = self._srv.accept()
            except (socket.timeout, OSError):
                if self._stop:
                    return
                continue
            conn.settimeout(2.0)
            with self._lock:
                # Keep only the latest live connection (worker may reconnect).
                self.conn = conn
            self._read_loop(conn)

    def _read_loop(self, conn):
        # Buffered, timeout-tolerant reader.  The connection carries a short
        # SO_RCVTIMEO (set in _accept_loop) only so this thread can periodically
        # observe self._stop during teardown — a read timeout means "the node
        # has nothing to say right now" (it is idle between heartbeats), NOT
        # that the connection is gone.  The previous version called _recv_frame()
        # and returned on the first None, but _recv_exact() collapses a socket
        # timeout into None, so any node-frame gap longer than the socket timeout
        # silently killed this reader.  The socket then stayed open but unread,
        # so a manager-originated PING's PONG was never captured and the next
        # collect_reply() reported a "dead" connection.  Keep waiting on timeout;
        # tear down only on real EOF (empty recv) or hard error.  Partial frames
        # are preserved in `buf` across timeouts so a split frame is never lost.
        buf = bytearray()
        while not self._stop:
            self._drain_frames(buf)
            keep_reading, chunk = self._read_chunk(conn)
            if not keep_reading:
                return
            if chunk:
                buf.extend(chunk)

    def _drain_frames(self, buf):
        while len(buf) >= CMS_HDR_LEN:
            streamid, code, modifier, dlen = struct.unpack(
                ">IBBH", bytes(buf[:CMS_HDR_LEN]))
            if len(buf) < CMS_HDR_LEN + dlen:
                break
            payload = bytes(buf[CMS_HDR_LEN:CMS_HDR_LEN + dlen])
            del buf[:CMS_HDR_LEN + dlen]
            with self._lock:
                self.frames.append((streamid, code, modifier, payload))

    @staticmethod
    def _read_chunk(conn):
        try:
            chunk = conn.recv(4096)
            return bool(chunk), chunk
        except socket.timeout:
            return True, None
        except OSError:
            return False, None

    # -- assertions / queries -------------------------------------------------

    def wait_for_code(self, code, timeout=20.0):
        """Block until a frame with the given rrCode is captured; return it."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                for fr in self.frames:
                    if fr[1] == code:
                        return fr
            time.sleep(0.1)
        return None

    def have_connection(self, timeout=20.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if self.conn is not None:
                    return True
            time.sleep(0.1)
        return False

    def send_to_node(self, streamid, code, modifier, payload=b""):
        with self._lock:
            conn = self.conn
        assert conn is not None, "no live node connection to send to"
        conn.sendall(_build_frame(streamid, code, modifier, payload))

    def collect_reply(self, code, timeout=8.0):
        """Wait for a node-originated reply with the given code that arrived
        AFTER the current frame count; return it or None."""
        with self._lock:
            start = len(self.frames)
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                for fr in self.frames[start:]:
                    if fr[1] == code:
                        return fr
            time.sleep(0.1)
        return None

    def close(self):
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass
        with self._lock:
            if self.conn is not None:
                try:
                    self.conn.close()
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# nginx process helpers
# ---------------------------------------------------------------------------

def _reachable(port, timeout=1.0):
    try:
        socket.create_connection((H, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def _wait_port(port, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _reachable(port, 0.5):
            return True
        time.sleep(0.2)
    return False


def _mkdirs(*paths):
    for p in paths:
        os.makedirs(p, exist_ok=True)


def _node_conf(name, listen_port, mgr_port, data_dir, allow_write=True):
    """A data-node nginx that serves root:// AND dials the Python manager peer.

    brix_cms_manager makes the worker open a persistent CMS connection to the
    peer and emit LOGIN + periodic LOAD; brix_cms_interval 2 keeps the
    heartbeat tight so tests don't wait long.  brix_listen_port is advertised
    as dPort in the LOGIN frame.
    """
    base = os.path.join(_DIR, name)
    _mkdirs(base, os.path.join(base, "logs"))
    write_line = "        brix_allow_write on;\n" if allow_write else ""
    conf = os.path.join(base, f"{name}.conf")
    with open(conf, "w") as f:
        f.write(
            f"worker_processes 1;\n"
            f"error_log {base}/logs/error.log info;\n"
            f"pid {base}/logs/nginx.pid;\n"
            f"events {{ worker_connections 128; }}\n"
            f"stream {{\n"
            f"    server {{\n"
            f"        listen 0.0.0.0:{listen_port};\n"
            f"        brix_root on; brix_storage_backend posix:{data_dir}; brix_auth none;\n"
            f"{write_line}"
            f"        brix_listen_port {listen_port};\n"
            f"        brix_cms_manager {HOST}:{mgr_port};\n"
            f"        brix_cms_paths /;\n"
            f"        brix_cms_interval 2;\n"
            f"    }}\n"
            f"}}\n")
    return conf


def _cms_server_conf(name, listen_port, data_dir):
    """An nginx CMS *server* (manager side) that accepts data-node CMS
    connections — used as the frame *parser* under test (header sizing,
    oversize-frame rejection, recv-boundary fragmentation)."""
    base = os.path.join(_DIR, name)
    _mkdirs(base, os.path.join(base, "logs"))
    conf = os.path.join(base, f"{name}.conf")
    with open(conf, "w") as f:
        f.write(
            f"worker_processes 1;\n"
            f"error_log {base}/logs/error.log info;\n"
            f"pid {base}/logs/nginx.pid;\n"
            f"events {{ worker_connections 128; }}\n"
            f"stream {{\n"
            f"    server {{\n"
            f"        listen 0.0.0.0:{listen_port};\n"
            f"        brix_root on; brix_storage_backend posix:{data_dir}; brix_auth none;\n"
            f"        brix_manager_mode on;\n"
            f"        brix_cms_server on;\n"
            f"        brix_cms_server_interval 60;\n"
            f"    }}\n"
            f"}}\n")
    return conf


def _start_nginx(conf):
    # Stop any instance left over from a prior run that shares this conf's pid
    # file, so we never silently attach to a stale master still holding the
    # listen port (which would defeat the bind and make the new master exit).
    subprocess.run([NGINX_BIN, "-c", conf, "-s", "stop"], capture_output=True)
    time.sleep(0.3)
    chk = subprocess.run([NGINX_BIN, "-t", "-c", conf],
                         capture_output=True, text=True)
    if chk.returncode != 0:
        return False, chk.stderr[-400:]
    started = subprocess.run([NGINX_BIN, "-c", conf], capture_output=True,
                             text=True)
    if started.returncode != 0:
        return False, started.stderr[-400:]
    return True, ""


def _stop_nginx(conf):
    subprocess.run([NGINX_BIN, "-c", conf, "-s", "stop"], capture_output=True)

from split_continuation import load as _load_continuations
_load_continuations(
    globals(), __file__,
    "_test_cms_wire_pup_conformance_part2.py",
    "_test_cms_wire_pup_conformance_part3.py",
)
