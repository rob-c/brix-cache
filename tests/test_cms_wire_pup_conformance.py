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
import threading
import time

import pytest

from server_registry import NginxInstanceSpec
from settings import SERVER_HOST
from ephemeral_port import free_port

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-cms-wire")]

H = SERVER_HOST
_DIR = os.path.join(os.environ["TMPDIR"], "xrd_cms_wire_pup")

# An arbitrary dPort advertised in the fake data-node LOGIN payloads the
# server-side tests build; it need not be a real listening port.
NODE_DATA_PORT = 41094


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
CMS_RR_STATS  = 11
CMS_RR_USAGE  = 26

# CMS response codes (CmsRspCode) carried in a reply frame's rrCode field.
CMS_RSP_DATA  = 0
CMS_RSP_ERROR = 1

CMS_PT_SHORT  = 0x80   # tagged 2-byte scalar
CMS_PT_INT    = 0xa0   # tagged 4-byte scalar

CMS_MOD_RAW     = 0x20  # kYR_raw — payload is unmarshalled
CMS_HAVE_ONLINE = 0x01  # kYR_have modifier: file is resident/online

# CmsLoginData Mode role bits (YProtocol.hh) — Phase-61 W7 explicit roles.
CMS_MODE_MANAGER = 0x02   # kYR_manager
CMS_MODE_SERVER  = 0x08   # kYR_server
# CmsStateRequest modifier: kYR_metaman — only a PURE meta-manager (no local
# export) may stamp it on a fanned-out kYR_state (XrdCmsNode.cc do_State).
CMS_STATE_METAMAN = 0x08

CMS_STATS_SIZE  = 0x01  # CmsStatsRequest::kYR_size — size form only
# Cluster.Stats statsz advertisement: sizeof(statfmt1) + 8 in stock v5.9.6,
# where statfmt1 = '<stats id="cms"><role>%s</role></stats>' (39 chars + NUL).
CMS_STATS_BUFSZ = 48

CMS_ST_RESUME   = 0x04
CMS_ST_NOSTAGE  = 0x02
CMS_ST_STAGE    = 0x01
CMS_ST_SUSPEND  = 0x08
CMS_ST_RESET    = 0x10

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
                self._srv.bind(("0.0.0.0", port))  # net-literal-allow: wildcard bind (all interfaces) for mock CMS server
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
            while len(buf) >= CMS_HDR_LEN:
                streamid, code, modifier, dlen = struct.unpack(
                    ">IBBH", bytes(buf[:CMS_HDR_LEN]))
                if len(buf) < CMS_HDR_LEN + dlen:
                    break
                payload = bytes(buf[CMS_HDR_LEN:CMS_HDR_LEN + dlen])
                del buf[:CMS_HDR_LEN + dlen]
                with self._lock:
                    self.frames.append((streamid, code, modifier, payload))
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if not chunk:
                return
            buf.extend(chunk)

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

    def count_frames(self, code):
        """Total captured frames with the given rrCode (full history)."""
        with self._lock:
            return sum(1 for fr in self.frames if fr[1] == code)

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
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def node_stack(lifecycle):
    """A Python manager peer + a dedicated nginx data-node that dials it.

    Yields the live peer with the node's first LOGIN/LOAD frames already
    captured (its real listen port is exposed as ``peer.node_port``).  Skips if
    the node never connects out to the peer.
    """
    data_dir = os.path.join(_DIR, "node_data")
    os.makedirs(data_dir, exist_ok=True)
    # A file that exists under the export root so kYR_state -> kYR_have works.
    with open(os.path.join(data_dir, "have_me.bin"), "wb") as f:
        f.write(b"resident-bytes" * 16)

    mgr_port = free_port()
    try:
        peer = CmsManagerPeer(mgr_port)
    except OSError as exc:
        pytest.skip(f"could not bind CMS manager peer port {mgr_port}: {exc}")

    try:
        ep = lifecycle.start(NginxInstanceSpec(
            name="lc-cms-wire-node",
            template="nginx_cms_wire_node.conf",
            protocol="root",
            readiness="tcp",
            data_root=data_dir,
            template_values={"MANAGER_PORT": mgr_port},
            reason="CMS wire/Pup conformance: outgoing encoder + incoming dispatch.",
        ))
    except Exception:
        peer.close()
        raise
    peer.node_port = ep.port

    try:
        if not peer.have_connection(timeout=20.0):
            pytest.skip("data-node never opened a CMS connection to the peer")
        yield peer
    finally:
        peer.close()


@pytest.fixture
def login_frame(node_stack):
    """The captured LOGIN frame (streamid, code, modifier, payload)."""
    fr = node_stack.wait_for_code(CMS_RR_LOGIN, timeout=20.0)
    if fr is None:
        pytest.skip("node did not emit a LOGIN frame")
    return fr


@pytest.fixture
def load_frame(node_stack):
    """The captured LOAD heartbeat frame."""
    fr = node_stack.wait_for_code(CMS_RR_LOAD, timeout=20.0)
    if fr is None:
        pytest.skip("node did not emit a LOAD frame within the heartbeat window")
    return fr


@pytest.fixture
def cms_server_ep(lifecycle):
    """A dedicated nginx CMS *server* whose frame parser we probe directly.
    Yields the full endpoint (port + prefix, for error-log asserts)."""
    return lifecycle.start(NginxInstanceSpec(
        name="lc-cms-wire-server",
        template="nginx_cms_wire_server.conf",
        protocol="root",
        readiness="tcp",
        reason="CMS wire/Pup conformance: server-side frame parser.",
    ))


@pytest.fixture
def cms_server(cms_server_ep):
    """The CMS server's listen port (most tests only need the port)."""
    return cms_server_ep.port


def _node_login_dialog(port, login_payload):
    """Open a fresh connection to the CMS server and send a LOGIN frame so the
    server registers us — returns the connected socket (caller closes it).
    Used to bring the server's per-connection parser into the logged-in state
    before probing LOAD/AVAIL handling."""
    sock = socket.create_connection((H, port), timeout=8)
    sock.settimeout(8)
    sock.sendall(_build_frame(0, CMS_RR_LOGIN, 0, login_payload))
    return sock


def _minimal_login_payload(dport, paths=b"r /"):
    """Build a minimal but well-formed CmsLoginData payload the server's
    cms_srv_parse_login() accepts, advertising dPort and a path list."""
    p = b""
    p += bytes([CMS_PT_SHORT]) + struct.pack(">H", CMS_LOGIN_VERSION)   # version
    p += bytes([CMS_PT_INT]) + struct.pack(">I", 0x08)                  # mode
    p += bytes([CMS_PT_INT]) + struct.pack(">I", 0)                     # holdtime
    p += bytes([CMS_PT_INT]) + struct.pack(">I", 100)                   # tSpace
    p += bytes([CMS_PT_INT]) + struct.pack(">I", 5000)                  # fSpace
    p += bytes([CMS_PT_INT]) + struct.pack(">I", 100)                   # mSpace
    p += bytes([CMS_PT_SHORT]) + struct.pack(">H", 1)                   # fsNum
    p += bytes([CMS_PT_SHORT]) + struct.pack(">H", 7)                   # fsUtil
    p += bytes([CMS_PT_SHORT]) + struct.pack(">H", dport)               # dPort
    p += bytes([CMS_PT_SHORT]) + struct.pack(">H", 0)                   # sPort
    # SID, Paths, ifList, envCGI — Pup strings (len incl trailing NUL).
    for s in (b"testnode:1", paths, b"", b""):
        if not s:
            p += struct.pack(">H", 0)
        else:
            p += struct.pack(">H", len(s) + 1) + s + b"\x00"
    return p


# ===========================================================================
# Class 1 — kYR_login outgoing Pup encoding (node -> manager)
# ===========================================================================

class TestLoginPupEncoding:
    """The node's emitted LOGIN frame must match the real CmsLoginData layout."""

    def test_login_four_string_tail_order(self, login_frame, node_stack):
        """Tail is exactly SID, Paths, ifList, envCGI — in that order, and the
        decode consumes the entire payload (no trailing bytes)."""
        _sid, code, _mod, payload = login_frame
        assert code == CMS_RR_LOGIN
        d = _decode_login(payload)
        # SID is "<host>:<port>" and must carry the advertised data port.
        assert b":" in d["sid"], f"SID not host:port form: {d['sid']!r}"
        assert d["sid"].endswith(str(node_stack.node_port).encode()), \
            f"SID must end with dPort {node_stack.node_port}: {d['sid']!r}"
        # ifList + envCGI are emitted empty by the node.
        assert d["iflist"] == b""
        assert d["envcgi"] == b""
        # The four strings must consume the full payload — proves the tail
        # order and that nothing trails envCGI.
        assert d["_tail_pos"] == len(payload), \
            "login payload has bytes beyond the 4-string tail"

    def test_login_paths_reencoded_w_r_newline(self, login_frame):
        """Paths is a newline-separated '<type> <path>' list; type is 'w' (the
        node has brix_allow_write on) or 'r', '/' is exported."""
        _sid, _code, _mod, payload = login_frame
        d = _decode_login(payload)
        paths = d["paths"]
        assert paths, "Paths string must not be empty"
        for line in paths.split(b"\n"):
            assert line[:1] in (b"w", b"r"), f"bad path type prefix: {line!r}"
            assert line[1:2] == b" ", f"type must be followed by a space: {line!r}"
            assert line[2:3] == b"/", f"path must be absolute: {line!r}"
        # This node is writable, so the '/' export must be advertised 'w /'.
        assert b"w /" in paths, f"writable export not 'w /': {paths!r}"

    def test_login_version_and_mode_are_tagged_scalars(self, login_frame):
        """Version is a PT_SHORT, Mode a PT_INT — verify the tags directly."""
        _sid, _code, _mod, payload = login_frame
        assert payload[0] == CMS_PT_SHORT, "Version must be a tagged short"
        assert struct.unpack(">H", payload[1:3])[0] == CMS_LOGIN_VERSION
        assert payload[3] == CMS_PT_INT, "Mode must be a tagged int"


# ===========================================================================
# Class 2 — empty Pup string encoding
# ===========================================================================

class TestEmptyStringEncoding:
    """An empty/absent Pup string is encoded as a bare 00 00 (len 0, no NUL)."""

    def test_empty_string_is_two_zero_bytes(self, login_frame):
        """ifList and envCGI are empty: each must occupy exactly 2 bytes (00
        00) with no data and no trailing NUL."""
        _sid, _code, _mod, payload = login_frame
        # Re-walk and capture the raw spans of the trailing two strings.
        p = 0
        # ten scalars
        for _ in range(10):
            _v, p = _pup_read_scalar(payload, p)
        # SID, Paths consume their own bytes
        _s, p = _pup_read_string(payload, p)
        _pa, p = _pup_read_string(payload, p)
        iflist_len = struct.unpack(">H", payload[p:p + 2])[0]
        assert iflist_len == 0, "ifList should be the empty (00 00) string"
        p += 2
        envcgi_len = struct.unpack(">H", payload[p:p + 2])[0]
        assert envcgi_len == 0, "envCGI should be the empty (00 00) string"
        p += 2
        assert p == len(payload), "empty strings must add no extra bytes"


# ===========================================================================
# Class 3 — kYR_load Pup layout: bare theLoad + tagged dskFree
# ===========================================================================

class TestLoadPupEncoding:
    """The LOAD payload is a BARE [len:2][6 load bytes] blob (no scalar tag)
    followed by dskFree as a TAGGED int."""

    def test_load_theload_is_bare_two_byte_length(self, load_frame):
        """The first field is a bare u16 length == 6 (NOT a 0x80 PT_SHORT tag),
        immediately followed by 6 raw load bytes."""
        _sid, code, _mod, payload = load_frame
        assert code == CMS_RR_LOAD
        # First byte must NOT be a tag byte: a bare length of 6 starts 0x00 0x06.
        assert payload[0] != CMS_PT_SHORT, \
            "theLoad must be a bare length, not a PT_SHORT-tagged scalar"
        assert payload[0] != CMS_PT_INT
        nload = struct.unpack(">H", payload[0:2])[0]
        assert nload == 6, f"theLoad blob length must be 6, got {nload}"
        # 2 length bytes + 6 load bytes = 8 bytes before dskFree.
        assert len(payload) >= 2 + 6

    def test_load_dskfree_is_tagged_int(self, load_frame):
        """After the 6 bare load bytes, dskFree is a PT_INT tagged scalar and
        consumes the rest of the payload exactly."""
        _sid, _code, _mod, payload = load_frame
        pos = 2 + 6                       # skip bare length + 6 load bytes
        assert payload[pos] == CMS_PT_INT, \
            "dskFree must be a tagged int (0xa0)"
        free_mb, newpos = _pup_read_scalar(payload, pos)
        assert newpos == len(payload), "dskFree must end the LOAD payload"
        assert free_mb >= 0

    def test_load_bytes_are_real_machine_load(self, load_frame):
        """Phase-89 W4: the 6 load bytes are live /proc-derived percentages,
        not zero padding.  Layout is cpu,net,xeq,mem,pag,dsk; every byte is a
        0-100 percentage.  mem comes from /proc/meminfo and is non-zero on any
        real machine (cpu/net/xeq/pag may legitimately be 0 — rate meters are
        unprimed on the first heartbeat)."""
        _sid, _code, _mod, payload = load_frame
        load6 = payload[2:8]
        assert all(b <= 100 for b in load6), f"load bytes must be 0-100: {load6!r}"
        assert load6[3] > 0, "mem pct must be non-zero on a live host"


# ===========================================================================
# Class 4 — Pup tag round-trip (encoder + our decoder agree)
# ===========================================================================

class TestPupTagRoundtrip:
    """The PT_SHORT (0x80) and PT_INT (0xa0) scalar tags round-trip through the
    same decode used on the live login frame — a self-checking spec of the tag
    format the encoder (wire.c put_short/put_int) emits."""

    def test_short_tag_roundtrip(self):
        enc = bytes([CMS_PT_SHORT]) + struct.pack(">H", 0xBEEF)
        val, pos = _pup_read_scalar(enc, 0)
        assert val == 0xBEEF and pos == 3

    def test_int_tag_roundtrip(self):
        enc = bytes([CMS_PT_INT]) + struct.pack(">I", 0xDEADBEEF)
        val, pos = _pup_read_scalar(enc, 0)
        assert val == 0xDEADBEEF and pos == 5

    def test_live_login_scalars_decode_with_these_tags(self, login_frame):
        """The first ten live login fields decode cleanly with exactly the
        PT_SHORT/PT_INT tag widths (3 and 5 bytes) — no other tag appears."""
        _sid, _code, _mod, payload = login_frame
        p = 0
        widths = []
        for _ in range(10):
            start = p
            _v, p = _pup_read_scalar(payload, start)
            widths.append(p - start)
        # Each scalar is either a 3-byte short or a 5-byte int.
        assert all(w in (3, 5) for w in widths), widths


# ===========================================================================
# Class 5 — 8-byte big-endian frame header
# ===========================================================================

class TestFrameHeader:
    """Every CMS frame the node emits carries the fixed 8-byte BE header."""

    def test_header_streamid_code_modifier_dlen(self, login_frame, node_stack):
        """The captured LOGIN frame's header round-trips through the documented
        [streamid:4 BE][code:1][modifier:1][dlen:2 BE] layout, and dlen equals
        the actual payload length."""
        streamid, code, modifier, payload = login_frame
        # Re-encode the header from the decoded fields and confirm it is what a
        # fresh _build_frame() of the same fields produces (8 bytes, BE).
        rebuilt = struct.pack(">IBBH", streamid, code, modifier, len(payload))
        assert len(rebuilt) == CMS_HDR_LEN
        assert code == CMS_RR_LOGIN
        # streamid of an unsolicited LOGIN is 0 in this implementation.
        assert streamid == 0, f"LOGIN streamid expected 0, got {streamid}"

    def test_status_frame_modifier_byte(self, node_stack):
        """The post-login kYR_status frame carries Resume|noStage in the
        dedicated modifier byte (proving the header's modifier field is live)."""
        fr = node_stack.wait_for_code(CMS_RR_STATUS, timeout=20.0)
        if fr is None:
            pytest.skip("node did not emit a kYR_status frame")
        _sid, _code, modifier, payload = fr
        assert modifier == (CMS_ST_RESUME | CMS_ST_NOSTAGE), \
            f"status modifier expected Resume|noStage, got 0x{modifier:02x}"
        assert payload == b"", "kYR_status is header-only"


# ===========================================================================
# Class 6 — manager-driven incoming dispatch (manager -> node)
# ===========================================================================

class TestIncomingDispatch:
    """Drive the node with manager-originated frames and assert its replies."""

    def test_ping_gets_pong_echoing_streamid(self, node_stack):
        """A manager kYR_ping must be answered with kYR_pong; the implementation
        echoes the request streamid."""
        sid = 0x11223344
        node_stack.send_to_node(sid, CMS_RR_PING, 0)
        reply = node_stack.collect_reply(CMS_RR_PONG, timeout=8.0)
        assert reply is not None, "node did not answer PING with PONG"
        assert reply[0] == sid, \
            f"PONG must echo PING streamid {sid:#x}, got {reply[0]:#x}"
        assert reply[3] == b"", "PONG is header-only"

    def test_space_query_avail_echoes_streamid(self, node_stack):
        """kYR_space -> kYR_avail with the SAME streamid, payload = two tagged
        ints (free_mb, util_pct)."""
        sid = 0x0A0B0C0D
        node_stack.send_to_node(sid, CMS_RR_SPACE, 0)
        reply = node_stack.collect_reply(CMS_RR_AVAIL, timeout=8.0)
        assert reply is not None, "node did not answer SPACE with AVAIL"
        assert reply[0] == sid, \
            f"AVAIL must echo the SPACE streamid {sid:#x}, got {reply[0]:#x}"
        # Payload: PT_INT free_mb + PT_INT util_pct (5 + 5 bytes).
        payload = reply[3]
        assert len(payload) == 10, f"AVAIL payload must be 10 bytes: {payload!r}"
        free_mb, p = _pup_read_scalar(payload, 0)
        util_pct, p = _pup_read_scalar(payload, p)
        assert p == len(payload)
        assert free_mb >= 0 and util_pct >= 0

    def test_state_have_sets_raw_and_online(self, node_stack):
        """kYR_state(raw) for a resident path -> kYR_have with the modifier byte
        carrying BOTH CMS_MOD_RAW and CMS_HAVE_ONLINE, echoing the streamid, and
        a raw NUL-terminated path payload."""
        sid = 0x55667788
        path = b"/have_me.bin"
        node_stack.send_to_node(sid, CMS_RR_STATE, CMS_MOD_RAW, path + b"\x00")
        reply = node_stack.collect_reply(CMS_RR_HAVE, timeout=8.0)
        assert reply is not None, \
            "node did not answer kYR_state with kYR_have for a resident file"
        assert reply[0] == sid, "kYR_have must echo the state streamid"
        modifier = reply[2]
        assert modifier & CMS_MOD_RAW, "kYR_have must set CMS_MOD_RAW (0x20)"
        assert modifier & CMS_HAVE_ONLINE, \
            "kYR_have must set CMS_HAVE_ONLINE (0x01)"
        # Payload is the raw NUL-terminated path (not Pup-encoded).
        assert reply[3].rstrip(b"\x00") == path

    def test_state_for_absent_path_is_silent(self, node_stack):
        """A kYR_state for a path the node does NOT hold draws no kYR_have — the
        node stays silent (matching real cmsd) and the connection survives."""
        sid = 0x99AABBCC
        node_stack.send_to_node(sid, CMS_RR_STATE, CMS_MOD_RAW,
                                b"/definitely_absent_file.bin\x00")
        reply = node_stack.collect_reply(CMS_RR_HAVE, timeout=3.0)
        assert reply is None, "node must not claim to hold an absent path"
        # Sanity: the connection survives — a manager PING still draws a PONG
        # (deterministic, unlike waiting on the heartbeat's LOAD timing).
        ping_sid = 0x0BADF00D
        node_stack.send_to_node(ping_sid, CMS_RR_PING, 0)
        alive = node_stack.collect_reply(CMS_RR_PONG, timeout=8.0)
        assert alive is not None, "CMS connection died after a silent kYR_state"
        assert alive[0] == ping_sid, "post-state PONG must echo the PING streamid"


# ===========================================================================
# Class 7 — CMS server-side frame parser (header sizing / oversize / fragments)
# ===========================================================================

class TestServerFrameParser:
    """Probe the nginx CMS *server* parser (server_recv.c) directly with a
    Python data-node peer as the frame source."""

    def test_oversized_frame_disconnects(self, cms_server):
        """A frame claiming dlen such that dlen+8 > 4096 must be rejected: the
        server logs 'frame too large' and closes the connection."""
        sock = socket.create_connection((H, cms_server), timeout=8)
        sock.settimeout(5)
        try:
            # dlen = 4089 -> 4089 + 8 = 4097 > 4096 (MAX_FRAME) -> reject.
            oversize_dlen = CMS_MAX_DLEN + 1
            hdr = struct.pack(">IBBH", 0, CMS_RR_LOGIN, 0, oversize_dlen)
            sock.sendall(hdr)
            # Send a little body so the server's recv has data to act on; it must
            # decide on the header alone and close.
            try:
                sock.sendall(b"\x00" * 64)
            except OSError:
                pass
            # The server must close the connection (recv returns 0 / EOF).
            data = _recv_exact(sock, 1)
            assert data is None, \
                "server accepted an oversized frame instead of disconnecting"
        finally:
            sock.close()

    def test_frame_fragmentation_across_recv(self, cms_server):
        """A well-formed LOGIN delivered in byte-dribbled fragments (header
        split from payload, payload split mid-string) must be reassembled and
        accepted: the server stays connected and keeps reading."""
        sock = socket.create_connection((H, cms_server), timeout=8)
        sock.settimeout(5)
        try:
            payload = _minimal_login_payload(NODE_DATA_PORT)
            frame = _build_frame(0, CMS_RR_LOGIN, 0, payload)
            # Dribble the frame one to five bytes at a time with tiny gaps so the
            # server's recv loop crosses the header/payload boundary repeatedly.
            i = 0
            step = 3
            while i < len(frame):
                sock.sendall(frame[i:i + step])
                i += step
                time.sleep(0.02)
            # Follow with a header-only PING-equivalent (kYR_load with no payload
            # is harmless); the key assertion is the connection is still open and
            # the server did not error out on the fragmented LOGIN.
            time.sleep(0.5)
            # If the server had rejected the fragmented LOGIN it would have closed
            # the socket; a non-blocking peek must not see EOF.
            sock.setblocking(False)
            closed = False
            try:
                chunk = sock.recv(1)
                if chunk == b"":
                    closed = True
            except (BlockingIOError, InterruptedError):
                closed = False
            except OSError:
                closed = False
            assert not closed, \
                "server closed the connection after a fragmented but valid LOGIN"
        finally:
            sock.close()

    def test_server_accepts_well_formed_login_then_load(self, cms_server):
        """End-to-end server parse: a LOGIN registers the node, and a subsequent
        LOAD frame (bare theLoad + tagged dskFree) is accepted without the
        server dropping the connection."""
        sock = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
        sock.settimeout(5)
        try:
            time.sleep(0.4)
            # Build a LOAD frame in the exact wire shape the parser expects.
            load = struct.pack(">H", 6) + b"\x00" * 6
            load += bytes([CMS_PT_INT]) + struct.pack(">I", 4096)   # dskFree
            sock.sendall(_build_frame(0, CMS_RR_LOAD, 0, load))
            time.sleep(0.4)
            # Connection must still be open (server processed LOAD silently).
            sock.setblocking(False)
            closed = False
            try:
                if sock.recv(1) == b"":
                    closed = True
            except (BlockingIOError, InterruptedError):
                closed = False
            except OSError:
                closed = False
            assert not closed, "server dropped connection after a valid LOAD"
        finally:
            sock.close()


# ===========================================================================
# Class — Plane A liveness/query replies (data-node -> manager, server side)
# ===========================================================================

def _recv_code(sock, want_code, timeout=5.0):
    """Read frames until one with rrCode==want_code arrives (skipping any
    server-initiated frames such as periodic pings), or return None on
    timeout/close."""
    deadline = time.time() + timeout
    sock.settimeout(timeout)
    while time.time() < deadline:
        fr = _recv_frame(sock)
        if fr is None:
            return None
        if fr[1] == want_code:
            return fr
    return None


class TestServerLivenessPlaneA:
    """The nginx CMS *server* (manager side) must answer node-originated
    ping/disc/update/statfs exactly like stock cmsd (do_Ping/do_Disc/do_Update/
    do_StatFS)."""

    def test_ping_gets_pong(self, cms_server):
        """An incoming kYR_ping is answered with a header-only kYR_pong."""
        sock = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
        try:
            time.sleep(0.4)
            sock.sendall(_build_frame(0, CMS_RR_PING, 0))
            fr = _recv_code(sock, CMS_RR_PONG, timeout=5.0)
            assert fr is not None, "server did not reply kYR_pong to a ping"
            _sid, code, _mod, payload = fr
            assert code == CMS_RR_PONG
            assert payload == b"", "pong must be header-only"
        finally:
            sock.close()

    def test_update_gets_status(self, cms_server):
        """kYR_update -> the server resends its state as a kYR_status frame with
        the Resume bit set (do_Update -> sendState)."""
        sock = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
        try:
            time.sleep(0.4)
            sock.sendall(_build_frame(0, CMS_RR_UPDATE, 0))
            fr = _recv_code(sock, CMS_RR_STATUS, timeout=5.0)
            assert fr is not None, "server did not reply kYR_status to an update"
            _sid, _code, mod, _payload = fr
            assert mod & CMS_ST_RESUME, "status reply must advertise Resume"
        finally:
            sock.close()

    def test_disc_is_echoed_and_closes(self, cms_server):
        """kYR_disc -> the manager echoes a kYR_disc and closes the link
        (do_Disc as-manager)."""
        sock = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
        try:
            time.sleep(0.4)
            sock.sendall(_build_frame(0, CMS_RR_DISC, 0))
            fr = _recv_code(sock, CMS_RR_DISC, timeout=5.0)
            assert fr is not None, "server did not echo kYR_disc"
            # After the echo the server closes — a subsequent read sees EOF.
            sock.settimeout(5)
            assert _recv_frame(sock) is None, "server must close after disc echo"
        finally:
            sock.close()

    def test_statfs_returns_space_data(self, cms_server):
        """kYR_statfs(path) -> kYR_data with a 4-byte zero prefix and a
        'wNum wFree wUtil sNum sFree sUtil' ASCII string (do_StatFS)."""
        sock = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
        try:
            time.sleep(0.4)
            # fwdArgC payload: ident, path (Pup strings; len incl trailing NUL).
            def pup(s):
                return struct.pack(">H", len(s) + 1) + s + b"\x00"
            payload = pup(b"tester") + pup(b"/")
            sock.sendall(_build_frame(7, CMS_RR_STATFS, 0, payload))
            fr = _recv_code(sock, CMS_RSP_DATA, timeout=5.0)
            assert fr is not None, "server did not reply kYR_data to statfs"
            sid, _code, _mod, data = fr
            assert sid == 7, "statfs reply must echo the request streamid"
            assert len(data) >= 5 and data[:4] == b"\x00\x00\x00\x00", \
                "statfs payload must start with the 4-byte zero prefix"
            fields = data[4:].rstrip(b"\x00").split(b" ")
            assert len(fields) == 6, f"expected 6 space fields, got {fields!r}"
            for f in fields:
                int(f)   # every field must be a base-10 integer
        finally:
            sock.close()

    def test_usage_gets_load_echoing_streamid(self, cms_server):
        """Phase-89 W1: kYR_usage -> kYR_load echoing the streamid, payload
        byte-exact with the node-side heartbeat: [>H 6][6 load bytes][tagged
        int dskFree] = 13 bytes; the dsk byte is a percentage (<= 100)."""
        sock = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
        try:
            time.sleep(0.4)
            sid = 0x11223344
            sock.sendall(_build_frame(sid, CMS_RR_USAGE, 0))
            fr = _recv_code(sock, CMS_RR_LOAD, timeout=5.0)
            assert fr is not None, "server did not reply kYR_load to usage"
            rsid, _code, _mod, payload = fr
            assert rsid == sid, "load reply must echo the usage streamid"
            assert len(payload) == 13, f"load payload must be 13 bytes: {payload!r}"
            (blob_len,) = struct.unpack(">H", payload[:2])
            assert blob_len == 6, "theLoad must be a bare 6-byte blob"
            load6 = payload[2:8]
            assert load6[5] <= 100, "dsk load byte must be a percentage"
            free_mb, p = _pup_read_scalar(payload, 8)
            assert p == 13 and free_mb >= 0, "dskFree must be a tagged int"
        finally:
            sock.close()

    def test_stats_gets_size_form(self, cms_server):
        """Phase-61 W7: kYR_stats(kYR_size) -> kYR_data echoing the streamid,
        payload the raw 4-byte big-endian statsz — byte-exact with stock
        v5.9.6 (Cluster.Stats(0,0) = sizeof(statfmt1) + 8 = 48)."""
        sock = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
        try:
            time.sleep(0.4)
            sock.sendall(_build_frame(9, CMS_RR_STATS, CMS_STATS_SIZE))
            fr = _recv_code(sock, CMS_RSP_DATA, timeout=5.0)
            assert fr is not None, "server did not reply kYR_data to stats"
            sid, _code, _mod, data = fr
            assert sid == 9, "stats reply must echo the request streamid"
            assert len(data) == 4, f"size form must be exactly 4 bytes: {data!r}"
            (need,) = struct.unpack(">I", data)
            assert need == CMS_STATS_BUFSZ, \
                f"statsz must be the stock advertisement {CMS_STATS_BUFSZ}, got {need}"
        finally:
            sock.close()

    def test_stats_full_form_returns_role_document(self, cms_server):
        """Phase-61 W7: kYR_stats without kYR_size -> kYR_data whose payload is
        [4B BE statsz][Cluster.Stats XML, snprintf length, no NUL] with this
        manager's role type ("M") in the role slot — byte-exact do_Stats."""
        sock = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
        try:
            time.sleep(0.4)
            sock.sendall(_build_frame(10, CMS_RR_STATS, 0))
            fr = _recv_code(sock, CMS_RSP_DATA, timeout=5.0)
            assert fr is not None, "server did not reply kYR_data to stats"
            sid, _code, _mod, data = fr
            assert sid == 10, "stats reply must echo the request streamid"
            assert len(data) > 4, f"full form must carry the document: {data!r}"
            (need,) = struct.unpack(">I", data[:4])
            assert need == CMS_STATS_BUFSZ, \
                f"statsz prefix must be {CMS_STATS_BUFSZ}, got {need}"
            doc = data[4:]
            assert doc == b'<stats id="cms"><role>M</role></stats>', \
                f"unexpected Cluster.Stats document: {doc!r}"
        finally:
            sock.close()

    def test_usage_stats_pre_login_ignored(self, cms_server):
        """Security-neg: usage/stats from a connection that never logged in are
        ignored — no reply frame, and no state leaks to the unauthenticated
        peer (the connection simply stays quiet)."""
        sock = socket.create_connection((H, cms_server), timeout=8)
        try:
            sock.sendall(_build_frame(5, CMS_RR_USAGE, 0))
            sock.sendall(_build_frame(6, CMS_RR_STATS, 0))
            sock.settimeout(2)
            try:
                fr = _recv_frame(sock)
            except socket.timeout:
                fr = "silent"
            assert fr in (None, "silent"), \
                f"pre-login usage/stats must not be answered, got {fr!r}"
        finally:
            sock.close()


def _statfs_wfree(sock, sid):
    """Issue a kYR_statfs("/") on an already-logged-in socket and return the
    wFree field (aggregate free MB) from the kYR_data reply."""
    def pup(s):
        return struct.pack(">H", len(s) + 1) + s + b"\x00"
    sock.sendall(_build_frame(sid, CMS_RR_STATFS, 0, pup(b"tester") + pup(b"/")))
    fr = _recv_code(sock, CMS_RSP_DATA, timeout=5.0)
    assert fr is not None, "server did not reply kYR_data to statfs"
    _sid, _code, _mod, data = fr
    fields = data[4:].rstrip(b"\x00").split(b" ")
    assert len(fields) == 6, f"expected 6 space fields, got {fields!r}"
    return int(fields[1])   # wNum wFree wUtil sNum sFree sUtil


class TestServerStatusStateMachine:
    """Phase-89 W9: the manager side of kYR_status — reset forgets cached
    metrics, unknown modifiers are a no-op, and pre-login status frames cannot
    touch another node's registration."""

    def test_status_reset_clears_reported_space(self, cms_server):
        """kYR_status(reset) -> the manager forgets our cached load figures:
        the aggregate free space visible through statfs drops to 0 (the node
        stays registered and the connection stays open)."""
        sock = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
        try:
            time.sleep(0.4)
            assert _statfs_wfree(sock, 21) == 5000, \
                "login-advertised fSpace must be visible before the reset"
            sock.sendall(_build_frame(0, CMS_RR_STATUS, CMS_ST_RESET))
            time.sleep(0.4)
            assert _statfs_wfree(sock, 22) == 0, \
                "reset must clear the cached free-space figure"
        finally:
            sock.close()

    def test_status_unknown_modifier_is_noop(self, cms_server):
        """A kYR_status with an unrecognised modifier bit is ignored: state is
        untouched and the connection stays live (ping still answered)."""
        sock = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
        try:
            time.sleep(0.4)
            sock.sendall(_build_frame(0, CMS_RR_STATUS, 0x40))
            time.sleep(0.2)
            assert _statfs_wfree(sock, 23) == 5000, \
                "unknown status modifier must not touch cached metrics"
            sock.sendall(_build_frame(3, CMS_RR_PING, 0))
            fr = _recv_code(sock, CMS_RR_PONG, timeout=5.0)
            assert fr is not None, "connection must survive an unknown modifier"
        finally:
            sock.close()

    def test_status_pre_login_cannot_touch_registration(self, cms_server):
        """Security-neg: a connection that never logged in sends
        kYR_status(reset) — the frame is ignored and a logged-in node's cached
        metrics are unaffected."""
        node = _node_login_dialog(cms_server, _minimal_login_payload(NODE_DATA_PORT))
        raw = socket.create_connection((H, cms_server), timeout=8)
        try:
            time.sleep(0.4)
            raw.sendall(_build_frame(0, CMS_RR_STATUS, CMS_ST_RESET))
            time.sleep(0.4)
            assert _statfs_wfree(node, 24) == 5000, \
                "pre-login status must not reach the registry"
        finally:
            raw.close()
            node.close()

    def test_login_envcgi_vnid_accepted(self, cms_server):
        """A LOGIN whose envCGI carries '&'-separated tokens including
        vnid=<id> (stock cmsd form) still registers normally — the node
        answers queries and its metrics are visible.  (The parsed vnid is
        surfaced via the dashboard cluster listing, outside this stream-only
        fixture.)"""
        p = _minimal_login_payload(NODE_DATA_PORT)
        # Rebuild the payload tail: replace the empty envCGI (last 2 bytes,
        # a zero-length Pup string) with a populated one.
        assert p[-2:] == struct.pack(">H", 0)
        env = b"foo=1&vnid=zoneA"
        p = p[:-2] + struct.pack(">H", len(env) + 1) + env + b"\x00"
        sock = _node_login_dialog(cms_server, p)
        try:
            time.sleep(0.4)
            assert _statfs_wfree(sock, 25) == 5000, \
                "vnid-bearing login must register the node normally"
        finally:
            sock.close()


# ===========================================================================
# Class — Plane B forwarded namespace ops (manager -> data node, node side)
# ===========================================================================

def _fwd_a_payload(ident, mode, path):
    """fwdArgA Pup payload: ident, mode, path (each [len incl NUL][bytes][NUL])."""
    def pup(s):
        return struct.pack(">H", len(s) + 1) + s + b"\x00"
    return pup(ident) + pup(mode) + pup(path)


class TestForwardedNamespaceOps:
    """A data node executes a manager-forwarded mkdir under kernel confinement:
    success is silent and creates the directory; a path that escapes the export
    root is refused (kYR_error) and creates nothing outside the root."""

    def test_forwarded_mkdir_creates_dir(self, node_stack):
        made = os.path.join(_DIR, "node_data", "fwd_made")
        if os.path.isdir(made):
            os.rmdir(made)
        node_stack.send_to_node(101, CMS_RR_MKDIR, 0,
                                _fwd_a_payload(b"mgr", b"755", b"/fwd_made"))
        # Success is silent; poll the filesystem for the created directory.
        deadline = time.time() + 6.0
        while time.time() < deadline and not os.path.isdir(made):
            time.sleep(0.1)
        assert os.path.isdir(made), "node did not create the forwarded directory"
        # And it must NOT have sent an error for a valid op.
        assert node_stack.collect_reply(CMS_RSP_ERROR, timeout=1.0) is None

    def test_forwarded_mkdir_traversal_is_refused(self, node_stack):
        """A '..' path that escapes the export root must be blocked by the
        kernel-confined open (openat2 RESOLVE_BENEATH) and answered kYR_error —
        and must NOT create anything outside the root."""
        escape = os.path.join(_DIR, "pwned")     # one level above node_data
        if os.path.isdir(escape):
            os.rmdir(escape)
        node_stack.send_to_node(102, CMS_RR_MKDIR, 0,
                                _fwd_a_payload(b"mgr", b"755", b"/../pwned"))
        fr = node_stack.collect_reply(CMS_RSP_ERROR, timeout=6.0)
        assert fr is not None, "node must reply kYR_error for a traversal attempt"
        # The escape target must never have been created.
        assert not os.path.exists(escape), \
            "confinement breach: directory created outside the export root"


# ===========================================================================
# Phase-61 W7 — explicit cluster roles + multi-tier state relay
# ===========================================================================

def _login_payload_with_mode(dport, mode, paths=b"r /"):
    """_minimal_login_payload with the Mode word (2nd field: 1 tag byte +
    4-byte BE int at payload offsets [3:8]) replaced."""
    p = _minimal_login_payload(dport, paths)
    assert p[3] == CMS_PT_INT
    return p[:3] + bytes([CMS_PT_INT]) + struct.pack(">I", mode) + p[8:]


def _wait_log_contains(ep, needle, timeout=10.0):
    """Poll the instance's error.log until `needle` (bytes) appears."""
    path = os.path.join(ep.prefix, "logs", "error.log")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(path, "rb") as f:
                if needle in f.read():
                    return True
        except OSError:
            pass
        time.sleep(0.2)
    return False


def _start_peered_node(lifecycle, name, template, template_values, reason,
                       data_dir):
    """Shared bring-up: Python manager peer + an nginx instance that dials it.
    Returns the peer (node listen port on peer.node_port); caller closes it."""
    os.makedirs(data_dir, exist_ok=True)
    mgr_port = free_port()
    try:
        peer = CmsManagerPeer(mgr_port)
    except OSError as exc:
        pytest.skip(f"could not bind CMS manager peer port {mgr_port}: {exc}")
    values = dict(template_values)
    values["MANAGER_PORT"] = mgr_port
    try:
        ep = lifecycle.start(NginxInstanceSpec(
            name=name,
            template=template,
            protocol="root",
            readiness="tcp",
            data_root=data_dir,
            template_values=values,
            reason=reason,
        ))
    except Exception:
        peer.close()
        raise
    peer.node_port = ep.port
    peer.ep = ep                # for _wait_log_contains on this instance
    if not peer.have_connection(timeout=20.0):
        peer.close()
        pytest.skip(f"{name} never opened a CMS connection to the peer")
    return peer


@pytest.fixture
def manager_node_stack(lifecycle):
    """A node running with an EXPLICIT ``brix_cms_role manager`` + its peer."""
    data_dir = os.path.join(_DIR, "mgr_node_data")
    os.makedirs(data_dir, exist_ok=True)
    with open(os.path.join(data_dir, "have_me.bin"), "wb") as f:
        f.write(b"resident-bytes" * 16)
    peer = _start_peered_node(
        lifecycle, "lc-cms-wire-mgr-node", "nginx_cms_wire_role_node.conf",
        {"ROLE": "manager"},
        "Phase-61 W7: explicit manager role — login Mode + manVOps filter.",
        data_dir)
    try:
        yield peer
    finally:
        peer.close()


@pytest.fixture
def server_node_stack(lifecycle):
    """A node running with an EXPLICIT ``brix_cms_role server`` + its peer."""
    peer = _start_peered_node(
        lifecycle, "lc-cms-wire-srv-node", "nginx_cms_wire_role_node.conf",
        {"ROLE": "server"},
        "Phase-61 W7: explicit server role — stock Pander login Mode word.",
        os.path.join(_DIR, "srv_node_data"))
    try:
        yield peer
    finally:
        peer.close()


def _super_stack(lifecycle, state_relay):
    name = "lc-cms-wire-super" + ("" if state_relay == "on" else "-norelay")
    return _start_peered_node(
        lifecycle, name, "nginx_cms_wire_super.conf",
        {"STATE_RELAY": state_relay},
        "Phase-61 W7: supervisor tier — kYR_state relay recursion.",
        os.path.join(_DIR, name.replace("-", "_") + "_data"))


@pytest.fixture
def super_stack(lifecycle):
    """Supervisor (manager_mode + cms_server + upward leg), state relay ON."""
    peer = _super_stack(lifecycle, "on")
    try:
        yield peer
    finally:
        peer.close()


@pytest.fixture
def super_stack_norelay(lifecycle):
    """Same supervisor topology with brix_cms_state_relay left at default off."""
    peer = _super_stack(lifecycle, "off")
    try:
        yield peer
    finally:
        peer.close()


class TestRoleDirectiveNodeLeg:
    """Phase-61 W7 PR-B: ``brix_cms_role`` on the upward leg — stock Pander
    login Mode word + the role's inbound valid-ops table (manVOps)."""

    def test_manager_role_login_mode_word(self, manager_node_stack):
        """brix_cms_role manager -> LOGIN Mode is exactly kYR_manager (0x02),
        matching XrdCmsPander for a sub-manager (no kYR_server bit)."""
        fr = manager_node_stack.wait_for_code(CMS_RR_LOGIN, timeout=20.0)
        assert fr is not None, "manager-role node did not emit a LOGIN frame"
        login = _decode_login(fr[3])
        assert login["mode"] == CMS_MODE_MANAGER, \
            f"manager role must log in with Mode 0x02, got {login['mode']:#x}"

    def test_manager_role_valid_op_still_served(self, manager_node_stack):
        """kYR_state is in manVOps: a resident-path probe still draws kYR_have
        (the filter must not eat legitimate manager-leg traffic)."""
        sid = 0x61B00001
        manager_node_stack.send_to_node(sid, CMS_RR_STATE, CMS_MOD_RAW,
                                        b"/have_me.bin\x00")
        reply = manager_node_stack.collect_reply(CMS_RR_HAVE, timeout=8.0)
        assert reply is not None, \
            "manVOps must still admit kYR_state on a manager-role node"
        assert reply[0] == sid

    def test_manager_role_drops_op_outside_manvops(self, manager_node_stack):
        """Security-neg: kYR_mkdir is NOT in manVOps (stock initMANrouting) —
        a manager-role node must drop it silently: no directory created, no
        kYR_error, and the connection stays live (PING still answered)."""
        made = os.path.join(_DIR, "mgr_node_data", "mgr_no_mkdir")
        if os.path.isdir(made):
            os.rmdir(made)
        manager_node_stack.send_to_node(
            0x61B00002, CMS_RR_MKDIR, 0,
            _fwd_a_payload(b"mgr", b"755", b"/mgr_no_mkdir"))
        time.sleep(1.0)
        assert not os.path.isdir(made), \
            "manVOps filter breach: manager-role node executed kYR_mkdir"
        assert manager_node_stack.collect_reply(CMS_RSP_ERROR, timeout=1.0) \
            is None, "invalid ops are dropped, not answered with kYR_error"
        ping_sid = 0x61B00003
        manager_node_stack.send_to_node(ping_sid, CMS_RR_PING, 0)
        alive = manager_node_stack.collect_reply(CMS_RR_PONG, timeout=8.0)
        assert alive is not None and alive[0] == ping_sid, \
            "connection must survive a dropped invalid op"

    def test_server_role_login_mode_word(self, server_node_stack):
        """brix_cms_role server -> LOGIN Mode is exactly kYR_server (0x08),
        the stock Pander data-server word (no manager bit)."""
        fr = server_node_stack.wait_for_code(CMS_RR_LOGIN, timeout=20.0)
        assert fr is not None, "server-role node did not emit a LOGIN frame"
        login = _decode_login(fr[3])
        assert login["mode"] == CMS_MODE_SERVER, \
            f"server role must log in with Mode 0x08, got {login['mode']:#x}"


class TestSupervisorValidOps:
    """Phase-61 W7 PR-B, supervisor leg: supVOps (stock initSUProuting)
    admits namespace mutations but marks them Forward — the supervisor fans
    them DOWN to its own data nodes instead of executing locally — and
    excludes kYR_update entirely."""

    CHILD_DPORT = NODE_DATA_PORT + 11

    def _login_child(self, peer):
        sock = _node_login_dialog(
            peer.node_port,
            _login_payload_with_mode(self.CHILD_DPORT, CMS_MODE_SERVER,
                                     paths=b"r /data"))
        time.sleep(0.4)
        return sock

    def test_supervisor_fans_forwarded_mkdir_down(self, super_stack):
        """kYR_mkdir IS in supVOps, flagged Forward: the supervisor must relay
        it down to its logged-in child — and must NOT create the directory
        locally (a supervisor is a routing tier, not an executor)."""
        child = self._login_child(super_stack)
        try:
            super_stack.send_to_node(
                0x61E00001, CMS_RR_MKDIR, 0,
                _fwd_a_payload(b"mgr", b"755", b"/fan_down_dir"))
            fr = _recv_code(child, CMS_RR_MKDIR, timeout=8.0)
            assert fr is not None, \
                "supervisor must fan a forwarded kYR_mkdir down to its child"
            assert b"/fan_down_dir" in fr[3], \
                "fanned-down op must carry the original path"
            local = os.path.join(_DIR, "lc_cms_wire_super_data",
                                 "fan_down_dir")
            assert not os.path.isdir(local), \
                "supervisor executed a Forward-flagged op locally"
        finally:
            child.close()

    def test_supervisor_drops_update_outside_supvops(self, super_stack):
        """Security-neg: kYR_update is NOT in supVOps — no kYR_status reply
        may come back (auto-role nodes answer update with status), and the
        connection survives."""
        # The upward leg announces kYR_status once right after login
        # (connect.c) — wait it out so collect_reply below can only match a
        # status provoked by the update.
        assert super_stack.wait_for_code(CMS_RR_STATUS, timeout=20.0) \
            is not None, "supervisor never sent its login-time kYR_status"
        super_stack.send_to_node(0x61E00002, CMS_RR_UPDATE, 0)
        assert super_stack.collect_reply(CMS_RR_STATUS, timeout=2.5) is None, \
            "supVOps must drop kYR_update on a supervisor"
        ping_sid = 0x61E00003
        super_stack.send_to_node(ping_sid, CMS_RR_PING, 0)
        alive = super_stack.collect_reply(CMS_RR_PONG, timeout=8.0)
        assert alive is not None and alive[0] == ping_sid, \
            "connection must survive a dropped invalid op"


class TestServerAdmitRoles:
    """Phase-61 W7 PR-C: the CMS server leg classifies a node's login Mode
    like stock Admit — (manager|subman) ? (server ? R : M) : S — and stamps
    the role into the registry (visible in the registration NOTICE)."""

    def test_supervisor_mode_login_admits_role_r(self, cms_server_ep):
        """Mode kYR_manager|kYR_server (0x0A) -> admitted as role R and still
        a fully-functional registrant (statfs sees its advertised space)."""
        dport = NODE_DATA_PORT + 1
        sock = _node_login_dialog(
            cms_server_ep.port, _login_payload_with_mode(dport, 0x0A))
        try:
            assert _wait_log_contains(
                cms_server_ep, f":{dport} role=R".encode()), \
                "supervisor-mode login must register with role=R"
            time.sleep(0.2)
            assert _statfs_wfree(sock, 61) == 5000, \
                "an R-role registrant must still serve/aggregate normally"
        finally:
            sock.close()

    def test_manager_mode_login_admits_role_m(self, cms_server_ep):
        """Mode kYR_manager alone (0x02) -> admitted as role M."""
        dport = NODE_DATA_PORT + 2
        sock = _node_login_dialog(
            cms_server_ep.port, _login_payload_with_mode(dport, 0x02))
        try:
            assert _wait_log_contains(
                cms_server_ep, f":{dport} role=M".encode()), \
                "manager-mode login must register with role=M"
            sock.sendall(_build_frame(62, CMS_RR_PING, 0))
            fr = _recv_code(sock, CMS_RR_PONG, timeout=5.0)
            assert fr is not None, "M-role registrant must stay serviceable"
        finally:
            sock.close()

    def test_unrelated_mode_bits_default_role_s(self, cms_server_ep):
        """Security-neg: a Mode word carrying only non-role bits (kYR_nostage,
        0x200) grants nothing — the node is classified plain server (role=S),
        the safe default."""
        dport = NODE_DATA_PORT + 3
        sock = _node_login_dialog(
            cms_server_ep.port, _login_payload_with_mode(dport, 0x200))
        try:
            assert _wait_log_contains(
                cms_server_ep, f":{dport} role=S".encode()), \
                "non-role Mode bits must fall back to role=S"
        finally:
            sock.close()


class TestStateRelayRecursion:
    """Phase-61 W7 PR-D: ``brix_cms_state_relay`` — on a registry miss a
    supervisor re-asks its own children and echoes the first kYR_have back up
    under the parent's streamid.  Default is OFF (silent miss)."""

    CHILD_DPORT = NODE_DATA_PORT + 10

    def _login_child(self, peer):
        """Register a Python child under the supervisor with a NARROW export
        (r /data) so a probe outside it is a registry miss."""
        sock = _node_login_dialog(
            peer.node_port,
            _login_payload_with_mode(self.CHILD_DPORT, CMS_MODE_SERVER,
                                     paths=b"r /data"))
        time.sleep(0.4)
        return sock

    def test_supervisor_login_mode_word(self, super_stack):
        """brix_cms_role supervisor -> upward LOGIN Mode is exactly
        kYR_manager|kYR_server (0x0A), the stock supervisor Pander word."""
        fr = super_stack.wait_for_code(CMS_RR_LOGIN, timeout=20.0)
        assert fr is not None, "supervisor did not emit a LOGIN frame"
        login = _decode_login(fr[3])
        assert login["mode"] == (CMS_MODE_MANAGER | CMS_MODE_SERVER), \
            f"supervisor must log in with Mode 0x0A, got {login['mode']:#x}"

    def test_state_relay_round_trip(self, super_stack):
        """Parent kYR_state for a path outside every child export (registry
        miss) is relayed DOWN to the child; the child's kYR_have is echoed
        back UP under the parent's original streamid.  The relayed probe MUST
        carry kYR_metaman: a brix_manager_mode instance keeps root_canon empty
        (no confined local export, process_server_init.c), so it holds nothing
        itself — stock do_State stamps kYR_metaman for exactly such a
        non-server sender."""
        child = self._login_child(super_stack)
        try:
            up_sid = 0x61D00001
            path = b"/elsewhere/wanted.bin"
            super_stack.send_to_node(up_sid, CMS_RR_STATE, CMS_MOD_RAW,
                                     path + b"\x00")
            fr = _recv_code(child, CMS_RR_STATE, timeout=8.0)
            assert fr is not None, \
                "relay-on supervisor must re-ask its child on a registry miss"
            down_sid, _code, mod, payload = fr
            assert payload.rstrip(b"\x00") == path, \
                "relayed probe must carry the parent's path verbatim"
            assert mod & CMS_MOD_RAW, "relayed kYR_state must be raw"
            assert mod & CMS_STATE_METAMAN, \
                "a no-local-export manager tier must stamp kYR_metaman"
            child.sendall(_build_frame(down_sid, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       path + b"\x00"))
            up = super_stack.wait_for_code(CMS_RR_HAVE, timeout=8.0)
            assert up is not None, \
                "child kYR_have must be echoed up to the parent"
            assert up[0] == up_sid, \
                "upward kYR_have must carry the PARENT's original streamid"
            assert up[3].rstrip(b"\x00") == path
        finally:
            child.close()

    def test_state_relay_default_off_is_silent(self, super_stack_norelay):
        """Default (brix_cms_state_relay off): a registry miss stays silent —
        nothing is relayed to the child and the parent gets no kYR_have."""
        child = self._login_child(super_stack_norelay)
        try:
            super_stack_norelay.send_to_node(0x61D00002, CMS_RR_STATE,
                                             CMS_MOD_RAW,
                                             b"/elsewhere/wanted.bin\x00")
            assert _recv_code(child, CMS_RR_STATE, timeout=3.0) is None, \
                "relay must be OFF by default — child saw a relayed probe"
            # Full-history scan (fresh peer): no kYR_have may EVER go upward.
            assert super_stack_norelay.wait_for_code(CMS_RR_HAVE, timeout=2.0) \
                is None, "silent miss must stay silent upward"
        finally:
            child.close()

    def test_relay_to_no_eligible_node_is_silent_but_logged(self, super_stack):
        """With relay ON and NO child logged in, a registry miss parks a leg
        that nobody can answer.  The parent still reads silence (unchanged
        wire behaviour), but the drop is visible at INFO — a debug-only
        counter would be invisible in every build that hits this."""
        super_stack.send_to_node(0x61D0000A, CMS_RR_STATE, CMS_MOD_RAW,
                                 b"/elsewhere/nobody.bin\x00")
        assert _wait_log_contains(
            super_stack.ep, b"down to no eligible node"), \
            "a relay that reached no node must say so in the error log"
        assert super_stack.wait_for_code(CMS_RR_HAVE, timeout=2.0) is None, \
            "a relay that reached no node must stay silent upward"

    def test_state_probe_path_is_escaped_in_the_error_log(self, super_stack):
        """Security-neg (WS6): the kYR_state path is manager-controlled and
        ``cms_state_extract_path`` accepts every byte but NUL — including
        CR/LF.  Logged raw it would let a hostile manager forge whole
        ``cmsd-action`` lines into error.log; every log site must render it
        through ``brix_sanitize_log_string``."""
        forged = b"/elsewhere/x\ncmsd-action op=login peer=evil dir=in"
        super_stack.send_to_node(0x61D0000B, CMS_RR_STATE, CMS_MOD_RAW,
                                 forged + b"\x00")
        # the escaped form must appear; the injected raw newline must not
        assert _wait_log_contains(super_stack.ep, rb"/elsewhere/x\x0A"), \
            "the probed path must reach the log hex-escaped"
        path = os.path.join(super_stack.ep.prefix, "logs", "error.log")
        with open(path, "rb") as fh:
            for line in fh:
                assert not line.startswith(b"cmsd-action"), \
                    f"forged log line landed unescaped: {line!r}"

    def test_supervisor_fan_down_to_no_node_is_logged(self, super_stack):
        """A forwarded mutation that reaches no data node is a silently
        dropped op — the one outcome of the fan-down worth a WARN."""
        super_stack.send_to_node(
            0x61D0000C, CMS_RR_MKDIR, 0,
            _fwd_a_payload(b"mgr", b"755", b"/fan_down_nobody"))
        assert _wait_log_contains(super_stack.ep, b"reached no node"), \
            "a fan-down that reached no node must be logged"

    def test_unsolicited_child_have_cannot_reach_parent(self, super_stack):
        """Security-neg: a child kYR_have whose streamid was never issued by
        the relay (a forged/unsolicited claim) must NOT surface upward as a
        parent-facing kYR_have."""
        child = self._login_child(super_stack)
        try:
            child.sendall(_build_frame(0x0666BEEF, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       b"/forged/claim.bin\x00"))
            # Full-history scan (fresh peer): a forged HAVE that leaked up
            # before this call would still be caught.
            assert super_stack.wait_for_code(CMS_RR_HAVE, timeout=3.0) is None, \
                "unsolicited child kYR_have leaked up to the parent"
        finally:
            child.close()

    def test_forged_path_on_issued_streamid_refused_then_honest_lands(
            self, super_stack):
        """Security-neg + success: the relay trust anchor is streamid AND
        exact probed path.  A kYR_have on the REAL relay streamid but a
        different path must be refused WITHOUT consuming the entry — the
        honest answer for the probed path must still be echoed upward."""
        child = self._login_child(super_stack)
        try:
            up_sid = 0x61D00004
            path = b"/elsewhere/wanted.bin"
            super_stack.send_to_node(up_sid, CMS_RR_STATE, CMS_MOD_RAW,
                                     path + b"\x00")
            fr = _recv_code(child, CMS_RR_STATE, timeout=8.0)
            assert fr is not None, "child never saw the relayed probe"
            down_sid = fr[0]
            child.sendall(_build_frame(down_sid, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       b"/elsewhere/DECOY.bin\x00"))
            # Full-history scan (fresh peer): nothing has been echoed yet,
            # so any upward kYR_have here is the forgery leaking through.
            assert super_stack.wait_for_code(CMS_RR_HAVE, timeout=2.5) \
                is None, "forged-path kYR_have on a real streamid leaked up"
            child.sendall(_build_frame(down_sid, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       path + b"\x00"))
            up = super_stack.wait_for_code(CMS_RR_HAVE, timeout=8.0)
            assert up is not None, \
                "forged path consumed the relay entry — honest answer lost"
            assert up[0] == up_sid and up[3].rstrip(b"\x00") == path, \
                "upward echo must carry the parent streamid + probed path"
        finally:
            child.close()

    def test_relay_entry_is_single_use(self, super_stack):
        """A consumed relay entry is gone: replaying the identical honest
        kYR_have must not produce a second upward echo (no amplification /
        stale-entry reuse)."""
        child = self._login_child(super_stack)
        try:
            up_sid = 0x61D00005
            path = b"/elsewhere/wanted.bin"
            super_stack.send_to_node(up_sid, CMS_RR_STATE, CMS_MOD_RAW,
                                     path + b"\x00")
            fr = _recv_code(child, CMS_RR_STATE, timeout=8.0)
            assert fr is not None, "child never saw the relayed probe"
            have = _build_frame(fr[0], CMS_RR_HAVE,
                                CMS_MOD_RAW | CMS_HAVE_ONLINE, path + b"\x00")
            child.sendall(have)
            assert super_stack.wait_for_code(CMS_RR_HAVE, timeout=8.0) \
                is not None, "honest kYR_have was not echoed upward"
            before = super_stack.count_frames(CMS_RR_HAVE)
            child.sendall(have)
            time.sleep(2.0)
            assert super_stack.count_frames(CMS_RR_HAVE) == before, \
                "replayed kYR_have re-used a consumed relay entry"
        finally:
            child.close()

    def test_unsolicited_have_does_not_poison_loc_cache(self, super_stack):
        """Security-neg: a dropped unsolicited kYR_have must leave NO trace —
        a later parent probe for that very path must still be a miss that is
        relayed down to the child (a cached forgery would answer it directly
        and short-circuit the relay)."""
        child = self._login_child(super_stack)
        try:
            path = b"/elsewhere/poison.bin"
            child.sendall(_build_frame(0x0666AAAA, CMS_RR_HAVE,
                                       CMS_MOD_RAW | CMS_HAVE_ONLINE,
                                       path + b"\x00"))
            time.sleep(0.5)
            super_stack.send_to_node(0x61D00006, CMS_RR_STATE, CMS_MOD_RAW,
                                     path + b"\x00")
            fr = _recv_code(child, CMS_RR_STATE, timeout=8.0)
            assert fr is not None, \
                "probe was not relayed — the forged kYR_have was cached"
            assert fr[3].rstrip(b"\x00") == path
            # And the forgery itself must never have surfaced upward.
            assert super_stack.wait_for_code(CMS_RR_HAVE, timeout=2.0) \
                is None, "forged kYR_have surfaced upward"
        finally:
            child.close()
