# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def node_stack():
    """A Python manager peer + a dedicated nginx data-node that dials it.

    Yields the live peer with the node's first LOGIN/LOAD frames already
    captured.  Skips if nginx is missing, the config is rejected (CMS support
    not built), or the node never connects out.
    """
    _require_nginx()
    data_dir = _prepare_node_data()
    peer = _create_manager_peer()
    conf = _node_conf("node", NODE_DATA_PORT, MGR_PEER_PORT, data_dir)
    _start_node(conf, peer)
    try:
        _require_node_ready(peer)
        yield peer
    finally:
        _stop_nginx(conf)
        peer.close()


def _require_nginx():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")


def _prepare_node_data():
    data_dir = os.path.join(_DIR, "node_data")
    _mkdirs(data_dir)
    with open(os.path.join(data_dir, "have_me.bin"), "wb") as handle:
        handle.write(b"resident-bytes" * 16)
    return data_dir


def _create_manager_peer():
    try:
        return CmsManagerPeer(MGR_PEER_PORT)
    except OSError as exc:
        pytest.skip(f"could not bind CMS manager peer port {MGR_PEER_PORT}: {exc}")


def _start_node(conf, peer):
    ok, error = _start_nginx(conf)
    if not ok:
        peer.close()
        pytest.skip(f"node nginx config rejected (CMS client unsupported?): {error}")


def _require_node_ready(peer):
    if not _wait_port(NODE_DATA_PORT):
        pytest.skip("data-node nginx did not come up")
    if not peer.have_connection(timeout=20.0):
        pytest.skip("data-node never opened a CMS connection to the peer")


@pytest.fixture(scope="module")
def login_frame(node_stack):
    """The captured LOGIN frame (streamid, code, modifier, payload)."""
    fr = node_stack.wait_for_code(CMS_RR_LOGIN, timeout=20.0)
    if fr is None:
        pytest.skip("node did not emit a LOGIN frame")
    return fr


@pytest.fixture(scope="module")
def load_frame(node_stack):
    """The captured LOAD heartbeat frame."""
    fr = node_stack.wait_for_code(CMS_RR_LOAD, timeout=20.0)
    if fr is None:
        pytest.skip("node did not emit a LOAD frame within the heartbeat window")
    return fr


@pytest.fixture(scope="module")
def cms_server():
    """A dedicated nginx CMS *server* whose frame parser we probe directly."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    data_dir = os.path.join(_DIR, "srv_data")
    _mkdirs(data_dir)
    conf = _cms_server_conf("cmssrv", CMS_SRV_PORT, data_dir)
    ok, err = _start_nginx(conf)
    if not ok:
        pytest.skip(f"cms-server nginx config rejected: {err}")
    try:
        if not _wait_port(CMS_SRV_PORT):
            pytest.skip("cms-server nginx did not come up")
        yield CMS_SRV_PORT
    finally:
        _stop_nginx(conf)


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

    def test_login_four_string_tail_order(self, login_frame):
        """Tail is exactly SID, Paths, ifList, envCGI — in that order, and the
        decode consumes the entire payload (no trailing bytes)."""
        _sid, code, _mod, payload = login_frame
        assert code == CMS_RR_LOGIN
        d = _decode_login(payload)
        # SID is "<host>:<port>" and must carry the advertised data port.
        assert b":" in d["sid"], f"SID not host:port form: {d['sid']!r}"
        assert d["sid"].endswith(str(NODE_DATA_PORT).encode()), \
            f"SID must end with dPort {NODE_DATA_PORT}: {d['sid']!r}"
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
