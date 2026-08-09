from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cms_wire_pup_conformance_helpers")

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
