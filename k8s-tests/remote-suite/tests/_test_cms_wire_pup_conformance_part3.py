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
            _send_fragments(sock, frame, 3)
            time.sleep(0.5)
            sock.setblocking(False)
            assert not _socket_closed(sock), \
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
        _remove_dir_if_present(made)
        node_stack.send_to_node(101, CMS_RR_MKDIR, 0,
                                _fwd_a_payload(b"mgr", b"755", b"/fwd_made"))
        assert _await_directory(made), "node did not create the forwarded directory"
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


def _send_fragments(sock, frame, step):
    for offset in range(0, len(frame), step):
        sock.sendall(frame[offset:offset + step])
        time.sleep(0.02)


def _socket_closed(sock):
    try:
        return sock.recv(1) == b""
    except (BlockingIOError, InterruptedError, OSError):
        return False


def _remove_dir_if_present(path):
    if os.path.isdir(path):
        os.rmdir(path)


def _await_directory(path):
    deadline = time.time() + 6.0
    while time.time() < deadline:
        if os.path.isdir(path):
            return True
        time.sleep(0.1)
    return os.path.isdir(path)
