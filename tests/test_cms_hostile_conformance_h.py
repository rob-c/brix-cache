from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cms_hostile_conformance_helpers")
from test_cms_hostile_conformance_e import _SWEEP_OPS, _SWEEP_GARBAGE
from test_cms_hostile_conformance_f import _STREAMIDS
from test_cms_hostile_conformance_g import _GONE_PATHS

class TestServerGonePathCorpus:
    """kYR_gone for every adversarial path -- an unheld gone is a bounded no-op
    that leaves the connection aligned and answering a ping."""

    @pytest.fixture(scope="class")
    def gone_link(self, sweep_server):
        sock = _login_server(sweep_server.port, paths=b"r /data")
        try:
            yield sock
        finally:
            sock.close()

    @pytest.mark.parametrize("path", [p for _, p in _GONE_PATHS],
                             ids=[n for n, _ in _GONE_PATHS])
    def test_gone_path_keeps_link_aligned(self, gone_link, path):
        body = (path + b"\x00") if path else b""
        gone_link.sendall(_build_frame(_SID | 0xF0, CMS_RR_GONE, 0, body))
        gone_link.sendall(_build_frame(_SID | 0xF1, CMS_RR_PING, 0))
        assert _recv_code(gone_link, CMS_RR_PONG, timeout=6) is not None, \
            "a kYR_gone for an adversarial path desynced the accept leg"


# kYR_error frames the manager may receive from a child: every ecode x text
# length is logged/dropped without a bound-read past the payload.
_ERR_CASES = [(ec, tl) for ec in (0, 1, 22, 0xDEADBEEF)
              for tl in (0, 1, 16, 100, 1000, 3000)]


class TestServerErrorFrameCorpus:
    """A received kYR_error (RSP_ERROR) with each ecode / text length is
    consumed exactly, never over-read; the connection stays aligned."""

    @pytest.fixture(scope="class")
    def err_link(self, sweep_server):
        sock = _login_server(sweep_server.port, paths=b"r /data")
        try:
            yield sock
        finally:
            sock.close()

    @pytest.mark.parametrize("ecode,tlen", _ERR_CASES,
                             ids=["e%08x_t%d" % (ec, tl) for ec, tl in _ERR_CASES])
    def test_error_frame_keeps_link_aligned(self, err_link, ecode, tlen):
        payload = ecode.to_bytes(4, "big") + b"E" * tlen
        err_link.sendall(_build_frame(_SID | 0xE8, CMS_RSP_ERROR, 0, payload))
        err_link.sendall(_build_frame(_SID | 0xE9, CMS_RR_PING, 0))
        assert _recv_code(err_link, CMS_RR_PONG, timeout=6) is not None, \
            "a received kYR_error (ecode 0x%08x, %d text bytes) desynced the " \
            "accept leg" % (ecode, tlen)


# Interleave-resync: a valid ping, then ONE arbitrary opcode frame carrying a
# 16-byte body, then a second ping.  The framer must stay aligned across the
# interposed frame and answer the trailing ping.  DISC/XAUTH are excluded (they
# legitimately close the offender pre-login, which is a *different*, already
# covered, behaviour).
_RESYNC_OPS = [(n, c) for n, c in _SWEEP_OPS if n not in ("disc", "xauth")]


class TestServerInterleaveResyncMatrix:
    """A fresh connection: ping (answered) / one arbitrary opcode+body / ping.
    The second pong proves the accumulator resynced past the interposed frame
    -- no opcode can slide the framer out of alignment."""

    @pytest.mark.parametrize("name,code", _RESYNC_OPS,
                             ids=[n for n, _ in _RESYNC_OPS])
    def test_junk_between_pings_resyncs(self, sweep_server, name, code):
        sock = socket.create_connection((H, sweep_server.port), timeout=8)
        sock.settimeout(8)
        try:
            sock.sendall(_build_frame(_SID | 0xD0, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "the first ping was not answered"
            sock.sendall(_build_frame(_SID | 0xD1, code, 0, bytes(16)))
            sock.sendall(_build_frame(_SID | 0xD2, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "the framer failed to resync after an interleaved 0x%02x frame" % code
        finally:
            sock.close()


# Concurrent hostile storm: N simultaneous peers each running one attack, then a
# fresh honest client must still be admitted and answered.  This is the headline
# stock-cmsd failure this MITM removes -- one hostile peer (or a swarm) must
# never head-of-line-block the single worker.

class TestServerConcurrentStormMatrix:
    """N concurrent hostile peers (per attack) can never wedge the accept leg --
    a fresh client is admitted and answered while the storm is still open."""

    @pytest.mark.parametrize("name,attack,conc", _STORM_CASES,
                             ids=["%s_x%d" % (an, c) for an, _af, c in _STORM_CASES])
    def test_concurrent_hostile_storm_survived(self, sweep_server, name, attack, conc):
        socks = []
        try:
            for _ in range(conc):
                s = socket.create_connection((H, sweep_server.port), timeout=6)
                s.settimeout(4)
                try:
                    attack(s)
                except OSError:
                    pass   # e.g. oversized closes the offender mid-write
                socks.append(s)
            time.sleep(0.1)
            assert _server_alive(sweep_server.port), \
                "%d concurrent '%s' peers wedged the accept leg" % (conc, name)
        finally:
            for s in socks:
                try:
                    s.close()
                except OSError:
                    pass


# ===========================================================================
# NODE-LEG wave-3 classes -- appended LAST so the shared sweep_node is settled
# (never mid-DISC-reconnect from an earlier node barrage) when they start.
# ===========================================================================

# 12 modifier bytes down into the node's manager leg.
_NODE_MODS = [0, 1, 2, 3, 4, 8, 0x10, 0x40, 0x7F, 0x80, 0xC0, 0xFF]
_NODE_MOD_OPS = [
    ("state", CMS_RR_STATE), ("have", CMS_RR_HAVE), ("load", CMS_RR_LOAD),
    ("avail", CMS_RR_AVAIL), ("status", CMS_RR_STATUS), ("space", CMS_RR_SPACE),
]
_NODE_MOD_CASES = [(n, c, m) for n, c in _NODE_MOD_OPS for m in _NODE_MODS]


class TestNodeOpModifierMatrix:
    """Each manager-leg opcode, empty-bodied, swept across 12 modifier bytes
    DOWN into the node.  A weird modifier can never permanently hang up the
    node's upward leg (it survives, reconnecting if it must)."""

    @pytest.mark.parametrize("name,code,mod", _NODE_MOD_CASES,
                             ids=["%s_m%02x" % (n, m) for n, _c, m in _NODE_MOD_CASES])
    def test_node_op_modifier_survives(self, sweep_node, name, code, mod):
        try:
            sweep_node.send_to_node(_SID | 0xE0, code, mod)
        except (AssertionError, OSError, AttributeError):
            pass   # mid-reconnect window
        assert _node_survives(sweep_node), \
            "the node upward leg died after kYR_%s modifier 0x%02x" % (name, mod)


class TestNodeStreamidSweep:
    """A ping DOWN into the node at each adversarial streamid: the node parses
    the unsigned 32-bit word and keeps its upward leg alive."""

    @pytest.mark.parametrize("sid", _STREAMIDS, ids=["0x%08x" % s for s in _STREAMIDS])
    def test_node_extreme_streamid_survives(self, sweep_node, sid):
        try:
            sweep_node.send_to_node(sid, CMS_RR_PING, 0)
        except (AssertionError, OSError, AttributeError):
            pass
        assert _node_survives(sweep_node), \
            "the node upward leg died after a ping at streamid 0x%08x" % sid


# Downward flood: 120 back-to-back frames of one opcode (garbage-bodied) rained
# down on the node, then the upward manager ping must still be answered.  DISC is
# excluded (a DISC flood is a deliberate reconnect storm, covered elsewhere).
_FLOOD_OPS = [(n, c) for n, c in _SWEEP_OPS if n != "disc"]


class TestNodeDownwardFloodMatrix:
    """A 120-frame downward flood of each opcode can never wedge the node's
    upward leg -- the manager ping is answered after the barrage (through a
    reconnect if one was forced)."""

    @pytest.mark.parametrize("name,code", _FLOOD_OPS, ids=[n for n, _ in _FLOOD_OPS])
    def test_downward_flood_keeps_upward_leg(self, sweep_node, name, code):
        for i in range(120):
            try:
                sweep_node.send_to_node(_SID | (i & 0xFFFF), code, 0, _SWEEP_GARBAGE)
            except (AssertionError, OSError, AttributeError):
                break   # mid-reconnect; the survive check re-establishes below
        assert _node_survives(sweep_node), \
            "a 120-frame downward '%s' flood wedged the node's upward leg" % name


# ===========================================================================
# WAVE-4 full-byte exhaustive sweeps (+1280 -> >=2000 total): drive the modifier
# and opcode bytes across their ENTIRE 0..255 range on both legs.  No single byte
# value -- however esoteric or undefined -- may desync the framer, crash a
# handler, or hang up the proxy for the peer on the other side.  The four
# server-leg classes come first (giving the shared node time to settle after the
# wave-3 downward floods); the single node-leg class is appended LAST.
# ===========================================================================

_FULL_BYTE = list(range(256))
_BYTE_IDS = ["0x%02x" % b for b in _FULL_BYTE]


class TestServerStatusFullModifierSweep:
    """kYR_status across the ENTIRE modifier byte range on one logged-in link.
    The suspend/resume/reset/stage/nostage state machine -- and every undefined
    bit combination -- can never desync the framer nor stop the link answering a
    ping (a status update emits no reply, so the link stays balanced)."""

    @pytest.fixture(scope="class")
    def link(self, sweep_server):
        sock = _login_server(sweep_server.port, paths=b"r /data")
        try:
            yield sock
        finally:
            sock.close()

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_status_modifier_keeps_link_aligned(self, link, mod):
        link.sendall(_build_frame(_SID | 0x100, CMS_RR_STATUS, mod))
        link.sendall(_build_frame(_SID | 0x101, CMS_RR_PING, 0))
        assert _recv_code(link, CMS_RR_PONG, timeout=6) is not None, \
            "kYR_status modifier 0x%02x desynced the accept leg" % mod


class TestServerStateFullModifierSweep:
    """kYR_state (empty body) across the ENTIRE modifier byte range on one
    logged-in link.  The 0x80 raw-form bit and every other value select a parse
    form, but an empty body always fails path extraction and is dropped -- no
    modifier can close the connection or misframe the trailing ping."""

    @pytest.fixture(scope="class")
    def link(self, sweep_server):
        sock = _login_server(sweep_server.port, paths=b"r /data")
        try:
            yield sock
        finally:
            sock.close()

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_state_modifier_keeps_link_aligned(self, link, mod):
        link.sendall(_build_frame(_SID | 0x110, CMS_RR_STATE, mod))
        link.sendall(_build_frame(_SID | 0x111, CMS_RR_PING, 0))
        assert _recv_code(link, CMS_RR_PONG, timeout=6) is not None, \
            "kYR_state modifier 0x%02x desynced the accept leg" % mod


class TestServerHaveFullModifierSweep:
    """kYR_have for a foreign path across the ENTIRE modifier byte range on one
    logged-in link.  Every online/pending/raw bit combination advertises a path
    outside the peer's exports, so the paths-cover gate drops it (relay-take
    finds no entry) without desyncing the link."""

    @pytest.fixture(scope="class")
    def link(self, sweep_server):
        sock = _login_server(sweep_server.port, paths=b"r /data")
        try:
            yield sock
        finally:
            sock.close()

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_have_modifier_keeps_link_aligned(self, link, mod):
        link.sendall(_build_frame(_SID | 0x120, CMS_RR_HAVE, mod, b"/etc/passwd\x00"))
        link.sendall(_build_frame(_SID | 0x121, CMS_RR_PING, 0))
        assert _recv_code(link, CMS_RR_PONG, timeout=6) is not None, \
            "kYR_have modifier 0x%02x desynced the accept leg" % mod


class TestServerFullOpcodeByteSweep:
    """Every possible rrCode byte 0..255, garbage-bodied, on a fresh pre-login
    accept-leg connection.  The offender may be closed (malformed login, disc,
    out-of-sequence xauth, …) but a fresh client is ALWAYS served afterwards --
    no opcode byte can take the single worker down."""

    @pytest.mark.parametrize("code", _FULL_BYTE, ids=_BYTE_IDS)
    def test_opcode_byte_keeps_server_alive(self, sweep_server, code):
        junk = socket.create_connection((H, sweep_server.port), timeout=6)
        junk.settimeout(4)
        try:
            try:
                junk.sendall(_build_frame(_SID | code, code, 0, _SWEEP_GARBAGE))
            except OSError:
                pass   # offender may be torn down mid-write
            time.sleep(0.02)
            assert _server_alive(sweep_server.port), \
                "opcode byte 0x%02x took the accept leg down" % code
        finally:
            junk.close()


# --- node-leg full-byte sweep (appended LAST) ------------------------------

class TestNodeStateFullModifierSweep:
    """kYR_state (empty body) DOWN into the node across the ENTIRE modifier byte
    range.  No modifier value can permanently hang up the node's upward leg -- a
    manager ping is answered after every one (through a reconnect if forced)."""

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_node_state_modifier_survives(self, sweep_node, mod):
        try:
            sweep_node.send_to_node(_SID | 0x200, CMS_RR_STATE, mod)
        except (AssertionError, OSError, AttributeError):
            pass   # mid-reconnect window
        assert _node_survives(sweep_node), \
            "the node upward leg died after kYR_state modifier 0x%02x" % mod


# ===========================================================================
# WAVE-5 exhaustive full-byte + fine-grained sweeps (+2944 -> >=5000 total):
# carry the 0..255 modifier sweep across every remaining SILENT accept-leg op,
# add fine payload-length / frame-size / streamid / pipelining sweeps, and drive
# the full-byte modifier + opcode sweep across the node leg.  No byte value,
# body length, or pipeline depth may desync the framer or hang up either leg.
# Server-leg classes come first; node-leg classes are appended LAST.
# ===========================================================================
class TestServerLoadFullModifierSweep:
    """kYR_load (empty body) across the ENTIRE modifier byte range on one
    logged-in link -- a child load report is consumed as a bounded metric update
    for every modifier; the link keeps answering a ping."""

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_load_modifier_keeps_link_aligned(self, shared_srv_link, mod):
        shared_srv_link.sendall(_build_frame(_SID | 0x130, CMS_RR_LOAD, mod))
        shared_srv_link.sendall(_build_frame(_SID | 0x131, CMS_RR_PING, 0))
        assert _recv_code(shared_srv_link, CMS_RR_PONG, timeout=6) is not None, \
            "kYR_load modifier 0x%02x desynced the accept leg" % mod


class TestServerAvailFullModifierSweep:
    """kYR_avail (empty body) across the ENTIRE modifier byte range on one
    logged-in link -- a bounded free-space update for every modifier value."""

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_avail_modifier_keeps_link_aligned(self, shared_srv_link, mod):
        shared_srv_link.sendall(_build_frame(_SID | 0x134, CMS_RR_AVAIL, mod))
        shared_srv_link.sendall(_build_frame(_SID | 0x135, CMS_RR_PING, 0))
        assert _recv_code(shared_srv_link, CMS_RR_PONG, timeout=6) is not None, \
            "kYR_avail modifier 0x%02x desynced the accept leg" % mod


class TestServerGoneFullModifierSweep:
    """kYR_gone (empty body) across the ENTIRE modifier byte range on one
    logged-in link -- an unheld gone is a no-op for every modifier value."""

    @pytest.mark.parametrize("mod", _FULL_BYTE, ids=_BYTE_IDS)
    def test_gone_modifier_keeps_link_aligned(self, shared_srv_link, mod):
        shared_srv_link.sendall(_build_frame(_SID | 0x138, CMS_RR_GONE, mod))
        shared_srv_link.sendall(_build_frame(_SID | 0x139, CMS_RR_PING, 0))
        assert _recv_code(shared_srv_link, CMS_RR_PONG, timeout=6) is not None, \
            "kYR_gone modifier 0x%02x desynced the accept leg" % mod


class TestServerStatePayloadLengthSweep:
    """kYR_state carrying a foreign path truncated to every body length 0..255 --
    the path-length decode boundary is exercised finely.  A foreign path is
    always dropped (no relay entry, not covered) so the link stays a bounded
    no-op and answers a ping after each length."""

    @pytest.mark.parametrize("blen", _FULL_BYTE, ids=_BYTE_IDS)
    def test_state_body_length_keeps_link_aligned(self, shared_srv_link, blen):
        body = (b"/" + b"a" * 255)[:blen]
        shared_srv_link.sendall(_build_frame(_SID | 0x140, CMS_RR_STATE, CMS_MOD_RAW, body))
        shared_srv_link.sendall(_build_frame(_SID | 0x141, CMS_RR_PING, 0))
        assert _recv_code(shared_srv_link, CMS_RR_PONG, timeout=6) is not None, \
            "kYR_state body length %d desynced the accept leg" % blen


class TestServerFrameSizeFineSweep:
    """An unknown-opcode frame at every body length 0..255 is read in full and
    dropped with the connection intact -- the length accumulator handles every
    small dlen; the same link answers a ping after each."""

    @pytest.mark.parametrize("blen", _FULL_BYTE, ids=_BYTE_IDS)
    def test_unknown_frame_length_keeps_link_aligned(self, shared_srv_link, blen):
        shared_srv_link.sendall(_build_frame(_SID | 0x150, 0x7E, 0, bytes(blen)))
        shared_srv_link.sendall(_build_frame(_SID | 0x151, CMS_RR_PING, 0))
        assert _recv_code(shared_srv_link, CMS_RR_PONG, timeout=6) is not None, \
            "an unknown frame of body length %d desynced the accept leg" % blen


# 256 densely-spread 32-bit streamids (0x00000000, 0x01010101, ... 0xFFFFFFFF).
_DENSE_SIDS = [(b * 0x01010101) & 0xFFFFFFFF for b in range(256)]
