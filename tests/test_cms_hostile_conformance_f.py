from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cms_hostile_conformance_helpers")
from test_cms_hostile_conformance_e import _SWEEP_CODES, _SWEEP_IDS, _SWEEP_GARBAGE

class TestFrameSizeBoundarySweep:
    """The exact dlen boundary on the accept leg.  dlen+8 <= 4096 (MAX_FRAME)
    is read-and-dropped in full (unknown opcode) with the connection intact;
    dlen+8 > 4096 closes only the offender.  Either way a fresh client is
    served."""

    # dlen values whose total frame (dlen+8) is <= 4096 -> ACCEPTED.
    ACCEPTED = [0, 1, 2, 7, 8, 9, 16, 64, 255, 256, 1000, 2048,
                4080, 4086, 4087, 4088]
    # dlen values whose total frame (dlen+8) is > 4096 -> offender CLOSED.
    REJECTED = [4089, 4090, 5000, 8000, 16000, 32000, 65535]

    @pytest.mark.parametrize("dlen", ACCEPTED, ids=[str(d) for d in ACCEPTED])
    def test_accepted_dlen_read_in_full(self, sweep_server, dlen):
        sock = socket.create_connection((H, sweep_server.port), timeout=6)
        sock.settimeout(6)
        try:
            frame = _build_frame(_SID | 0x11, 0x7E, 0, b"\x00" * dlen)
            assert len(frame) == dlen + 8 <= 4096
            sock.sendall(frame)
            # Same connection must still answer -> the frame was consumed whole
            # and framer alignment is preserved.
            sock.sendall(_build_frame(_SID | 0x12, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                f"accepted dlen {dlen} broke framer alignment"
        finally:
            sock.close()

    @pytest.mark.parametrize("dlen", REJECTED, ids=[str(d) for d in REJECTED])
    def test_rejected_dlen_closes_only_offender(self, sweep_server, dlen):
        bad = socket.create_connection((H, sweep_server.port), timeout=6)
        bad.settimeout(6)
        try:
            # Craft an 8-byte header advertising an over-cap dlen and send ONLY
            # the header — the server rejects on the length word, before the
            # (never-sent) body, so it must close without waiting for bytes.
            hdr = ((_SID | 0x13).to_bytes(4, "big") + bytes([0x7E, 0])
                   + dlen.to_bytes(2, "big"))
            bad.sendall(hdr)
            assert _recv_exact(bad, 1) is None, \
                f"over-cap dlen {dlen} did not close the offender"
            assert _server_alive(sweep_server.port), \
                f"over-cap dlen {dlen} disturbed the accept leg"
        finally:
            bad.close()


class TestNodeLegOpcodeMatrix:
    """Every opcode, with a garbage payload, thrown by a hostile manager DOWN
    the upward leg into the node.  The node must never hang: the manager leg
    keeps answering kYR_ping, tolerating a DISC-forced reconnect."""

    @pytest.mark.parametrize("code", _SWEEP_CODES, ids=_SWEEP_IDS)
    def test_manager_opcode_garbage_keeps_node_alive(self, sweep_node, code):
        try:
            sweep_node.send_to_node(_SID | code, code, 0, _SWEEP_GARBAGE)
        except (AssertionError, OSError):
            pass   # a prior DISC may have the socket mid-reconnect
        assert _node_survives(sweep_node), \
            f"manager opcode 0x{code:02x} wedged the node's upward leg"


class TestNodeStatePathCorpus:
    """A broad corpus of adversarial kYR_state paths, every one of which MUST
    draw NO kYR_have from a data node whose only resident file is
    /have_me.bin: parent-traversal, non-absolute, absolute-outside-export,
    control-byte, oversized, and near-miss paths.  brix_stat_beneath resolves
    under the export rootfd with RESOLVE_BENEATH and cms_state_extract_path
    rejects ``..``/relative/oversized before any syscall."""

    CORPUS = [
        # parent traversal (cms_state_extract_path rejects any "..")
        ("dotdot_etc", b"/../etc/passwd"),
        ("dotdot_deep", b"/a/../../etc/passwd"),
        ("dotdot_bare", b"/.."),
        ("dotdot_trail", b"/../"),
        ("dotdot_mid", b"/foo/../bar"),
        ("dotdot_multi", b"/x/../../../../root"),
        # absolute, but outside the export root (stat_beneath miss)
        ("etc_passwd", b"/etc/passwd"),
        ("etc_shadow", b"/etc/shadow"),
        ("proc_maps", b"/proc/self/maps"),
        ("dev_zero", b"/dev/zero"),
        ("root_ssh", b"/root/.ssh/id_rsa"),
        ("bin_sh", b"/bin/sh"),
        ("var_log", b"/var/log/syslog"),
        ("sys_kernel", b"/sys/kernel/notes"),
        ("home_bashrc", b"/home/someone/.bashrc"),
        ("double_slash_foreign", b"//etc/passwd"),
        # near-miss / nonexistent under the root
        ("nonexistent", b"/nonexistent/deep/path.bin"),
        ("near_miss", b"/have_me.binX"),
        ("case_flip", b"/HAVE_ME.BIN"),
        ("trailing_slash", b"/have_me.bin/"),
        # control / high bytes (miss)
        ("ctrl_bytes", b"/\x01\x02\x03"),
        ("newline", b"/foo\nbar"),
        ("tab", b"/foo\tbar"),
        ("high_bytes", b"/\xff\xfe\xfd"),
        # oversized (extract_path pl >= buffer -> reject)
        ("oversized", b"/" + b"z" * 1500),
        # non-absolute (payload[0] != '/')
        ("relative_file", b"have_me.bin"),
        ("relative_dir", b"foo/bar"),
        ("bare_token", b"x"),
    ]

    @pytest.mark.parametrize("path", [p for _, p in CORPUS],
                             ids=[n for n, _ in CORPUS])
    def test_adversarial_state_path_draws_no_have(self, sweep_node, path):
        base = sweep_node.count_frames(CMS_RR_HAVE)
        sweep_node.send_to_node(_SID | 0x5A, CMS_RR_STATE, CMS_MOD_RAW,
                                path + b"\x00")
        time.sleep(0.6)   # give any (wrongly) generated kYR_have time to land
        assert _node_alive(sweep_node), \
            "the node's upward leg died after an adversarial state probe"
        assert sweep_node.count_frames(CMS_RR_HAVE) == base, \
            "an adversarial state path forged a kYR_have (confinement escape)"


# ===========================================================================
# Second-wave deep-fuzz sweeps — the header modifier/streamid space, the frame
# re-assembly + pipelining paths, the LOGIN and load/avail TLV parsers, and the
# node-leg forwarded-op / redirect-injection / state-path corpora, all widened
# to hundreds of adversarial cases.  Same invariant as above: after every
# hostile frame the *other* side must still be served (server leg) or the
# upward leg must still answer (node leg).  Reuses the two module-scoped sweep
# instances so the whole second wave runs against one process per leg.
# ===========================================================================

# --- header modifier / streamid corpora ------------------------------------

# kYR_status reads the modifier as a suspend/resume/reset/stage/nostage bitset;
# sweeping the whole low-6-bit space covers every bit combination the handler
# branches on.  An unknown bit is a stock no-op, never a close (verified:
# TestServerLegEsotericOps.test_status_garbage_modifier_is_noop).
_STATUS_MODS = list(range(64))

# kYR_stats reads the modifier for the CMS_STATS_SIZE form; a full byte sweep
# (paired with the size bit) must never crash the encoder.
_STATS_MODS = list(range(32))

# Streamids that stress signedness / truncation / high-bit handling.  The
# server's do_Ping replies with a static streamid-0 pong, so the property is
# "accepted + not mis-framed", asserted by a pong coming back at all.
_STREAMIDS = [
    0x00000000, 0x00000001, 0x00000002, 0x000000FF, 0x00000100, 0x00000101,
    0x00007FFF, 0x00008000, 0x0000FFFF, 0x00010000, 0x00FF00FF, 0x0100_0000,
    0x7FFFFFFF, 0x80000000, 0x80000001, 0xC0000000, 0xDEADBEEF, 0xF0F0F0F0,
    0xFFFF0000, 0x0000FFFE, 0xFFFFFFFE, 0xFFFFFFFF, 0xABAD1DEA, 0x40C50000,
]


class TestServerModifierByteSweep:
    """Every low-band kYR_status modifier and kYR_stats modifier, one at a time
    on a single logged-in link, each re-proving the *same* connection stays
    frame-aligned and answers a ping — the header modifier byte can never
    desync the parser or crash the handler."""

    @pytest.fixture(scope="class")
    def status_link(self, sweep_server):
        sock = _login_server(sweep_server.port)
        try:
            yield sock
        finally:
            sock.close()

    @pytest.mark.parametrize("mod", _STATUS_MODS, ids=[str(m) for m in _STATUS_MODS])
    def test_status_modifier_keeps_link_aligned(self, status_link, mod):
        status_link.sendall(_build_frame(0, CMS_RR_STATUS, mod))
        status_link.sendall(_build_frame(_SID | 0x90, CMS_RR_PING, 0))
        assert _recv_code(status_link, CMS_RR_PONG, timeout=6) is not None, \
            f"kYR_status modifier {mod} desynced the link"

    @pytest.mark.parametrize("mod", _STATS_MODS, ids=[str(m) for m in _STATS_MODS])
    def test_stats_modifier_no_crash(self, sweep_server, mod):
        sock = _login_server(sweep_server.port)
        try:
            sock.sendall(_build_frame(_SID | 0x91, CMS_RR_STATS,
                                      mod | CMS_STATS_SIZE))
            time.sleep(0.05)
        finally:
            sock.close()
        assert _server_alive(sweep_server.port), \
            f"kYR_stats modifier {mod} crashed the accept leg"


class TestServerStreamidSweep:
    """A ping at each adversarial streamid is parsed without a signedness or
    truncation bug and answered — the 32-bit streamid word is treated as the
    unsigned wire value throughout."""

    @pytest.mark.parametrize("sid", _STREAMIDS,
                             ids=["0x%08x" % s for s in _STREAMIDS])
    def test_extreme_streamid_ping_answered(self, sweep_server, sid):
        sock = socket.create_connection((H, sweep_server.port), timeout=6)
        sock.settimeout(6)
        try:
            sock.sendall(_build_frame(sid, CMS_RR_PING, 0))
            fr = _recv_code(sock, CMS_RR_PONG, timeout=6)
            assert fr is not None, f"streamid 0x{sid:08x} ping was not answered"
        finally:
            sock.close()


# --- fragmentation / pipelining --------------------------------------------

# A composite buffer: an unknown-opcode junk frame (dropped) immediately
# followed by a real ping (answered).  Splitting it at every interesting offset
# proves the accumulator reassembles a header/body straddling a recv() edge and
# never mis-frames the trailing ping.
_FRAG_BASE = (_build_frame(_SID | 0x7C, 0x7E, 0, bytes(16))
              + _build_frame(_SID | 0x7D, CMS_RR_PING, 0))
_FRAG_OFFSETS = [1, 2, 3, 4, 7, 8, 9, 12, 16, 20, 23, 24, 25, 28, 30, 31]

# Pipeline depths spanning the 64-frame fairness batch boundary and well beyond.
_PIPELINE_NS = [1, 2, 3, 4, 8, 16, 31, 32, 33, 48, 63, 64, 65, 96, 128, 192,
                256, 384, 512]


class TestServerFragmentationSweep:
    """The junk+ping composite split at every interesting byte offset — each a
    fresh connection — must always drop the junk and answer the ping,
    reassembling across the segment boundary."""

    @pytest.mark.parametrize("off", _FRAG_OFFSETS, ids=[str(o) for o in _FRAG_OFFSETS])
    def test_split_frame_reassembled(self, sweep_server, off):
        sock = socket.create_connection((H, sweep_server.port), timeout=6)
        sock.settimeout(6)
        try:
            sock.sendall(_FRAG_BASE[:off])
            time.sleep(0.05)
            sock.sendall(_FRAG_BASE[off:])
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                f"a frame split at offset {off} was not reassembled"
        finally:
            sock.close()


class TestServerPipeliningSweep:
    """N back-to-back ping frames in a single write must draw exactly N pongs —
    no frame dropped at the 64-per-wakeup fairness boundary, all excess
    reassembled across subsequent wakeups."""

    @pytest.mark.parametrize("n", _PIPELINE_NS, ids=[str(n) for n in _PIPELINE_NS])
    def test_pipelined_pings_all_answered(self, sweep_server, n):
        sock = socket.create_connection((H, sweep_server.port), timeout=8)
        sock.settimeout(8)
        try:
            sock.sendall(b"".join(
                _build_frame(_SID | (i & 0xFFFF), CMS_RR_PING, 0)
                for i in range(n)))
            got = 0
            for _ in range(n):
                if _recv_code(sock, CMS_RR_PONG, timeout=8) is None:
                    break
                got += 1
            assert got == n, f"pipelined {n} pings drew only {got} pongs"
        finally:
            sock.close()


# --- LOGIN + load/avail TLV parser fuzz ------------------------------------

_GOOD_LOGIN = _minimal_login_payload(NODE_DATA_PORT, b"r /data")
_LOGIN_FUZZ = [
    ("empty", b""),
    ("one_byte", b"\x00"),
    ("short2", b"\x80\x00"),
    ("short3", b"\xa0\x00\x00"),
    ("tag_short_only", bytes([CMS_PT_SHORT])),
    ("tag_int_only", bytes([CMS_PT_INT])),
    ("badtag0_8", b"\x00" * 8),
    ("badtagff_8", b"\xff" * 8),
    ("ff16", b"\xff" * 16),
    ("ff64", b"\xff" * 64),
    ("ff300", b"\xff" * 300),
    ("zero16", b"\x00" * 16),
    ("zero64", b"\x00" * 64),
    ("zero300", b"\x00" * 300),
    ("rand31", bytes(range(31))),
    ("rand200", bytes((i * 7) & 0xFF for i in range(200))),
] + [("trunc_%d" % n, _GOOD_LOGIN[:n])
     for n in (2, 4, 6, 9, 13, 17, 21, 27, 33, 41, 55, len(_GOOD_LOGIN) - 1)] + [
    ("good_tail_junk", _GOOD_LOGIN + b"\xff" * 24),
    ("good_tail_zeros", _GOOD_LOGIN + b"\x00" * 512),
]

_TLV_FUZZ = [
    ("empty", b""),
    ("short_tag", bytes([CMS_PT_SHORT])),
    ("int_tag", bytes([CMS_PT_INT])),
    ("short_partial", bytes([CMS_PT_SHORT, 0x00])),
    ("int_partial1", bytes([CMS_PT_INT, 0x00])),
    ("int_partial3", bytes([CMS_PT_INT, 0x00, 0x00, 0x00])),
    ("bad_tag_00", b"\x00\x00\x00"),
    ("bad_tag_ff", b"\xff\xff\xff\xff"),
    ("bad_tag_7f", b"\x7f\x11\x22"),
    ("short_max", bytes([CMS_PT_SHORT, 0xFF, 0xFF])),
    ("int_max", bytes([CMS_PT_INT]) + b"\xff\xff\xff\xff"),
    ("count_then_trunc", bytes([CMS_PT_SHORT, 0x00, 0x06]) + b"\x00" * 6
     + bytes([CMS_PT_SHORT, 0xFF, 0xFF])),
    ("only_cpu", bytes([CMS_PT_SHORT, 0x00, 0x06]) + b"\x11" * 6),
    ("cpu_trunc", bytes([CMS_PT_SHORT, 0x00, 0x06]) + b"\x11" * 3),
    ("double_int", bytes([CMS_PT_INT]) + b"\x00\x00\x27\x10"
     + bytes([CMS_PT_INT]) + b"\x00\x00\x00\x0a"),
    ("nested_tags", bytes([CMS_PT_SHORT, CMS_PT_INT, CMS_PT_SHORT])),
    ("ff32", b"\xff" * 32),
    ("zeros32", b"\x00" * 32),
    ("rand40", bytes((i * 13) & 0xFF for i in range(40))),
    ("alt_tags", bytes(CMS_PT_SHORT if i % 2 else CMS_PT_INT
                       for i in range(20))),
    ("short_then_int_trunc", bytes([CMS_PT_SHORT, 0x00, 0x03, CMS_PT_INT, 0x00])),
    ("giant_short_run", bytes([CMS_PT_SHORT]) * 100),
    ("giant_int_run", bytes([CMS_PT_INT]) * 100),
    ("one_byte", b"\x2a"),
]


class TestServerLoginFuzzSweep:
    """A broad corpus of malformed CmsLoginData payloads on the accept leg.
    Each may cost the offender its own connection, but the accept leg must keep
    serving a fresh, well-behaved client — a hostile login can never wedge the
    single worker."""

    @pytest.mark.parametrize("payload", [p for _, p in _LOGIN_FUZZ],
                             ids=[n for n, _ in _LOGIN_FUZZ])
    def test_malformed_login_keeps_server_alive(self, sweep_server, payload):
        try:
            bad = _node_login_dialog(sweep_server.port, payload)
        except OSError:
            # even the connect/handshake failing is fine — what matters is the
            # server still serves others.
            assert _server_alive(sweep_server.port)
            return
        try:
            time.sleep(0.05)
            assert _server_alive(sweep_server.port), \
                "a malformed login took the accept leg down for other clients"
        finally:
            bad.close()
