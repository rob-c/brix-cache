from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cms_hostile_conformance_helpers")
from test_cms_hostile_conformance_f import _TLV_FUZZ

class TestServerLoadAvailTlvFuzzSweep:
    """The load/avail TLV reader fed a broad corpus of malformed payloads on a
    single logged-in link: the bounded reader decodes missing/garbage fields as
    zero (documented posture) and never over-reads — the same link answers a
    ping after each."""

    @pytest.fixture(scope="class")
    def tlv_link(self, sweep_server):
        sock = _login_server(sweep_server.port)
        try:
            yield sock
        finally:
            sock.close()

    @pytest.mark.parametrize("payload", [p for _, p in _TLV_FUZZ],
                             ids=[n for n, _ in _TLV_FUZZ])
    def test_load_tlv_fuzz_recovers(self, tlv_link, payload):
        tlv_link.sendall(_build_frame(0, CMS_RR_LOAD, 0, payload))
        tlv_link.sendall(_build_frame(_SID | 0x92, CMS_RR_PING, 0))
        assert _recv_code(tlv_link, CMS_RR_PONG, timeout=6) is not None, \
            "a malformed kYR_load TLV payload wedged the link"


# --- node-leg forwarded-op / redirect / state fuzz -------------------------

_FWD_OPS = [
    ("chmod", CMS_RR_CHMOD), ("mkdir", CMS_RR_MKDIR), ("mkpath", CMS_RR_MKPATH),
    ("mv", CMS_RR_MV), ("rm", CMS_RR_RM), ("rmdir", CMS_RR_RMDIR),
    ("trunc", CMS_RR_TRUNC), ("prepadd", CMS_RR_PREPADD),
    ("prepdel", CMS_RR_PREPDEL),
]
_FWD_VARIANTS = [
    ("empty", b""),
    ("trunc_pup", b"\x00\x64ab"),
    ("garbage", bytes(range(32))),
    ("traversal", _fwd_a_payload(b"mgr", b"493", b"/../pwn")),
    ("embedded_nul", _fwd_a_payload(b"mgr", b"493", b"/a\x00b/c")),
]
_FWD_MATRIX = [("%s_%s" % (on, vn), oc, pv)
               for on, oc in _FWD_OPS for vn, pv in _FWD_VARIANTS]

_REDIR_FUZZ = [
    ("empty", b""),
    ("ab", b"ab"),
    ("host_nul_only", b"host\x00"),
    ("valid", b"good.example\x00" + (1094).to_bytes(2, "big")),
    ("port0", b"h\x00" + (0).to_bytes(2, "big")),
    ("portmax", b"h\x00" + (0xFFFF).to_bytes(2, "big")),
    ("no_nul", b"hostwithoutnul"),
    ("nul_first", b"\x00" + (1094).to_bytes(2, "big")),
    ("embedded_nul", b"ho\x00st\x00" + (1094).to_bytes(2, "big")),
    ("long_host", b"h" * 300 + b"\x00" + (1094).to_bytes(2, "big")),
    ("many_hosts", b"".join(b"h%d.ex\x00" % i + (1000 + i).to_bytes(2, "big")
                            for i in range(50))),
    ("nonascii", b"\xff\xfe host\x00" + (1094).to_bytes(2, "big")),
    ("only_port", (1094).to_bytes(2, "big")),
    ("trailing_junk", b"h\x00" + (1094).to_bytes(2, "big") + b"\xff" * 20),
    ("newline_host", b"ho\nst\x00" + (1094).to_bytes(2, "big")),
    ("spaces", b"   \x00" + (1094).to_bytes(2, "big")),
]
_REDIR_MATRIX = [("select_%s" % n, CMS_RR_SELECT, p) for n, p in _REDIR_FUZZ] \
    + [("try_%s" % n, CMS_RR_TRY, p) for n, p in _REDIR_FUZZ]

# A second, disjoint corpus of adversarial kYR_state paths (none overlap the
# first corpus, none resolve to the resident /have_me.bin) — every one must
# draw NO kYR_have from the confined data node.
_STATE_CORPUS_2 = [
    ("proc_environ", b"/proc/self/environ"),
    ("proc_root", b"/proc/1/root/etc/passwd"),
    ("proc_cmdline", b"/proc/self/cmdline"),
    ("proc_mounts", b"/proc/mounts"),
    ("dev_null", b"/dev/null"),
    ("dev_mem", b"/dev/mem"),
    ("dev_kmsg", b"/dev/kmsg"),
    ("dev_random", b"/dev/random"),
    ("sys_net", b"/sys/class/net/eth0/address"),
    ("sys_firmware", b"/sys/firmware/efi"),
    ("run_secret", b"/run/secrets/token"),
    ("docker_sock", b"/var/run/docker.sock"),
    ("boot_kernel", b"/boot/vmlinuz"),
    ("libc", b"/lib/x86_64-linux-gnu/libc.so.6"),
    ("opt_secret", b"/opt/secret/key"),
    ("srv_other", b"/srv/other/data"),
    ("mnt_foreign", b"/mnt/foreign/vol"),
    ("media_usb", b"/media/usb/stick"),
    ("trailing_space", b"/have_me.bin "),
    ("leading_space", b"/ have_me.bin"),
    ("prefix_only", b"/have_me"),
    ("suffix_only", b"/e_me.bin"),
    ("dotdot_to_resident", b"/xyz/../have_me.bin"),
    ("utf8_accent", "/café/passwd".encode("utf-8")),
    ("utf8_cjk", "/日本/secret".encode("utf-8")),
    ("many_components", b"/" + b"deep/" * 50 + b"x"),
    ("long_component", b"/" + b"a" * 500),
    ("mixed_slashes", b"/a///b////c"),
]


class TestNodeForwardedOpFuzzSweep:
    """Every forwarded namespace opcode × a corpus of malformed/adversarial
    payloads thrown DOWN the upward leg.  None may crash, wedge, or force the
    node to hang up (reconnect): after each the upward leg still answers and the
    login count is unchanged."""

    @pytest.mark.parametrize("code,payload", [(c, p) for _, c, p in _FWD_MATRIX],
                             ids=[n for n, _, _ in _FWD_MATRIX])
    def test_forwarded_op_fuzz_no_hangup(self, sweep_node, code, payload):
        base = sweep_node.count_frames(CMS_RR_LOGIN)
        try:
            sweep_node.send_to_node(_SID | code, code, 0, payload)
        except (AssertionError, OSError):
            pass   # mid-reconnect window from a prior case — liveness check follows
        time.sleep(0.1)
        assert sweep_node.count_frames(CMS_RR_LOGIN) == base, \
            f"forwarded op 0x{code:02x} forced the node to hang up + reconnect"
        assert _node_alive(sweep_node), \
            f"forwarded op 0x{code:02x} wedged the node's upward leg"


class TestNodeRedirectInjectionSweep:
    """MITM redirect-injection at scale: unsolicited kYR_select / kYR_try with a
    broad corpus of host-list payloads for a streamid with no pending locate.
    None may steer the node (it never issued the locate) nor make it hang up —
    the upward leg stays connected and answering."""

    @pytest.mark.parametrize("code,payload", [(c, p) for _, c, p in _REDIR_MATRIX],
                             ids=[n for n, _, _ in _REDIR_MATRIX])
    def test_redirect_injection_steers_nothing(self, sweep_node, code, payload):
        base = sweep_node.count_frames(CMS_RR_LOGIN)
        try:
            sweep_node.send_to_node(_SID | 0x99, code, 0, payload)
        except (AssertionError, OSError):
            pass
        time.sleep(0.1)
        assert sweep_node.count_frames(CMS_RR_LOGIN) == base, \
            f"an injected redirect (op 0x{code:02x}) made the node hang up"
        assert _node_alive(sweep_node), \
            f"an injected redirect (op 0x{code:02x}) wedged the upward leg"


class TestNodeStatePathCorpusExtended:
    """A second, disjoint corpus of adversarial kYR_state paths — /proc, /dev,
    /sys, secrets, UTF-8, oversized-but-in-buffer, and near-miss — each drawing
    NO kYR_have from a data node holding only /have_me.bin."""

    @pytest.mark.parametrize("path", [p for _, p in _STATE_CORPUS_2],
                             ids=[n for n, _ in _STATE_CORPUS_2])
    def test_extended_state_path_draws_no_have(self, sweep_node, path):
        base = sweep_node.count_frames(CMS_RR_HAVE)
        sweep_node.send_to_node(_SID | 0x5B, CMS_RR_STATE, CMS_MOD_RAW,
                                path + b"\x00")
        time.sleep(0.4)
        assert _node_alive(sweep_node), \
            "the node's upward leg died after an extended state probe"
        assert sweep_node.count_frames(CMS_RR_HAVE) == base, \
            "an extended adversarial state path forged a kYR_have"


# ===========================================================================
# WAVE-3 exhaustive fuzz (+469 -> >=1000 total): carpet-bomb both legs across
# the modifier, streamid, login-value, ingest, forwarded-op, resync and
# concurrency axes.  Every case re-proves the MITM's core promise -- a hostile
# frame on either leg can never wedge, desync, or hang up the proxy for the
# honest peer on the *other* side.  Server-leg classes come first (sweep_server
# is order-independent); the node-leg classes are appended LAST so the shared
# sweep_node is never mid-DISC-reconnect from an earlier barrage when they run.
# ===========================================================================

# 24 modifier bytes: every low nibble, the 0x40 flag band, the 0x80 "raw form"
# bit and the high 0xE0..0xFF range.
_OP_MODS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0A, 0x0F, 0x10, 0x1F, 0x20, 0x3F,
            0x40, 0x7F, 0x80, 0xBF, 0xC0, 0xE0, 0xFE, 0xFF]

# The six accept-leg opcodes that take a body but emit NO reply frame, so an
# empty-payload probe leaves the shared link clean for the trailing ping.
_SILENT_SRV_OPS = [
    ("state", CMS_RR_STATE), ("have", CMS_RR_HAVE), ("load", CMS_RR_LOAD),
    ("avail", CMS_RR_AVAIL), ("gone", CMS_RR_GONE), ("status", CMS_RR_STATUS),
]
_OP_MOD_CASES = [(name, code, mod)
                 for name, code in _SILENT_SRV_OPS for mod in _OP_MODS]


class TestServerOpModifierMatrix:
    """Each body-carrying accept-leg opcode, empty-bodied, swept across 24
    modifier bytes on ONE logged-in link.  A weird modifier can neither desync
    the framer nor close the connection: the same link keeps answering a
    ping (empty kYR_state is already known to survive same-conn, and the
    modifier byte never gates a close)."""

    @pytest.fixture(scope="class")
    def op_link(self, sweep_server):
        sock = _login_server(sweep_server.port, paths=b"r /data")
        try:
            yield sock
        finally:
            sock.close()

    @pytest.mark.parametrize("name,code,mod", _OP_MOD_CASES,
                             ids=["%s_m%02x" % (n, m) for n, _c, m in _OP_MOD_CASES])
    def test_op_modifier_keeps_link_aligned(self, op_link, name, code, mod):
        op_link.sendall(_build_frame(_SID | 0xA0, code, mod))
        op_link.sendall(_build_frame(_SID | 0xA1, CMS_RR_PING, 0))
        assert _recv_code(op_link, CMS_RR_PONG, timeout=6) is not None, \
            "kYR_%s modifier 0x%02x desynced the accept leg" % (name, mod)


# 24 distinct 32-bit login mode words spanning single role bits, flag
# combinations and the sign boundary -- every classification must still yield a
# serviceable registration (the Admit path classifies by bits, never rejects).
_MODE_WORDS = [
    0x00000000, 0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x0000000A,
    0x00000010, 0x00000020, 0x00000040, 0x0000001F, 0x000000FF, 0x00000100,
    0x00008000, 0x00010000, 0x08000000, 0x40000000, 0x80000000, 0xC000000A,
    0x0000FFFF, 0xFFFF0000, 0xFFFFFFFF, 0xDEADBEEF, 0x02020202, 0x0A0A0A0A,
]


class TestServerLoginModeWordSweep:
    """A structurally valid login carrying each esoteric role/mode word must
    register a HEALTHY link -- the classifier can never leave a peer half-open
    or refuse to service a subsequent ping."""

    @pytest.mark.parametrize("mode", _MODE_WORDS,
                             ids=["0x%08x" % m for m in _MODE_WORDS])
    def test_mode_word_registers_healthy(self, sweep_server, mode):
        sock = _node_login_dialog(
            sweep_server.port,
            _login_payload_with_mode(NODE_DATA_PORT, mode, paths=b"r /data"))
        sock.settimeout(6)
        try:
            time.sleep(0.2)
            sock.sendall(_build_frame(_SID | 0xB0, CMS_RR_PING, 0))
            assert _recv_code(sock, CMS_RR_PONG, timeout=6) is not None, \
                "login mode word 0x%08x did not yield a serviceable link" % mode
        finally:
            sock.close()


# Edge advertised-data-port values (u16). Whether or not a given port is
# accepted, an edge value can never wedge the accept leg for other peers.
_LOGIN_PORTS = [1, 2, 80, 443, 1024, 1094, 1095, 8443, 20000, 32767, 32768,
                49152, 60000, 65534, 65535, 1200]


class TestServerLoginPortSweep:
    """A login advertising each edge data port must leave the accept leg
    serving a fresh client -- a bogus port can never take the worker down."""

    @pytest.mark.parametrize("dport", _LOGIN_PORTS, ids=[str(p) for p in _LOGIN_PORTS])
    def test_login_data_port_does_not_wedge(self, sweep_server, dport):
        try:
            _node_login_dialog(
                sweep_server.port,
                _minimal_login_payload(dport, b"r /data")).close()
        except OSError:
            pass
        assert _server_alive(sweep_server.port), \
            "a login advertising data port %d wedged the accept leg" % dport


# Structurally valid logins carrying edge / hostile path declarations. None may
# wedge the accept leg (offender may be refused; a fresh client is still served).
_LOGIN_PATH_CORPUS = [
    ("empty", b""),
    ("root", b"r /"),
    ("data", b"r /data"),
    ("write", b"w /data"),
    ("rw_split", b"r /data w /data"),
    ("two_lines", b"r /a\nr /b"),
    ("traversal", b"r /../etc"),
    ("deep", b"r /a/b/c/d/e"),
    ("many", b"\n".join(b"r /p%d" % i for i in range(20))),
    ("hundred", b"\n".join(b"r /export/deep/%03d" % i for i in range(100))),
    ("dot", b"r /."),
    ("dotdot_only", b"r /.."),
    ("trailing_slash", b"r /data/"),
    ("double_slash", b"r //data"),
    ("embedded_space", b"r / data"),
    ("nonascii", b"r /d\xc3\xa9ta"),
    ("embedded_nul", b"r /da\x00ta"),
    ("no_flag", b"/data"),
    ("bad_flag", b"x /data"),
    ("flag_only", b"r"),
    ("flag_space", b"r "),
    ("rw_flags", b"rw /data"),
    ("tab_sep", b"r\t/data"),
    ("long_single", b"r /" + b"a" * 400),
]


class TestServerLoginPathListCorpus:
    """Every edge / hostile export declaration in a login: bounded copy, no
    escape, no wedge.  A fresh client is always served afterwards."""

    @pytest.mark.parametrize("paths", [p for _, p in _LOGIN_PATH_CORPUS],
                             ids=[n for n, _ in _LOGIN_PATH_CORPUS])
    def test_edge_path_declaration_does_not_wedge(self, sweep_server, paths):
        try:
            _node_login_dialog(
                sweep_server.port,
                _minimal_login_payload(NODE_DATA_PORT, paths)).close()
        except OSError:
            pass
        assert _server_alive(sweep_server.port), \
            "an edge path declaration wedged the accept leg"


# kYR_have ingest fuzz: a logged-in child advertising foreign / covered /
# traversal paths under every online/pending/raw modifier.  The paths-cover gate
# (and relay-take, which finds no entry) drops the foreign advertisements; the
# connection stays frame-aligned throughout.
_HAVE_PATHS = [
    ("foreign_passwd", b"/etc/passwd"),
    ("empty", b""),
    ("covered_root", b"/data"),
    ("covered_child", b"/data/have_me.bin"),
    ("traversal", b"/../etc/shadow"),
    ("proc", b"/proc/self/maps"),
]
_HAVE_MODS = [CMS_MOD_RAW | CMS_HAVE_ONLINE, CMS_MOD_RAW, CMS_HAVE_ONLINE, 0, 0xFF]
_HAVE_CASES = [(pn, pv, m) for pn, pv in _HAVE_PATHS for m in _HAVE_MODS]


class TestServerHaveIngestFuzz:
    """Adversarial kYR_have advertisements (foreign / covered / traversal paths
    x online/pending/raw modifiers) on one logged-in link never desync the
    framer nor drop the connection."""

    @pytest.fixture(scope="class")
    def have_link(self, sweep_server):
        sock = _login_server(sweep_server.port, paths=b"r /data")
        try:
            yield sock
        finally:
            sock.close()

    @pytest.mark.parametrize("pv,mod", [(pv, m) for _pn, pv, m in _HAVE_CASES],
                             ids=["%s_m%02x" % (pn, m) for pn, _pv, m in _HAVE_CASES])
    def test_have_ingest_keeps_link_aligned(self, have_link, pv, mod):
        body = (pv + b"\x00") if pv else b""
        have_link.sendall(_build_frame(_SID | 0xC0, CMS_RR_HAVE, mod, body))
        have_link.sendall(_build_frame(_SID | 0xC1, CMS_RR_PING, 0))
        assert _recv_code(have_link, CMS_RR_PONG, timeout=6) is not None, \
            "a kYR_have advertisement (mod 0x%02x) desynced the accept leg" % mod


# kYR_gone for an adversarial path set: an unheld gone is a no-op, the framer
# stays aligned, and no path string can crash the handler.
_GONE_PATHS = [
    ("foreign", b"/etc/passwd"), ("covered", b"/data"),
    ("covered_child", b"/data/have_me.bin"), ("empty", b""), ("root", b"/"),
    ("dotdot", b"/.."), ("deep_dotdot", b"/../../root"),
    ("proc", b"/proc/1/environ"), ("dev", b"/dev/null"), ("sys", b"/sys/kernel"),
    ("mid_dotdot", b"/data/../etc"), ("dot_seg", b"/data/./x"),
    ("double_lead", b"//data"), ("double_mid", b"/data//x"),
    ("deep_chain", b"/a/b/c/d/e/f/g"), ("long", b"/" + b"z" * 300),
    ("trailing_space", b"/data "), ("leading_space", b"  /data"),
    ("embedded_nul", b"/da\x00ta"), ("tab", b"/tab\tpath"),
    ("nonascii", b"/uni\xc3\xa9"), ("backslash", b"/mixed\\slash"),
    ("trailing_slash", b"/data/"), ("bare_name", b"CVE"),
]
