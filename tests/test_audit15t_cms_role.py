"""`brix_cms_role` at VALUE granularity — the tranche-15 cluster-role table.

WHY THIS FILE EXISTS
--------------------
Steps 1-2 of the audit's Method count directive NAMES.  An enum-valued directive
scores "covered" the moment ANY ONE of its accepted tokens appears somewhere in
the corpus, which is how a six-token directive can be green with four tokens
never written.  Re-running step 1 per (directive, value) pair over the 36
`ngx_conf_enum_t` tables in `src/` gives 93 pairs, 48 written, 45 never — and
`brix_cms_role` is one of the sharper misses:

    brix_cms_roles[] (module_enums.c:78-86)
        auto        never written anywhere in the corpus
        server      test_cms_wire_pup_conformance_b.py
        manager     test_cms_wire_pup_conformance_b.py
        supervisor  nginx_cms_wire_super.conf
        peer        test_cms_role_peer_proxy.py
        proxy       never written anywhere in the corpus

`auto` is the interesting one twice over.  It is the MERGE DEFAULT
(server_conf_merge_cluster.c:243-244), so it is what every deployment that never
writes the directive actually runs — the one value guaranteed to be in
production and the one value no test had ever named.  And it is the only token
whose Mode word is DERIVED rather than fixed: `auto` reads `brix_manager_mode`
and adds the manager bit itself (send.c:78-80), so a single arm cannot pin it;
the table needs `auto` twice, with manager_mode off and on.

WHAT THE VALUE SELECTS
----------------------
Two things, in two different files, and only one of them is visible from the
wire the node emits:

1.  The login Mode word (cms_login_mode, send.c:59-81) — the node's self-
    description in the very first frame it sends its manager:

        server      0x08  kYR_server
        manager     0x02  kYR_manager ALONE (a sub-manager, not a data server)
        supervisor  0x0A  kYR_manager|kYR_server
        peer        0x04  kYR_peer — the ONLY token without the server bit
        proxy       0x18  kYR_server|kYR_proxy
        auto        0x08 | (manager_mode ? 0x02 : 0)

2.  The inbound valid-ops class (cms_frame_role_ok, recv_frame.c:468-495) —
    which manager-originated opcodes this node will EXECUTE:

        manager                 XRDCMS_ROLE_SUBMAN
        supervisor              XRDCMS_ROLE_SUPER
        peer, proxy             XRDCMS_ROLE_SUBMAN  (§2.17)
        auto, server            `return 1` — accept everything

WHAT THE TABLE ESTABLISHES
--------------------------
*   Every token produces a distinct, exact Mode word, and the directive being
    ABSENT produces the same wire as an explicit `auto` — the merge default is
    a fact about the running binary, not about the header comment.
*   `auto` derives the manager bit from `brix_manager_mode`; the two `auto`
    arms differ in exactly that bit and in nothing else.
*   `peer` is the only token that withholds kYR_server: a peer cluster's
    contact point must never be registered as ordinary serving capacity.
*   `proxy` is the only token that sets kYR_proxy, and it sets it ON TOP OF
    kYR_server — "proxy data server", not "proxy instead of server".
*   The two planes are INDEPENDENT: `auto` + manager_mode and `supervisor`
    emit the SAME Mode word 0x0A and are nonetheless different nodes — the
    first dispatches a forwarded kYR_mkdir to its own executor, the second
    relays it down its tier (cms_super_fan_down, recv_frame.c:376-378).  A
    reader who inferred the dispatch class from the wire would get that
    backwards, which is why this file drives frames as well as decoding them.

A FACT PINNED RATHER THAN A DEFECT — MANAGER MODE HAS NO EXPORT
---------------------------------------------------------------
The automgr arm passes the role gate and still creates nothing:
brix_manager_mode makes brix_server_has_runtime_export() false
(runtime_server.c:25-29), so root_canon stays empty and the export rootfd is
never opened (process_server_init.c:165-171) — "cluster manager — redirects
clients to data servers (does not serve local files)".  §C therefore reads the
GATE (the cmsd-action audit line) and the STORAGE LEG (the directory) as two
separate observables rather than inferring one from the other.

THE FINDING — DEFECT CANDIDATE #51
----------------------------------
Chasing that arm surfaced an observability defect one step further on.
cms_frame_forward() derives its cmsd-action audit line from `rc == NGX_OK`
(recv_frame.c:380-386), but the failure path returns
ngx_brix_cms_send_error()'s value, which is NGX_OK whenever the kYR_error frame
was DELIVERED (send.c:32-50).  A forwarded namespace op that was refused — a
path escaping the export root, say — is therefore recorded as `result=ok
detail=manager-forwarded namespace op executed on this node`, and the audit
trail cannot distinguish a mutation that landed from one that was rejected.
Pinned as current behaviour in
TestTheTokenSelectsTheDispatchClass.test_a_failed_forwarded_op_is_logged_as_a_success.
"""

import os
import time

import pytest

from _test_cms_wire_pup_conformance_helpers import (
    CMS_MOD_RAW, CMS_MODE_MANAGER, CMS_MODE_SERVER, CMS_RR_HAVE, CMS_RR_LOGIN,
    CMS_RR_MKDIR, CMS_RR_PING, CMS_RR_PONG, CMS_RR_STATE, CMS_RSP_ERROR,
    _decode_login, _fwd_a_payload, _start_peered_node, _wait_log_contains)
from _test_phase25_ratelimit_helpers import _parse_fail, _stream_values

# The helper module carries the wire suite's own pytestmark (xdist_group
# "lc-cms-wire"); this file owns six ledger instances of its own, so it declares
# its own group rather than inheriting that one.
pytestmark = [pytest.mark.timeout(240),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15t-cmsrole")]

_DATA = os.path.join(os.environ["TMPDIR"], "xrd_audit15t_cmsrole")

CMS_MODE_PEER  = 0x04   # kYR_peer
CMS_MODE_PROXY = 0x10   # kYR_proxy

# arm -> (ROLE_LINE, MGR_LINES).  "absent" writes no role line at all: it is the
# merge-default control, and its whole point is that it must be indistinguishable
# from the explicit `auto` arm on the wire.
ARMS = {
    "auto":    ("        brix_cms_role auto;\n",   ""),
    "automgr": ("        brix_cms_role auto;\n",   "        brix_manager_mode on;\n"),
    "absent":  ("",                                ""),
    "peer":    ("        brix_cms_role peer;\n",   ""),
    "proxy":   ("        brix_cms_role proxy;\n",  ""),
    "server":  ("        brix_cms_role server;\n", ""),
}

# The assertion of this file: cms_login_mode(), read off the wire.
MODE = {
    "auto":    CMS_MODE_SERVER,                      # 0x08
    "automgr": CMS_MODE_SERVER | CMS_MODE_MANAGER,   # 0x0A — derived, not fixed
    "absent":  CMS_MODE_SERVER,                      # 0x08 — merge default AUTO
    "peer":    CMS_MODE_PEER,                        # 0x04
    "proxy":   CMS_MODE_SERVER | CMS_MODE_PROXY,     # 0x18
    "server":  CMS_MODE_SERVER,                      # 0x08
}

# cms_frame_role_ok(): the arms that fall through to `return 1`, and the arms
# that map to XRDCMS_ROLE_SUBMAN.  kYR_mkdir (3) is absent from manVOps, so the
# same frame is executed by the first set and dropped by the second.
PERMISSIVE = ("auto", "automgr", "absent", "server")
RESTRICTED = ("peer", "proxy")
# The permissive arms that also own a local export.  automgr is permissive at the
# gate and has NO export root (brix_manager_mode -> no runtime export), so it is
# read through the audit line instead of through the filesystem.
EXPORTING_PERMISSIVE = tuple(a for a in PERMISSIVE if a != "automgr")

# cms_frame_forward() emits this once the frame has passed the role gate and been
# dispatched — the observable that separates "accepted" from "landed".
_ACTION_MKDIR = b"cmsd-action op=mkdir"

RESIDENT = "have_me.bin"
REASON = ("Tranche 15 (value granularity): brix_cms_role — the login Mode word "
          "and the inbound valid-ops class each token selects.")


def _node(lifecycle, arm):
    """Start the arm's nginx node against a fresh in-process manager peer.

    The peer binds a free_port (not a ledger port) inside _start_peered_node;
    only the nginx side draws from the fleet ledger.
    """
    role_line, mgr_lines = ARMS[arm]
    data_dir = os.path.join(_DATA, arm)
    os.makedirs(data_dir, exist_ok=True)
    # A resident file so a kYR_state probe has something to answer kYR_have for.
    with open(os.path.join(data_dir, RESIDENT), "wb") as f:
        f.write(b"resident-bytes" * 16)
    return _start_peered_node(
        lifecycle, "lc-audit15t-role-" + arm, "nginx_audit15t_cmsrole.conf",
        {"ROLE_LINE": role_line, "MGR_LINES": mgr_lines}, REASON, data_dir)


@pytest.fixture
def nodes(lifecycle):
    """Factory: `nodes("proxy")` starts that arm; every peer opened is closed."""
    opened = []

    def _open(arm):
        peer = _node(lifecycle, arm)
        opened.append(peer)
        return peer

    try:
        yield _open
    finally:
        for peer in opened:
            peer.close()


def _login(peer, arm):
    fr = peer.wait_for_code(CMS_RR_LOGIN, timeout=20.0)
    assert fr is not None, f"{arm}: node never emitted a kYR_login frame"
    return _decode_login(fr[3])


def _mode(peer, arm):
    return _login(peer, arm)["mode"]


def _mkdir_probe(peer, arm, name):
    """Send one manager-forwarded kYR_mkdir; return the path it would create."""
    made = os.path.join(_DATA, arm, name)
    if os.path.isdir(made):
        os.rmdir(made)
    peer.send_to_node(0x15700001, CMS_RR_MKDIR, 0,
                      _fwd_a_payload(b"mgr", b"755", ("/" + name).encode()))
    return made


def _wait_dir(path, timeout=6.0):
    deadline = time.time() + timeout
    while time.time() < deadline and not os.path.isdir(path):
        time.sleep(0.1)
    return os.path.isdir(path)


def _errlog(peer, limit=3000):
    try:
        with open(os.path.join(peer.ep.prefix, "logs", "error.log"), "rb") as f:
            return f.read()[-limit:].decode("utf-8", "replace")
    except OSError as exc:                       # pragma: no cover - diagnostic
        return f"<no error log: {exc}>"


def _still_alive(peer, sid):
    peer.send_to_node(sid, CMS_RR_PING, 0)
    pong = peer.collect_reply(CMS_RR_PONG, timeout=8.0)
    return pong is not None and pong[0] == sid


# --------------------------------------------------------------------------- #
# §A — the token selects the login Mode word.                                  #
# --------------------------------------------------------------------------- #

class TestTheTokenSelectsTheLoginModeWord:
    """cms_login_mode() (send.c:59-81), read off the first frame the node
    sends.  Six arms, six exact words — the value granularity the audit's
    name-level pass could not reach."""

    @pytest.mark.parametrize("arm", sorted(ARMS))
    def test_the_mode_word_is_exactly_the_table_entry(self, nodes, arm):
        got = _mode(nodes(arm), arm)
        assert got == MODE[arm], (
            f"brix_cms_role {arm}: login Mode {got:#04x}, "
            f"expected {MODE[arm]:#04x}")

    def test_the_absent_directive_is_exactly_auto(self, nodes):
        """The merge default (server_conf_merge_cluster.c:243-244) is
        BRIX_CMS_ROLE_AUTO.  Two nodes, identical but for the presence of the
        line, must be indistinguishable in the word they log in with — which is
        what makes `auto` the value every unconfigured deployment runs."""
        explicit = _mode(nodes("auto"), "auto")
        omitted = _mode(nodes("absent"), "absent")
        assert omitted == explicit, (
            f"omitting brix_cms_role gave Mode {omitted:#04x}, explicit auto "
            f"gave {explicit:#04x}: the merge default is not AUTO")

    def test_auto_derives_the_manager_bit_from_manager_mode(self, nodes):
        """`auto` is the only token whose word is computed: the default arm of
        cms_login_mode() ORs kYR_manager in when brix_manager_mode is on.  The
        two arms must differ in EXACTLY that bit — a role that also flipped, say,
        kYR_proxy would mean the derivation had drifted."""
        off = _mode(nodes("auto"), "auto")
        on = _mode(nodes("automgr"), "automgr")
        assert off ^ on == CMS_MODE_MANAGER, (
            f"auto/manager_mode differ by {off ^ on:#04x}, expected only "
            f"kYR_manager ({CMS_MODE_MANAGER:#04x}): {off:#04x} vs {on:#04x}")
        assert not off & CMS_MODE_MANAGER and on & CMS_MODE_MANAGER

    def test_peer_is_the_only_token_that_withholds_the_server_bit(self, nodes):
        """§2.17: a peer is a foreign cluster's contact point, registered as
        overflow capacity — never as ordinary serving capacity.  Withholding
        kYR_server is the whole mechanism, so this is a security-relevant
        property of the token and not a cosmetic one."""
        mode = _mode(nodes("peer"), "peer")
        assert mode & CMS_MODE_SERVER == 0, (
            f"peer logged in with the kYR_server bit set ({mode:#04x}): the "
            "manager would route ordinary client traffic to it")
        assert mode == CMS_MODE_PEER, f"peer Mode {mode:#04x}, expected 0x04"
        assert [a for a in MODE if not MODE[a] & CMS_MODE_SERVER] == ["peer"]

    def test_proxy_sets_the_proxy_bit_on_top_of_the_server_bit(self, nodes):
        """`proxy` means "a data server reached through a proxy front", so
        kYR_proxy is ADDITIVE — a word of 0x10 alone would tell the manager the
        node serves nothing."""
        mode = _mode(nodes("proxy"), "proxy")
        assert mode & CMS_MODE_PROXY, f"proxy Mode {mode:#04x} lacks kYR_proxy"
        assert mode & CMS_MODE_SERVER, (
            f"proxy Mode {mode:#04x} lacks kYR_server: the proxy bit replaced "
            "the server bit instead of joining it")
        assert [a for a in MODE if MODE[a] & CMS_MODE_PROXY] == ["proxy"]


# --------------------------------------------------------------------------- #
# §B — the token moves the Mode word and nothing else.                         #
# --------------------------------------------------------------------------- #

class TestTheTokenMovesOnlyTheModeWord:
    """The login carries the node's whole self-description; the role selects one
    field of it.  If a token also changed the advertised paths or the protocol
    version, a manager would mis-register the node for reasons the operator
    never wrote down."""

    def test_the_rest_of_the_login_is_identical_across_two_tokens(self, nodes):
        auto = _login(nodes("auto"), "auto")
        proxy = _login(nodes("proxy"), "proxy")
        assert auto["mode"] != proxy["mode"], "the arms must differ somewhere"
        for field in ("version", "paths", "iflist", "envcgi"):
            assert auto[field] == proxy[field], (
                f"brix_cms_role also moved {field}: "
                f"auto={auto[field]!r} proxy={proxy[field]!r}")

    def test_the_holdtime_slot_is_per_process_not_per_role(self, nodes):
        """The one login field that legitimately differs between two arms, and
        the reason it is excluded above: this encoder puts getpid() in the
        CmsLoginData HoldTime slot (send.c:191-192), so two nodes always differ
        there — asserting it as a constant would make the invariance test above
        flap on process ids rather than on anything the role selects."""
        auto = _login(nodes("auto"), "auto")
        proxy = _login(nodes("proxy"), "proxy")
        assert auto["holdtime"] > 0 and proxy["holdtime"] > 0
        assert auto["holdtime"] != proxy["holdtime"], (
            "two separate worker processes reported the same HoldTime slot: "
            f"{auto['holdtime']} — it is meant to carry each node's pid")

    @pytest.mark.parametrize("arm", ["peer", "server"])
    def test_the_node_still_advertises_its_own_listen_port(self, nodes, arm):
        """dPort is how the manager reaches the node for data; a role that
        blanked it would produce a registered but unreachable node."""
        peer = nodes(arm)
        login = _login(peer, arm)
        assert login["dport"] == peer.node_port, (
            f"{arm}: advertised dPort {login['dport']}, listening on "
            f"{peer.node_port}")
        assert b"/" in login["paths"], (
            f"{arm}: exported paths {login['paths']!r} lost the export root")


# --------------------------------------------------------------------------- #
# §C — the token also selects the inbound valid-ops class.                     #
# --------------------------------------------------------------------------- #

class TestTheTokenSelectsTheDispatchClass:
    """cms_frame_role_ok() (recv_frame.c:468-495).  One identical
    manager-forwarded kYR_mkdir frame, six nodes, two verdicts — selected purely
    by the enum token.

    Two observables, deliberately separated: whether the frame PASSED THE GATE
    (the cmsd-action line, emitted by cms_frame_forward once dispatch is
    reached) and whether the storage leg then LANDED it (the directory).  The
    automgr arm is why they cannot be conflated — see
    test_a_manager_mode_node_passes_the_gate_with_no_export_to_land_it.
    """

    @pytest.mark.parametrize("arm", EXPORTING_PERMISSIVE)
    def test_a_permissive_role_executes_a_forwarded_mkdir(self, nodes, arm):
        """auto/server fall through to `return 1`: legacy accept-everything.
        The `absent` arm is here because the default a deployment inherits is
        the permissive one — a fact worth having written down."""
        peer = nodes(arm)
        made = _mkdir_probe(peer, arm, "fwd_" + arm)
        assert _wait_dir(made), (
            f"{arm}: a permissive role did not execute the forwarded mkdir\n"
            f"{_errlog(peer)}")
        assert peer.collect_reply(CMS_RSP_ERROR, timeout=1.0) is None, (
            f"{arm}: a valid op must not draw kYR_error")

    @pytest.mark.parametrize("arm", RESTRICTED)
    def test_a_restricted_role_drops_a_forwarded_mkdir(self, nodes, arm):
        """Security-negative, and the reason §2.17 gives peer/proxy the SUBMAN
        table: a remote cluster's manager must not be able to drive namespace
        mutations into this one.  kYR_mkdir is absent from manVOps, so the frame
        is DROPPED — no directory, no kYR_error to probe with, and the
        connection stays live so a dropped op cannot be used as a disconnect."""
        peer = nodes(arm)
        made = _mkdir_probe(peer, arm, "fwd_" + arm)
        time.sleep(1.0)
        assert not os.path.isdir(made), (
            f"valid-ops breach: role {arm} executed a forwarded kYR_mkdir\n"
            f"{_errlog(peer)}")
        assert peer.collect_reply(CMS_RSP_ERROR, timeout=1.0) is None, (
            f"{arm}: invalid ops are dropped silently, not answered kYR_error\n"
            f"{_errlog(peer)}")
        assert _wait_log_contains(
            peer.ep, b"CMS subman: manager sent an invalid request (op=3)"), (
            f"{arm}: the drop was not attributed to the subman valid-ops "
            f"table\n{_errlog(peer)}")
        assert _ACTION_MKDIR not in _errlog(peer, limit=200000).encode(), (
            f"{arm}: the frame reached the forwarded-op executor — the gate "
            "logged a drop and dispatched anyway")
        assert _still_alive(peer, 0x15700002), (
            f"{arm}: connection died on a dropped op\n{_errlog(peer)}")

    @pytest.mark.parametrize("arm", RESTRICTED)
    def test_a_restricted_role_still_admits_a_state_probe(self, nodes, arm):
        """The filter must be a table lookup, not a blanket mute: kYR_state IS
        in manVOps, so a residency probe still draws kYR_have on the same
        connection whose mkdir was just dropped."""
        peer = nodes(arm)
        sid = 0x15700003
        peer.send_to_node(sid, CMS_RR_STATE, CMS_MOD_RAW,
                          ("/" + RESIDENT).encode() + b"\x00")
        reply = peer.collect_reply(CMS_RR_HAVE, timeout=8.0)
        assert reply is not None, (
            f"{arm}: manVOps must still admit kYR_state")
        assert reply[0] == sid, "kYR_have must echo the probe's streamid"

    def test_the_mode_word_does_not_determine_the_dispatch_class(self, nodes):
        """The sharpest row in the table, and the one only value granularity
        reaches: `auto` + brix_manager_mode emits Mode 0x0A — byte-for-byte the
        word `supervisor` emits — yet it is a DIFFERENT node, because
        cms_frame_role_ok() switches on the role enum and not on the word.  A
        reader who inferred the dispatch class from the wire would get this
        backwards, so it is pinned live: the frame a SUBMAN would have dropped
        reaches this node's forwarded-op executor."""
        arm = "automgr"
        peer = nodes(arm)
        assert _mode(peer, arm) == CMS_MODE_SERVER | CMS_MODE_MANAGER, \
            "the premise of this test is that automgr shares supervisor's word"
        _mkdir_probe(peer, arm, "fwd_supervisor_lookalike")
        assert _wait_log_contains(peer.ep, _ACTION_MKDIR), (
            "auto+manager_mode must keep the permissive dispatch class even "
            f"though its Mode word is a supervisor's\n{_errlog(peer)}")
        assert not _wait_log_contains(
            peer.ep, b"manager sent an invalid request", timeout=1.0), (
            "the gate treated auto+manager_mode as a restricted role")

    def test_a_manager_mode_node_passes_the_gate_with_no_export_to_land_it(
            self, nodes):
        """A FACT PINNED RATHER THAN A DEFECT.  brix_manager_mode makes
        brix_server_has_runtime_export() false (runtime_server.c:25-29), so
        root_canon stays empty, brix_init_server_rootfd() returns early
        (process_server_init.c:165-171) and the node never opens an export at
        all — "cluster manager — redirects clients to data servers (does not
        serve local files)".  The forwarded mkdir therefore passes the ROLE gate
        and still creates nothing, which is why this file reads the gate and the
        storage leg as two separate observables instead of inferring one from
        the other."""
        arm = "automgr"
        peer = nodes(arm)
        made = _mkdir_probe(peer, arm, "fwd_no_export")
        assert _wait_log_contains(peer.ep, _ACTION_MKDIR), \
            "the premise is that the frame reaches the executor"
        time.sleep(1.0)
        assert not os.path.isdir(made), (
            "a manager-mode node created a local directory although it opens "
            "no export root")

    def test_a_failed_forwarded_op_is_logged_as_a_success(self, nodes):
        """THE FINDING — DEFECT CANDIDATE #51 (observability, audit trail says
        ok on failure).  cms_frame_forward() logs the cmsd-action audit line
        from `rc == NGX_OK` (recv_frame.c:380-386), but the failure path returns
        ngx_brix_cms_send_error()'s value — and that is NGX_OK whenever the
        kYR_error FRAME was delivered (send.c:32-50).  So a forwarded namespace
        op that was REFUSED is recorded as `result=ok detail=manager-forwarded
        namespace op executed on this node`, and the audit trail cannot
        distinguish a mutation that landed from one that was rejected.

        Driven here with a path that escapes the export root, so the failure is
        the confinement refusal a hostile manager would provoke — the exact case
        an operator would go to this log to find.  Pinned as CURRENT behaviour:
        when the log line is corrected to report the op's own outcome, this test
        is the one that must be updated."""
        arm = "server"
        peer = nodes(arm)
        escape = os.path.join(_DATA, "pwned_by_" + arm)
        if os.path.isdir(escape):
            os.rmdir(escape)
        peer.send_to_node(0x15700004, CMS_RR_MKDIR, 0,
                          _fwd_a_payload(b"mgr", b"755", b"/../pwned_by_server"))
        err = peer.collect_reply(CMS_RSP_ERROR, timeout=8.0)
        assert err is not None, "the escaping op must be refused with kYR_error"
        assert not os.path.exists(escape), (
            "confinement breach: the op landed outside the export root")
        assert _wait_log_contains(peer.ep, _ACTION_MKDIR + b" peer="), \
            "the refused op left no audit line at all"
        log = _errlog(peer, limit=200000)
        action = [ln for ln in log.splitlines() if "cmsd-action op=mkdir" in ln]
        assert action, log[-2000:]
        assert "result=ok" in action[-1], (
            "defect candidate #51 appears to be fixed — the audit line now "
            f"reports the op's own outcome: {action[-1]}")


# --------------------------------------------------------------------------- #
# §D — the parse tier.                                                         #
# --------------------------------------------------------------------------- #

def _knob(value):
    return f"        brix_cms_role {value};\n"


class TestTheParseTier:
    """Every token the table holds is accepted; nothing else is.  Parse-only —
    nginx -t never binds, so no ledger port is involved."""

    @pytest.mark.parametrize(
        "token", ["auto", "server", "manager", "supervisor", "peer", "proxy"])
    def test_each_token_in_the_table_is_accepted(self, tmp_path, token):
        rc, out = _parse_fail(tmp_path, "nginx_rl_stream.conf",
                              _stream_values(_knob(token), ""))
        assert rc == 0, f"brix_cms_role {token} was refused:\n{out}"

    @pytest.mark.parametrize("token", ["PROXY", "Auto"])
    def test_the_table_match_is_case_insensitive(self, tmp_path, token):
        """ngx_conf_set_enum_slot() compares with ngx_strcasecmp, so the config
        surface accepts `PROXY`.  Pinned rather than assumed: a future hand-
        rolled setter that switched to ngx_strcmp would silently break configs
        that had been valid."""
        rc, out = _parse_fail(tmp_path, "nginx_rl_stream.conf",
                              _stream_values(_knob(token), ""))
        assert rc == 0, f"brix_cms_role {token} was refused:\n{out}"

    @pytest.mark.parametrize("token", ["gateway", "peers", "proxy,server", "1"])
    def test_a_value_outside_the_table_is_refused(self, tmp_path, token):
        """`peers` and `proxy,server` are the two mistakes the table invites —
        a plural, and a list where the enum takes exactly one name — and `1` is
        the raw enum value behind a token.  All three must be parse errors, not
        a silent fall-through to AUTO."""
        rc, out = _parse_fail(tmp_path, "nginx_rl_stream.conf",
                              _stream_values(_knob(token), ""))
        assert rc != 0, f"brix_cms_role {token} parsed:\n{out}"
        assert "invalid value" in out, out

    @pytest.mark.parametrize(
        "line", ["        brix_cms_role;\n", "        brix_cms_role peer proxy;\n"])
    def test_the_directive_takes_exactly_one_argument(self, tmp_path, line):
        rc, out = _parse_fail(tmp_path, "nginx_rl_stream.conf",
                              _stream_values(line, ""))
        assert rc != 0, f"{line.strip()!r} parsed:\n{out}"
        assert "invalid number of arguments" in out, out

    def test_the_directive_is_refused_outside_a_server_block(self, tmp_path):
        """NGX_STREAM_SRV_CONF only.  The role describes ONE node's leg to its
        manager, so a stream-wide setting has no meaning; placing it there is a
        parse error rather than a line that is read and ignored."""
        rc, out = _parse_fail(tmp_path, "nginx_rl_stream.conf",
                              _stream_values("", "    brix_cms_role proxy;"))
        assert rc != 0, f"brix_cms_role was accepted in stream {{}}:\n{out}"
        assert "directive is not allowed here" in out, out
