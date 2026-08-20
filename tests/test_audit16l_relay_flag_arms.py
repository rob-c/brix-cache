"""The tap-proxy and dead-peer flag arms `directives_cms.h` never had written.

WHY THIS FILE EXISTS
--------------------
Tranche 16 measures flag coverage at (directive, value) granularity.  After the
five selection-policy flags (test_audit16k_cms_select_flag_arms.py), five arms
of the same table remain unwritten anywhere in the corpus — the transparent
proxy's three switches and the two dead-peer keepalives:

    brix_tap_proxy                    on: 8 configs        off: NOWHERE
    brix_tap_proxy_upstream_tls       on: test_upstream…   off: NOWHERE
    brix_tap_proxy_upstream_tls_verify off: test_upstream… on:  NOWHERE
    brix_tcp_keepalive                on: 2 configs        off: NOWHERE
    brix_cms_tcp_keepalive            off: test_audit15f…  on:  NOWHERE

Three of them (`brix_tap_proxy`, `brix_tap_proxy_upstream_tls`,
`brix_tcp_keepalive`) merge to 0 and two (`…_tls_verify`, `brix_cms_tcp_keepalive`)
merge to 1 — server_conf_merge_proxy_net.c:47-77 and
server_conf_merge_cluster.c:373 — so for every one of them the unwritten arm is
also the arm that no default can stand in for, and no reading here can be a
value comparison.

THE FINDING — DEFECT CANDIDATE #88 (`brix_tap_proxy off` still advertises the
proxy capability)
-----------------------------------------------------------------------------
`protocol_role_flags()` (protocols/root/session/protocol.c:85) sets
kXR_attrProxy on a disjunction:

    ((conf->proxy.enable > 0 || conf->proxy.upstreams != NULL)
     ? kXR_attrProxy : 0)

`proxy.upstreams` is populated by `brix_tap_proxy_upstream`
(net/proxy/directives.c:200-207) with no reference to the flag, and nothing in
the config tier refuses an upstream whose proxy is off.  So a server that says

    brix_tap_proxy off;
    brix_tap_proxy_upstream some.host:1095;

— an operator disabling a proxy hop while leaving its address in the file, which
is how a hop gets turned off in practice — answers kXR_protocol with the
transparent-proxy bit set while every proxy code path is inert.  §B measures the
bit on the wire and the control that isolates it (the same `off` arm without the
upstream line clears it).

The blast radius is a client's routing decision, not a crash: kXR_attrProxy is
what tells a client it is talking to a proxy rather than to the data server
itself, and XRootD clients use it to decide whether to re-resolve a redirect.
The audit files it as a candidate, with the fix left to the owner — the
one-character reading (`enable > 0 &&`) is not obviously right either, since a
proxy is also identified by having upstreams at all.

THE SECOND FINDING — the config-time TLS audit is gated on the flag
------------------------------------------------------------------
`brix_server_setup_tls()` (core/config/runtime_server_tls.c:62) wraps the whole
upstream-TLS validation in `if (xcf->proxy.enable && xcf->proxy.upstream_tls)`.
That validation is the fail-closed gate A-1 added: TLS on with no CA is an
`[emerg]` refusal, because an unverified TLS upstream re-sends the client's
kXR_login over an attacker-controllable channel.  Either flag's `off` arm
therefore silences the refusal — the very same directive block that nginx
refuses with the flag on parses clean with it off.  That is correct as designed
(no hop, no exposure) but it is exactly what the arm owns, and §A reads it by
flipping one token and watching the refusal appear and disappear.

WHAT WAS ALREADY OWNED
----------------------
*   `test_upstream_tls_verify.py` owns the A-1 matrix with the proxy ON: CA
    present accepted, no CA refused, and the loud `…_verify off` opt-out.  It
    does not (and by its shape cannot) say what the flags' unwritten arms do.
*   `test_protocol_flags.py` owns kXR_attrProxy for a proxy server, a plain
    server and a cache server — all three with no `brix_tap_proxy off` anywhere,
    which is how the defect above stayed invisible.
*   `test_audit15f_cms_node_legs.py` owns `brix_cms_tcp_keepalive` by default
    (armed) and with `off` (bare).  The explicit `on` arm is what is missing.
*   `test_netfault_stream.py` owns `brix_tcp_keepalive on` — as a directive that
    is *accepted*.  Nothing has ever read the socket it is supposed to arm, so
    §B's control is the first reading of that arm's observable, and the `off`
    arm is measured against it.

WHAT THIS FILE DOES NOT CLAIM
-----------------------------
Not a claim about proxying itself: no client is proxied here, because the whole
subject is what happens when the proxy is switched off with its plumbing left in
place.  Not a claim about TLS crypto either — the handshake, the verify-result
gate and the host pinning belong to test_upstream_tls_verify.py, which reads
them at the source.  The keepalive readings assert the kernel's own timer
column, never a timeout's duration.

Run:
    PYTHONPATH=tests pytest tests/test_audit16l_relay_flag_arms.py -v
"""

import os
import subprocess
import time

import pytest

from config_parse import nginx_t
from fleet_lifecycle_ports import PARSE_PLACEHOLDER_PORT
from settings import BIND_HOST, HOST, SERVER_HOST
# The kernel-timer witness for the dead-peer knobs — the only external evidence
# that a setsockopt happened, and already the audit's helper for it.
from _test_audit15f_helpers import SS_BIN, socket_timers
# The two-faced manager, the node + stub-manager pair and the client session.
from _test_cms_parity_wave_helpers import (CMS_RR_LOGIN, StubManager, _mgr,
                                          _node, _xrd_session)
# The parse scaffold and its diagnostic filter (tranche file 10).
from test_audit16j_root_caps_flags import _diagnostics, _parse
# The kXR_protocol flags probe and the bit under test (Phase-1 flags file).
from test_protocol_flags import _get_protocol_flags, _kXR_attrProxy

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.timeout(180),
              # Both live templates below are the parity wave's ledger slots.
              pytest.mark.xdist_group("lc-cms-parity")]

MGR = "lc-cms-parity-mgr"
NODE = "lc-cms-parity-node"

# All five flags of this file, for the generic parse matrix.
FLAGS = ("brix_tap_proxy", "brix_tap_proxy_upstream_tls",
         "brix_tap_proxy_upstream_tls_verify", "brix_tcp_keepalive",
         "brix_cms_tcp_keepalive")

# An upstream address that is never dialled: with the proxy off nothing connects,
# and the config tier only has to parse it.  1095 is the xrootd default port and
# the address test_upstream_tls_verify.py uses for the same purpose.
UPSTREAM = f"{HOST}:1095"


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def ca_pem(tmp_path_factory):
    """A throwaway self-signed CA PEM — enough for ngx_ssl_trusted_certificate
    to load, which is the branch the verify arms live in.  Generated here rather
    than taken from the shared test PKI so a parallel fleet is never touched
    (the same reasoning, and the same recipe, as test_upstream_tls_verify.py)."""
    d = tmp_path_factory.mktemp("a16l_ca")
    pem = d / "ca.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(d / "ca.key"), "-out", str(pem), "-days", "1",
                    "-subj", "/CN=brix-a16l-test-ca"],
                   check=True, capture_output=True)
    return str(pem)


def _tls_t(tmp_path, directives, name):
    """`nginx -t` one directive block in a root stream server.

    Reuses test_upstream_tls_verify.py's template — the only scaffold in the
    suite whose slot is a whole proxy/TLS directive block — through the
    registry-free `nginx_t`, so these cases claim no ledger port and start
    nothing.  Returns (returncode, combined output).
    """
    root = tmp_path / name
    data = root / "data"
    data.mkdir(parents=True)
    result = nginx_t("nginx_upstream_tls_verify.conf", str(root),
                     LOG_DIR=str(root), BIND_HOST=BIND_HOST,
                     PORT=PARSE_PLACEHOLDER_PORT, DATA_ROOT=str(data),
                     TLS_DIRECTIVES=directives)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def _proxy_block(enable, *extra):
    """A tap-proxy directive block: the flag, its upstream, and whatever the
    case adds.  The upstream is always present — an operator who turns the hop
    off does not delete its address, which is the whole subject of this file."""
    lines = [f"brix_tap_proxy {enable};", f"brix_tap_proxy_upstream {UPSTREAM};"]
    lines.extend(extra)
    return "\n        ".join(lines)


def _needs_ss():
    if not os.path.exists(SS_BIN):
        pytest.skip("ss(8) not available")


def _pending_timer(*, local_port=None, peer_port=None, want="keepalive",
                   timeout=8.0):
    """The trailing ss(8) columns of the matching established socket, polled
    until its pending timer is `want`; the last reading otherwise.

    ss reports ONE timer per socket — the nearest one to fire — so a socket with
    a segment still unacknowledged reads `timer:(on,181ms,0)`, the
    retransmission timer, and the keepalive timer queued behind it is simply not
    displayed.  On loopback that window is one RTO (~200 ms) after each reply,
    which is exactly when a test that has just completed a handshake looks.

    Polling is therefore part of the reading rather than a flake workaround, and
    both arms below poll the same way: the positive asks whether the keepalive
    timer is ever the pending one, and the negative asks the same question over
    a window at least as long, so a masked timer cannot make it pass.
    """
    deadline = time.time() + timeout
    rest = socket_timers(local_port=local_port, peer_port=peer_port)
    while want not in rest and time.time() < deadline:
        time.sleep(0.25)
        rest = socket_timers(local_port=local_port, peer_port=peer_port)
    return rest


# --------------------------------------------------------------------------- #
# §A — the parse tier                                                          #
# --------------------------------------------------------------------------- #

class TestTheParseTier:
    """Step 1 of the audit's method for all ten arms."""

    @pytest.mark.parametrize("arm", ("on", "off"))
    @pytest.mark.parametrize("flag", FLAGS)
    def test_both_arms_are_accepted_in_a_stream_server(self, tmp_path, flag,
                                                       arm):
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} {arm};\n")
        assert rc == 0, out

    @pytest.mark.parametrize("value", ("1", "true"))
    @pytest.mark.parametrize("flag", FLAGS)
    def test_a_value_outside_the_two_arms_is_refused(self, tmp_path, flag,
                                                     value):
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} {value};\n")
        assert rc != 0, f"{flag} {value} was accepted: {out}"

    @pytest.mark.parametrize("flag", FLAGS)
    def test_the_directive_takes_exactly_one_argument(self, tmp_path, flag):
        rc, out = _parse(tmp_path, KNOBS=f"        {flag} on off;\n")
        assert rc != 0, out
        assert "invalid number of arguments" in out, out

    @pytest.mark.parametrize("flag", FLAGS)
    def test_a_duplicate_is_refused(self, tmp_path, flag):
        rc, out = _parse(tmp_path,
                         KNOBS=f"        {flag} off;\n        {flag} on;\n")
        assert rc != 0, out
        assert "duplicate" in out, out

    @pytest.mark.parametrize("slot", ("STREAM_KNOBS", "HTTP_KNOBS", "OUTER"))
    @pytest.mark.parametrize("flag", FLAGS)
    def test_every_other_placement_is_refused(self, tmp_path, flag, slot):
        """All five are declared NGX_STREAM_SRV_CONF and nothing else
        (directives_cms.h:326-333, 449-454; the proxy TLS pair at :349-371), so
        the parent slot their merges read can never hold a written value.  The
        refusal must name the placement, not the directive: "unknown directive"
        would mean the module was not loaded and the case measured nothing."""
        rc, out = _parse(tmp_path, **{slot: f"    {flag} on;\n"})
        assert rc != 0, out
        assert "is not allowed here" in out, out
        assert "unknown directive" not in out, out

    def test_the_five_arms_load_together_and_say_nothing(self, tmp_path):
        """The unwritten arm of each flag, in one server, silent.  A flag that
        merges to 1 written `on` and one that merges to 0 written `off` are both
        no-ops by construction — they must not be diagnosed as anything."""
        knobs = ("        brix_tap_proxy off;\n"
                 "        brix_tap_proxy_upstream_tls off;\n"
                 "        brix_tap_proxy_upstream_tls_verify on;\n"
                 "        brix_tcp_keepalive off;\n"
                 "        brix_cms_tcp_keepalive on;\n")
        rc, out = _parse(tmp_path, KNOBS=knobs)
        assert rc == 0, out
        assert _diagnostics(out) == [], out


class TestTheFailClosedTlsAuditIsGatedOnTheseFlags:
    """The A-1 gate refuses `brix_tap_proxy_upstream_tls on` without a CA.  Each
    flag's unwritten arm decides whether that refusal happens at all, which is
    the observable those arms own — measured by flipping one token per case so
    the refusal appearing and disappearing is attributable to nothing else."""

    def test_the_tap_proxy_off_arm_suppresses_the_refusal(self, tmp_path):
        """success + the arm: with the proxy on, TLS on and no CA is an [emerg];
        with the proxy off the identical block parses."""
        tail = ("brix_tap_proxy_upstream_tls on;",)
        rc_on, out_on = _tls_t(tmp_path, _proxy_block("on", *tail), "on")
        assert rc_on != 0, "the anchor case must still fail closed\n" + out_on
        assert "refusing an unauthenticated" in out_on, out_on

        rc_off, out_off = _tls_t(tmp_path, _proxy_block("off", *tail), "off")
        assert rc_off == 0, (
            "brix_tap_proxy off must suppress the proxy-leg TLS audit\n"
            + out_off)
        assert "refusing an unauthenticated" not in out_off, out_off

    def test_the_upstream_tls_off_arm_suppresses_the_refusal(self, tmp_path):
        """success + the arm: the same flip on the second gating flag, with the
        proxy left on — so the suppression is this flag's doing, not the
        proxy's."""
        rc_on, out_on = _tls_t(
            tmp_path, _proxy_block("on", "brix_tap_proxy_upstream_tls on;"),
            "tlson")
        assert rc_on != 0, out_on
        assert "refusing an unauthenticated" in out_on, out_on

        rc_off, out_off = _tls_t(
            tmp_path, _proxy_block("on", "brix_tap_proxy_upstream_tls off;"),
            "tlsoff")
        assert rc_off == 0, (
            "brix_tap_proxy_upstream_tls off must suppress the audit\n"
            + out_off)
        assert "refusing an unauthenticated" not in out_off, out_off

    def test_the_explicit_verify_on_arm_is_the_only_silent_spelling(
            self, tmp_path, ca_pem):
        """success + security-neg: with a CA loaded, the explicit `on` arm is
        accepted with no diagnostic at all, while the `off` opt-out is accepted
        WITH a warning that names the exposure.  Silence is the reading: the arm
        that authenticates the peer is the one an operator hears nothing about,
        and the arm that does not is loud."""
        block = _proxy_block("on", "brix_tap_proxy_upstream_tls on;",
                             f"brix_tap_proxy_upstream_tls_ca {ca_pem};",
                             "brix_tap_proxy_upstream_tls_verify on;")
        rc, out = _tls_t(tmp_path, block, "vfyon")
        assert rc == 0, out
        assert _diagnostics(out) == [], (
            "an authenticated upstream must not be warned about\n" + out)

        loud = _proxy_block("on", "brix_tap_proxy_upstream_tls on;",
                            f"brix_tap_proxy_upstream_tls_ca {ca_pem};",
                            "brix_tap_proxy_upstream_tls_verify off;")
        rc_off, out_off = _tls_t(tmp_path, loud, "vfyoff")
        assert rc_off == 0, out_off
        assert "the peer is UNVERIFIED and the hop is MITM-able" in out_off, (
            "the opt-out must say what it costs\n" + out_off)

    def test_the_explicit_verify_on_arm_still_fails_closed_without_a_ca(
            self, tmp_path):
        """security-neg: writing the arm the default already implies must not
        become a way to reach a different branch — no CA is still a refusal, and
        the message still names the escape hatch."""
        block = _proxy_block("on", "brix_tap_proxy_upstream_tls on;",
                             "brix_tap_proxy_upstream_tls_verify on;")
        rc, out = _tls_t(tmp_path, block, "vfynoca")
        assert rc != 0, "an explicit verify on with no CA MUST be refused\n" + out
        assert "refusing an unauthenticated, MITM-able TLS upstream" in out, out


# --------------------------------------------------------------------------- #
# §B — the live tier                                                           #
# --------------------------------------------------------------------------- #

def test_the_tap_proxy_off_arm_still_advertises_the_proxy_bit(lifecycle):
    """DEFECT CANDIDATE #88: `brix_tap_proxy off` with the upstream line left in
    place answers kXR_protocol with kXR_attrProxy (0x200) set.

    protocol.c:85 ORs the flag with `proxy.upstreams != NULL`, and nothing
    refuses an upstream whose proxy is off, so the bit tracks the plumbing rather
    than the switch.  The reading is on the wire, from a client's point of view,
    because that is the only place the defect is visible — every proxy code path
    in the process is inert.
    """
    root_port, _cms = _mgr(lifecycle, MGR,
                           f"brix_tap_proxy off; "
                           f"brix_tap_proxy_upstream {UPSTREAM};",
                           "audit-16l tap_proxy off + upstream still advertises")
    flags = _get_protocol_flags(SERVER_HOST, root_port)
    assert flags & _kXR_attrProxy, (
        f"the finding is that the bit IS set — if this server really tracked "
        f"its own flag the assertion would be the other way round; "
        f"flags={flags:#010x}")


def test_the_tap_proxy_off_arm_alone_advertises_nothing(lifecycle):
    """control: the same `off` arm without the upstream line clears the bit.

    This is what makes the reading above a statement about `proxy.upstreams` and
    not about the server's role: one line moves the bit, and it is not the flag.
    """
    root_port, _cms = _mgr(lifecycle, MGR, "brix_tap_proxy off;",
                           "audit-16l tap_proxy off, no upstream")
    flags = _get_protocol_flags(SERVER_HOST, root_port)
    assert not (flags & _kXR_attrProxy), (
        f"a server with no upstream must not claim to be a proxy; "
        f"flags={flags:#010x}")


def test_the_keepalive_on_arm_arms_the_accepted_socket(lifecycle):
    """success: the first reading of `brix_tcp_keepalive on`'s observable — the
    accepted control connection carries the kernel's keepalive timer.

    The directive has been in two configs since Phase 39, but only ever as a line
    nginx accepts; nothing has read the socket.  Without this arm the `off`
    reading below would be unfalsifiable.
    """
    _needs_ss()
    root_port, _cms = _mgr(lifecycle, MGR, "brix_tcp_keepalive on;",
                           "audit-16l root accept keepalive on")
    sock = _xrd_session(root_port)
    try:
        rest = _pending_timer(local_port=root_port)
        assert "keepalive" in rest, (
            f"brix_tcp_keepalive on must arm the accepted socket: {rest}")
    finally:
        sock.close()


def test_the_keepalive_off_arm_leaves_the_accepted_socket_bare(lifecycle):
    """the arm: the same session against the same server with the flag written
    off carries no timer, and the session is otherwise unaffected — the option is
    hardening, never a precondition, so a logged-in client stays logged in."""
    _needs_ss()
    root_port, _cms = _mgr(lifecycle, MGR, "brix_tcp_keepalive off;",
                           "audit-16l root accept keepalive off")
    sock = _xrd_session(root_port)
    try:
        rest = _pending_timer(local_port=root_port)
        assert "keepalive" not in rest, (
            f"brix_tcp_keepalive off must leave the kernel defaults: {rest}")
        # The connection the reading was taken on is still usable.
        flags = _get_protocol_flags(SERVER_HOST, root_port)
        assert flags, "the server stopped answering without the keepalive"
    finally:
        sock.close()


def test_the_explicit_cms_keepalive_on_arm_arms_the_upward_leg(lifecycle):
    """the arm: `brix_cms_tcp_keepalive on` written out reaches the same armed
    socket the default gives.

    The flag merges to 1, so the arm's risk is not that it disarms anything but
    that it is a spelling nobody has ever run — a merge that read a different
    field, or a directive wired to the wrong offset, would leave the socket bare
    while `nginx -t` stayed happy.  test_audit15f_cms_node_legs.py owns the
    default (armed) and the `off` arm (bare); this is the third spelling.
    """
    _needs_ss()
    stub = StubManager()
    try:
        _node(lifecycle, NODE, stub, "brix_cms_tcp_keepalive on;",
              "audit-16l cms client-leg keepalive explicit on")
        assert stub.wait(CMS_RR_LOGIN) is not None, "node never logged in"
        rest = _pending_timer(peer_port=stub.port)
        assert "keepalive" in rest, (
            f"an explicit brix_cms_tcp_keepalive on must arm the leg: {rest}")
    finally:
        stub.stop()
