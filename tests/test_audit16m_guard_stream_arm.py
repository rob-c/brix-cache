"""`brix_guard_stream off` — the last unwritten arm in directives_cms.h.

WHY THIS FILE EXISTS
--------------------
Tranche 16 measures flag coverage at (directive, value) granularity.  Twelve of
`directives_cms.h`'s flags had an arm that no config, test or document in the
corpus ever wrote; eleven are closed by test_audit16k_cms_select_flag_arms.py
and test_audit16l_relay_flag_arms.py.  This is the twelfth:

    brix_guard_stream    on: nginx_lc_stream_guard_relay.conf   off: NOWHERE

The bad-actor guard is the one flag of the twelve whose subsystem is a security
control, which makes the unwritten arm the more interesting one: `off` is an
operator switching a protection OFF, and what a switched-off protection does is
worth a reading of its own.

WHY "OFF" IS NOT THE SAME QUESTION AS "ABSENT"
----------------------------------------------
`test_stream_guard.py` already runs an unguarded relay — but it builds it by
writing NO directive (`GUARD_DIRECTIVE: ""`), and reads the guard's absence off
the audit log.  The merge is `ngx_conf_merge_value(conf->relay_guard_enable,
prev->relay_guard_enable, 0)` (server_conf_merge_proxy_net.c:46), so absent and
`off` both arrive at 0 — but they arrive there by different routes, and the route
matters here more than in most of the tranche:

    conf->relay_guard_enable == 1        (relay/relay.c:367)

is what relay.c passes to `brix_relay_guard_init`, and NGX_CONF_UNSET is -1 while
an explicit `off` is 0.  A comparison written `!= 0` instead of `== 1` would turn
the *unset* case into an enabled guard, and no existing test would see it: the
absent case is the one every other config takes.  Writing `off` is what pins the
two routes to the same behaviour, and the truth-table reading below (`on` drops,
`off` does not, and `off` looks exactly like absent) is what makes it a pin
rather than a coincidence.

WHAT WAS ALREADY OWNED
----------------------
`test_stream_guard.py` owns the guard itself: clean ops relayed byte-exact, the
four non-root wire signatures dropped with a `signal=notroot` audit line naming
the wire, the junk-path signature, the kXR_NotFound post-signal, fragmentation
fail-open, and the unguarded (absent) relay classifying nothing.  Nothing here
re-reads any of that; the `on` relay appears only as the control that proves the
probe can see a drop at all, and the origin appears only so the relay has
somewhere to forward to.

Run:
    PYTHONPATH=tests pytest tests/test_audit16m_guard_stream_arm.py -v
"""

import os
import pathlib
import socket
import time

import pytest

from guard_http_lib import NGINX_BIN
from server_registry import NginxInstanceSpec
from settings import BIND_HOST
# The parse scaffold and its diagnostic filter (tranche file 10).
from test_audit16j_root_caps_flags import _diagnostics, _parse
# The relay probe and the audit-line reader belong to the guard's own suite.
from test_stream_guard import _guard_lines, _raw_probe

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.timeout(180),
              # The three ledger slots below are test_stream_guard.py's.
              pytest.mark.xdist_group("lc-stream-guard")]

FLAG = "brix_guard_stream"

# The wire the guard's first-bytes classifier calls "http-request".  One shape is
# enough: the four-shape sweep is test_stream_guard.py's, and this file is about
# whether the classifier runs at all.
NONROOT = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"


@pytest.fixture()
def relays(lifecycle, tmp_path):
    """An origin behind two relays: one with the flag written `off`, one with it
    written `on`.  Both arms in one process-set, so the pair below differs in
    exactly one token."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    # brix_export is validated at config-parse time, so seed it before start().
    export = tmp_path / "export"
    export.mkdir()
    (export / "f.bin").write_bytes(b"guard-arm-payload\n")

    origin = lifecycle.start(NginxInstanceSpec(
        name="lc-stream-guard-origin",
        template="nginx_lc_stream_guard_origin.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "EXPORT_DIR": str(export)},
        reason="audit-16m guard-arm origin (anon root:// export)"))
    off = lifecycle.start(NginxInstanceSpec(
        name="lc-stream-guard-unguarded",
        template="nginx_lc_stream_guard_relay.conf",
        protocol="root",
        # Spelled out rather than built from FLAG: the audit's own step-1/step-2
        # measurement is a grep for `<directive> <value>;` over the corpus, so an
        # arm assembled at runtime would still read as unwritten in the very
        # measurement this file exists to close.
        template_values={"BIND_HOST": BIND_HOST, "ORIGIN_PORT": origin.port,
                         "GUARD_DIRECTIVE": "brix_guard_stream off;"},
        reason="audit-16m relay with brix_guard_stream written off"))
    on = lifecycle.start(NginxInstanceSpec(
        name="lc-stream-guard-guarded",
        template="nginx_lc_stream_guard_relay.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "ORIGIN_PORT": origin.port,
                         "GUARD_DIRECTIVE": "brix_guard_stream on;"},
        reason="audit-16m control relay with the guard on"))
    return {
        "origin_port": origin.port,
        "off_port": off.port, "on_port": on.port,
        "off_logs": pathlib.Path(off.prefix) / "logs",
        "on_logs": pathlib.Path(on.prefix) / "logs",
    }


# --------------------------------------------------------------------------- #
# §A — the parse tier                                                          #
# --------------------------------------------------------------------------- #

class TestTheParseTier:

    @pytest.mark.parametrize("arm", ("on", "off"))
    def test_both_arms_are_accepted_in_a_stream_server(self, tmp_path, arm):
        rc, out = _parse(tmp_path, KNOBS=f"        {FLAG} {arm};\n")
        assert rc == 0, out

    @pytest.mark.parametrize("value", ("1", "enabled"))
    def test_a_value_outside_the_two_arms_is_refused(self, tmp_path, value):
        rc, out = _parse(tmp_path, KNOBS=f"        {FLAG} {value};\n")
        assert rc != 0, f"{FLAG} {value} was accepted: {out}"

    def test_the_directive_takes_exactly_one_argument(self, tmp_path):
        rc, out = _parse(tmp_path, KNOBS=f"        {FLAG} on off;\n")
        assert rc != 0, out
        assert "invalid number of arguments" in out, out

    def test_a_duplicate_is_refused(self, tmp_path):
        rc, out = _parse(tmp_path,
                         KNOBS=f"        {FLAG} off;\n        {FLAG} on;\n")
        assert rc != 0, out
        assert "duplicate" in out, out

    @pytest.mark.parametrize("slot", ("STREAM_KNOBS", "HTTP_KNOBS", "OUTER"))
    def test_every_other_placement_is_refused(self, tmp_path, slot):
        """Declared NGX_STREAM_SRV_CONF and nothing else (directives_cms.h:318-323),
        so the parent value its merge reads can never be written."""
        rc, out = _parse(tmp_path, **{slot: f"    {FLAG} on;\n"})
        assert rc != 0, out
        assert "is not allowed here" in out, out
        assert "unknown directive" not in out, out

    def test_the_off_arm_is_accepted_without_a_relay_and_says_nothing(
            self, tmp_path):
        """A server with no transparent proxy at all may still write the flag —
        it is a plain server-scope flag, not a relay sub-directive — and writing
        the arm that disables a feature must not advise anything."""
        rc, out = _parse(tmp_path, KNOBS=f"        {FLAG} off;\n")
        assert rc == 0, out
        assert _diagnostics(out) == [], out


# --------------------------------------------------------------------------- #
# §B — the live arm                                                            #
# --------------------------------------------------------------------------- #

def test_the_on_arm_drops_the_nonroot_client(relays):
    """control: the guarded relay tears the connection down and says why.

    Not a re-reading of test_stream_guard.py's sweep — it is what makes the
    `off` reading below falsifiable, on this probe, in this process-set.
    """
    dropped = _raw_probe(relays["on_port"], NONROOT)
    assert dropped, "the control relay did not drop a non-root client"

    deadline = time.time() + 5
    lines = []
    while time.time() < deadline:
        lines = [ln for ln in _guard_lines(relays["on_logs"])
                 if "signal=notroot" in ln]
        if lines:
            break
        time.sleep(0.1)
    assert lines, f"no notroot audit line: {_guard_lines(relays['on_logs'])}"


def test_the_off_arm_never_classifies_the_same_client(relays):
    """the arm: the same bytes through the relay whose flag is written `off` are
    not classified — no verdict, no audit line, no drop by the guard.

    The connection's fate afterwards is the origin's business (a root:// server
    handed an HTTP request may close it itself), so the reading is the guard's
    own trace: an empty audit log.  That is precisely the difference between a
    guard that ran and found nothing and a guard that never ran.
    """
    _raw_probe(relays["off_port"], NONROOT)
    time.sleep(0.5)
    assert _guard_lines(relays["off_logs"]) == [], (
        "a relay with brix_guard_stream off must classify nothing: "
        f"{_guard_lines(relays['off_logs'])}")


def test_the_off_arm_still_relays_a_root_client(relays):
    """the arm, other half: switching the guard off must not switch the relay
    off.  A genuine kXR handshake through the `off` relay is answered — the
    server-side handshake reply comes back — so the arm removes the classifier
    and nothing else.
    """
    # kXR ClientInitHandShake: 12 zeros, then htonl(4), htonl(2012).
    handshake = bytes(12) + bytes([0, 0, 0, 4]) + bytes([0, 0, 0x07, 0xDC])
    with socket.create_connection((BIND_HOST, relays["off_port"]),
                                  timeout=5) as sock:
        sock.sendall(handshake)
        sock.settimeout(5)
        reply = sock.recv(16)
    assert len(reply) == 16, (
        f"the off relay must still carry a root session: got {reply!r}")
    assert _guard_lines(relays["off_logs"]) == [], (
        f"nothing may be classified: {_guard_lines(relays['off_logs'])}")


def test_the_off_arm_is_indistinguishable_from_absent(relays, lifecycle):
    """security-neg: `off` and absent must reach the same disabled guard.

    relay.c:367 compares `conf->relay_guard_enable == 1`, and the two routes to
    "disabled" carry different values — NGX_CONF_UNSET (-1) when nothing is
    written, 0 when `off` is.  A comparison relaxed to `!= 0` would enable the
    guard for the unwritten case that every other config in the tree uses.  This
    reading pins both routes to the same observable behaviour.

    One instance, one port, one log, reconfigured between the two spellings: the
    ledger owns three relay slots and all three are already in use above, and
    swapping the directive in place is the stricter comparison anyway — nothing
    but the token under test differs between the two halves.
    """
    _raw_probe(relays["off_port"], NONROOT)
    time.sleep(0.5)
    after_off = _guard_lines(relays["off_logs"])

    lifecycle.reconfigure("lc-stream-guard-unguarded", GUARD_DIRECTIVE="")
    lifecycle.restart("lc-stream-guard-unguarded")

    _raw_probe(relays["off_port"], NONROOT)
    time.sleep(0.5)
    after_absent = _guard_lines(relays["off_logs"])

    assert after_off == [] and after_absent == [], (
        f"both routes to a disabled guard must classify nothing: "
        f"off={after_off} absent={after_absent}")
