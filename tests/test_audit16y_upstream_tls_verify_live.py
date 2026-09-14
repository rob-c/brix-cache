"""Audit 16y — `brix_upstream_tls_verify` on the wire, not in the source.

`src/protocols/root/stream/directives_net.h` declares the outbound redirector's
TLS controls, and the coverage census says the corpus writes
`brix_upstream_tls_verify off` twice and `on` never — the armed arm of the flag
that decides whether the leg authenticates the server it is about to re-send a
login to has never been written by a test at all.  `test_upstream_tls_verify.py`
covers the ends that can be read: the CTX build sets `SSL_VERIFY_PEER` plus
`X509_VERIFY_PARAM_set1_host`, both handshake-done callbacks abort on a bad
`SSL_get_verify_result`, and `nginx -t` refuses a TLS upstream with no CA.  It
says, in its own docstring, that the branch is "not drivable as a live negative
from this suite."

It is drivable.  What was missing was an upstream that finishes the bootstrap
and then presents a certificate the test chose — the fleet's `gotorls` stub
sends the kXR_gotoTLS flag and closes, one frame short of the handshake this
file is about.  `_test_audit16y_helpers.GotoTlsUpstream` goes the rest of the
way, so each of the eight planes below is a trust decision with a wire outcome:
a redirect that reached the client, or a refusal, and in the refusals whether
the login frame ever left this process.

Two things measured here are not what the code says they are.

  * `brix_upstream_tls_verify off` does not disable verification.  The
    belt-and-braces gate in `net/upstream/tls.c` calls it "harmless (X509_V_OK)
    when verification is off"; it is not.  With verification off and no CA, the
    peer's chain still has to validate against a trust store that was never
    populated, so the leg aborts every connection with "TLS peer verification
    failed" — after a completed handshake, which is how you can tell the
    refusal is ours.  The opt-out the EMERG message advertises ("set the CA, or
    brix_upstream_tls_verify off to opt out") does not exist (#103).
  * The pinned name falls back to the upstream host as spelled, and
    `X509_VERIFY_PARAM_set1_host` matches DNS names only.  An upstream written
    as an address literal therefore cannot be verified even by a certificate
    carrying the matching IP SAN — the same peer, the same certificate, and the
    same CA are accepted when the host is spelled as a name (#104).
"""

from contextlib import ExitStack, closing
import os
import re
import socket
import struct
import sys
import time

import pytest

from _test_audit16y_helpers import (REDIRECT_HOST, REDIRECT_PORT,
                                    GotoTlsUpstream, mint_cert)
from ephemeral_port import free_port
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, SERVER_HOST

# The client wire is test_zip_member.py's: handshake, login, kXR_open.
from test_zip_member import _open, _session, kXR_ok

NAME = "lc-audit16y-uptls"
_EXTRA = LIFECYCLE_SHARED_PORTS[NAME]["extra"]

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group(NAME)]

kXR_error = 4003
kXR_redirect = 4004
kXR_login = 3007
kXR_open = 3010
#: kXR_ServerError — what an aborted upstream leg reports to the client.
kXR_ServerError = 3012

MISSING = "/absent-locally.dat"
LOCAL = "/present.dat"


# --------------------------------------------------------------------------- #
# One nginx, eight planes, three stub upstreams.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def uptls(tmp_path_factory):
    root = tmp_path_factory.mktemp("a16y")
    export = root / "export"
    export.mkdir()
    (export / os.path.basename(LOCAL)).write_bytes(b"local hit\n")

    # `good` is both the peer certificate of the trusted stub and the CA file
    # the trusting planes are given; `other` is a valid chain for a host none of
    # the planes dial; `evil` is signed by nobody the planes trust.
    good_cert, good_key = mint_cert(root, "good", SERVER_HOST,
                                    f"DNS:{SERVER_HOST},IP:{HOST}")
    other_cert, other_key = mint_cert(root, "other", "elsewhere.example.org",
                                      "DNS:elsewhere.example.org")
    evil_cert, evil_key = mint_cert(root, "evil", SERVER_HOST,
                                    f"DNS:{SERVER_HOST},IP:{HOST}")

    with ExitStack() as cleanup:
        stubs = {}
        for name, port, cert, key in (
                ("good", _EXTRA["STUB_GOOD_PORT"], good_cert, good_key),
                ("evil", _EXTRA["STUB_EVIL_PORT"], evil_cert, evil_key),
                ("other", _EXTRA["STUB_OTHER_PORT"], other_cert, other_key)):
            # All DNS answers must reach this peer; retain hostname verification.
            stub = GotoTlsUpstream(SERVER_HOST, port, cert, key)
            stubs[name] = cleanup.enter_context(closing(stub))
        harness = cleanup.enter_context(closing(LifecycleHarness()))
        endpoint = harness.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_audit16y_upstream_tls_verify_live.conf",
            protocol="root", readiness="tcp", data_root=str(export),
            template_values={"BIND_HOST": BIND_HOST,
                             "UP_HOST": SERVER_HOST, "UP_IP": HOST,
                             "GOOD_CA": good_cert, "OTHER_CA": other_cert},
            reason="audit-16y the never-written armed arm of "
                   "brix_upstream_tls_verify, driven against a gotoTLS peer"))
        state = {"endpoint": endpoint, "stubs": stubs,
                 "ports": dict(_EXTRA, PORT=endpoint.port),
                 "log_dir": os.path.join(endpoint.prefix, "logs")}
        _wait_for_leg(state)
        # Refusals logged while the name was still unresolved belong to the
        # gate, not to any plane's trust decision, so the tests below count
        # only the ones that appear after it.
        state["unresolved_at_gate"] = _errlog(state).count(_UNRESOLVED)
        yield state


#: How long the outbound leg may take to become dialable after the listener
#: binds.  Phase-116 resolves `brix_upstream` names asynchronously:
#: `dns_target_arm()` schedules the first lookup 1-200 ms after worker init
#: (`DNS_FIRST_JITTER_MS`) and hands it to the thread pool, so the answer lands
#: some way after `readiness="tcp"` has already returned.
_LEG_READY_TIMEOUT = 20.0

#: What `brix_upstream_start()` logs for a name with no answer yet.
_UNRESOLVED = 'cannot resolve "'


def _wait_for_leg(state):
    """WHAT: block until the armed default plane's outbound leg really dials the
    `good` stub and completes its TLS handshake, and fail loudly if it never
    does within `_LEG_READY_TIMEOUT`.

    WHY: `readiness="tcp"` proves the listener is bound, not that the upstream
    name has an answer.  Seven of the eight planes spell the upstream as a DNS
    name, and phase-116 resolves those off the event loop; between the bind and
    the answer every one of them refuses the session with "cannot resolve"
    before a socket is dialled.  Five of this module's assertions are absences
    ("no login reached the peer", "nothing was forwarded"), and an undialled
    leg satisfies every one of them — the module would report green over a leg
    that never left the process.  The gate is what makes those absences mean
    something.

    HOW: drive the export-missing path through the armed default plane until
    the stub records `tls-established`, which nothing but a resolved name, a
    dialled socket and a verified peer can produce.  The stub is reset on the
    way out so the first real test still sees a clean slate.
    """
    good = state["stubs"]["good"]
    deadline = time.monotonic() + _LEG_READY_TIMEOUT
    attempts, kinds, last = 0, [], "none"
    while time.monotonic() < deadline:
        attempts += 1
        good.reset()
        # A leg that is not ready yet refuses or drops the session outright, so
        # a transport error here is a "not yet", not a failure to report: the
        # whole purpose of this gate is to absorb that window rather than let
        # it error out 36 tests at setup.
        try:
            sock = _session(state["ports"]["PORT"])
            try:
                _open(sock, MISSING)
            finally:
                sock.close()
        except (ConnectionError, OSError) as exc:
            last = f"{type(exc).__name__}: {exc}"
            time.sleep(0.2)
            continue
        kinds = good.wait_for_terminal()
        last = str(kinds)
        if "tls-established" in kinds:
            good.reset()
            return
        time.sleep(0.2)
    pytest.fail(
        f"the outbound leg never became dialable in {_LEG_READY_TIMEOUT}s over "
        f"{attempts} attempt(s); the last one ended {last}. Every absence "
        f"assertion in this module would have passed vacuously. Tail of "
        f"error.log:\n" + "\n".join(_errlog(state).splitlines()[-25:]))


def _drive(uptls, plane, stub, path=MISSING):
    """Open a path that is not in the export through `plane`, and return the
    client's answer together with what the stub upstream saw for that one leg."""
    upstream = uptls["stubs"][stub]
    upstream.reset()
    sock = _session(uptls["ports"][plane])
    try:
        status, body = _open(sock, path)
    finally:
        sock.close()
    if path == MISSING:
        return status, body, upstream.wait_for_terminal()
    return status, body, upstream.settle()


def _errmsg(body):
    return body[4:].split(b"\x00")[0].decode("utf-8", "replace")


def _errcode(body):
    return struct.unpack(">I", body[:4])[0]


def _errlog(uptls):
    with open(os.path.join(uptls["log_dir"], "error.log"),
              encoding="utf-8", errors="replace") as handle:
        return handle.read()


# --------------------------------------------------------------------------- #
# Success — a peer the CA signs and the pin names completes the upgrade.
# --------------------------------------------------------------------------- #
class TestTheVerifiedUpgradeCompletes:
    def test_default_arm_reaches_the_upstream_redirect(self, uptls):
        status, body, _ = _drive(uptls, "PORT", "good")
        assert status == kXR_redirect, f"expected the stub's redirect, got {status}"
        assert struct.unpack(">I", body[:4])[0] == REDIRECT_PORT
        assert body[4:].decode() == REDIRECT_HOST

    def test_default_arm_upgraded_and_relogged_in_over_tls(self, uptls):
        _, _, kinds = _drive(uptls, "PORT", "good")
        assert "tls-established" in kinds
        assert "tls-login" in kinds, f"no login over TLS: {kinds}"

    def test_default_arm_forwards_the_client_open_over_tls(self, uptls):
        upstream = uptls["stubs"]["good"]
        _drive(uptls, "PORT", "good")
        assert upstream.details("forwarded-request") == [str(kXR_open)]

    def test_the_relogin_is_a_login_frame(self, uptls):
        upstream = uptls["stubs"]["good"]
        _drive(uptls, "PORT", "good")
        assert upstream.details("tls-login") == [str(kXR_login)]

    def test_written_on_behaves_exactly_like_the_default(self, uptls):
        status, body, kinds = _drive(uptls, "ON_PORT", "good")
        assert status == kXR_redirect
        assert body[4:].decode() == REDIRECT_HOST
        assert kinds.count("tls-established") == 1
        assert "tls-login" in kinds

    def test_written_on_leaves_the_same_trace_as_the_default(self, uptls):
        _, _, written = _drive(uptls, "ON_PORT", "good")
        _, _, defaulted = _drive(uptls, "PORT", "good")
        assert written == defaulted, "the armed arm is not a second code path"

    def test_the_bootstrap_pre_sends_a_cleartext_login(self, uptls):
        """The leg's own contract, and the reason the stub drains it: handshake,
        protocol and login go out in one write, before any peer is trusted."""
        _, _, kinds = _drive(uptls, "PORT", "good")
        assert kinds.index("cleartext-login") < kinds.index("tls-established")
        assert uptls["stubs"]["good"].details("cleartext-login") == [str(kXR_login)]


# --------------------------------------------------------------------------- #
# Error — a peer no configured CA signs is refused, and refused early.
# --------------------------------------------------------------------------- #
class TestAnUnsignedPeerIsRefused:
    def test_the_client_is_told_the_leg_failed(self, uptls):
        status, body, _ = _drive(uptls, "EVIL_PORT", "evil")
        assert status == kXR_error
        assert _errcode(body) == kXR_ServerError
        assert _errmsg(body) == "upstream: TLS handshake failed"

    def test_the_handshake_never_completed(self, uptls):
        _, _, kinds = _drive(uptls, "EVIL_PORT", "evil")
        assert "tls-refused" in kinds, kinds
        assert "tls-established" not in kinds

    def test_no_login_reached_the_untrusted_peer(self, uptls):
        _, _, kinds = _drive(uptls, "EVIL_PORT", "evil")
        # A positive witness first: an undialled leg satisfies every
        # absence below, so the absences only mean something once the
        # peer has been reached and refused.
        assert "tls-refused" in kinds, f"the leg never reached the peer: {kinds}"
        assert "tls-login" not in kinds
        assert "forwarded-request" not in kinds

    def test_openssl_named_the_reason(self, uptls):
        _drive(uptls, "EVIL_PORT", "evil")
        log = _errlog(uptls)
        assert "SSL_do_handshake() failed" in log
        assert "certificate verify failed" in log

    def test_the_client_request_is_never_forwarded(self, uptls):
        """Security-negative: the sensitive work — re-login and then the client's
        own request — must not happen on an unauthenticated channel."""
        upstream = uptls["stubs"]["evil"]
        _, _, kinds = _drive(uptls, "EVIL_PORT", "evil")
        # A positive witness first: an undialled leg satisfies every
        # absence below, so the absences only mean something once the
        # peer has been reached and refused.
        assert "tls-refused" in kinds, f"the leg never reached the peer: {kinds}"
        assert upstream.details("forwarded-request") == []
        assert upstream.details("tls-login") == []


# --------------------------------------------------------------------------- #
# The pinned name — which spelling of the upstream a certificate must carry.
# --------------------------------------------------------------------------- #
class TestTheHostnamePin:
    def test_a_valid_chain_for_the_wrong_host_is_refused(self, uptls):
        status, body, kinds = _drive(uptls, "HOSTPIN_PORT", "other")
        assert status == kXR_error
        assert _errmsg(body) == "upstream: TLS handshake failed"
        assert "tls-refused" in kinds, "the chain validates; the name must not"

    def test_the_wrong_host_peer_sees_no_login(self, uptls):
        _, _, kinds = _drive(uptls, "HOSTPIN_PORT", "other")
        # A positive witness first: an undialled leg satisfies every
        # absence below, so the absences only mean something once the
        # peer has been reached and refused.
        assert "tls-refused" in kinds, f"the leg never reached the peer: {kinds}"
        assert "tls-login" not in kinds

    def test_an_unpinned_plane_falls_back_to_the_upstream_spelling(self, uptls):
        status, body, kinds = _drive(uptls, "FALLBACK_PORT", "good")
        assert status == kXR_redirect, "the DNS spelling is in the certificate"
        assert body[4:].decode() == REDIRECT_HOST
        assert "tls-login" in kinds

    def test_an_address_literal_upstream_cannot_be_verified(self, uptls):
        """DEFECT CANDIDATE #104 — the pin is set through
        X509_VERIFY_PARAM_set1_host, which matches DNS names only, so an
        upstream written as an address literal fails against a certificate that
        carries the matching IP SAN."""
        status, body, kinds = _drive(uptls, "IP_PIN_PORT", "good")
        assert status == kXR_error
        assert _errmsg(body) == "upstream: TLS handshake failed"
        assert "tls-established" not in kinds

    def test_the_literal_failure_is_a_certificate_failure(self, uptls):
        _drive(uptls, "IP_PIN_PORT", "good")
        log = _errlog(uptls)
        assert "certificate verify failed" in log
        assert "no live upstreams" not in log

    def test_the_same_peer_and_ca_differ_only_by_spelling(self, uptls):
        """The A/B that makes #104 a defect rather than a misconfiguration: one
        stub, one certificate, one CA, two ways of writing the same host."""
        by_name, _, _ = _drive(uptls, "FALLBACK_PORT", "good")
        by_literal, _, _ = _drive(uptls, "IP_PIN_PORT", "good")
        assert by_name == kXR_redirect
        assert by_literal == kXR_error


# --------------------------------------------------------------------------- #
# The documented opt-out — what `verify off` actually turns off.
# --------------------------------------------------------------------------- #
class TestTheDocumentedOptOut:
    def test_verify_off_without_a_ca_still_refuses_every_peer(self, uptls):
        """DEFECT CANDIDATE #103 — the escape hatch the EMERG message names
        ("set the CA, or brix_upstream_tls_verify off to opt out") cannot be
        used: with no CA there is nothing for the belt-and-braces gate's
        SSL_get_verify_result to succeed against."""
        status, body, _ = _drive(uptls, "NOCA_OFF_PORT", "evil")
        assert status == kXR_error
        assert _errcode(body) == kXR_ServerError

    def test_the_refusal_is_ours_not_the_handshakes(self, uptls):
        status, body, kinds = _drive(uptls, "NOCA_OFF_PORT", "evil")
        assert _errmsg(body) == "upstream: TLS peer verification failed"
        assert "tls-established" in kinds, "the handshake itself succeeded"

    def test_the_opted_out_plane_still_fails_closed(self, uptls):
        _, _, kinds = _drive(uptls, "NOCA_OFF_PORT", "evil")
        # A positive witness first: an undialled leg satisfies every
        # absence below, so the absences only mean something once the
        # peer has been reached and refused.
        assert "tls-established" in kinds, f"the leg never handshook: {kinds}"
        assert "tls-login" not in kinds
        assert "forwarded-request" not in kinds

    def test_verify_off_with_a_ca_drops_the_name_check(self, uptls):
        status, body, kinds = _drive(uptls, "CA_OFF_PORT", "other")
        assert status == kXR_redirect, "the chain validates, the name does not"
        assert body[4:].decode() == REDIRECT_HOST
        assert "tls-login" in kinds

    def test_the_relaxed_plane_hands_its_login_to_the_wrong_host(self, uptls):
        """Security-negative: this is what the config-time WARN means by
        "UNVERIFIED … MITM-able" — the same peer that plane 6 refuses gets the
        leg's login here, and the only difference between the two is the arm."""
        _, _, relaxed = _drive(uptls, "CA_OFF_PORT", "other")
        _, _, armed = _drive(uptls, "HOSTPIN_PORT", "other")
        assert "tls-login" in relaxed
        assert "tls-login" not in armed

    def test_reaching_the_relaxed_plane_is_loud_at_config_time(self, uptls):
        log = _errlog(uptls)
        assert "brix_upstream_tls_verify is off" in log
        assert "MITM-able" in log


# --------------------------------------------------------------------------- #
# Config-time verdicts, counted against the eight planes that produced them.
# --------------------------------------------------------------------------- #
class TestTheConfigTimeVerdicts:
    @staticmethod
    def _parses(log):
        """Each parse of this config emits the enable line once per plane."""
        enabled = log.count("upstream redirector TLS enabled")
        assert enabled and enabled % 8 == 0, f"{enabled} enable lines for 8 planes"
        return enabled // 8

    def test_every_plane_announces_the_gototls_leg(self, uptls):
        assert self._parses(_errlog(uptls)) >= 1

    def test_six_planes_announce_peer_verification(self, uptls):
        log = _errlog(uptls)
        notices = log.count("peer verification (chain + host) enabled")
        assert notices == 6 * self._parses(log), \
            "the six CA-bearing armed planes each log one NOTICE"

    def test_the_ca_bearing_opt_out_warns_once(self, uptls):
        log = _errlog(uptls)
        warned = len(re.findall(
            r"CA loaded from .* but brix_upstream_tls_verify is off", log))
        assert warned == self._parses(log)

    def test_the_ca_less_opt_out_warns_separately(self, uptls):
        log = _errlog(uptls)
        warned = log.count("verification explicitly off and no CA")
        assert warned == self._parses(log)


# --------------------------------------------------------------------------- #
# The planes are eight listeners in one worker over one export.
# --------------------------------------------------------------------------- #
class TestEightPlanesOneWorker:
    def test_a_local_hit_never_dials_the_upstream(self, uptls):
        status, _, kinds = _drive(uptls, "PORT", "good", path=LOCAL)
        assert status == kXR_ok
        assert kinds == [], f"a served path must not start a leg: {kinds}"

    def test_every_plane_logs_a_client_in(self, uptls):
        planes = ["PORT", "ON_PORT", "EVIL_PORT", "NOCA_OFF_PORT", "CA_OFF_PORT",
                  "HOSTPIN_PORT", "IP_PIN_PORT", "FALLBACK_PORT"]
        for plane in planes:
            sock = _session(uptls["ports"][plane])
            try:
                status, _ = _open(sock, LOCAL)
            finally:
                sock.close()
            assert status == kXR_ok, f"{plane} did not serve the local export"

    def test_one_pid_owns_all_eight(self, uptls):
        with open(uptls["endpoint"].pidfile, encoding="utf-8") as handle:
            pid = int(handle.read().strip())
        assert os.path.isdir(f"/proc/{pid}")

    def test_the_stub_ports_are_the_only_other_listeners(self, uptls):
        for name in ("STUB_GOOD_PORT", "STUB_EVIL_PORT", "STUB_OTHER_PORT"):
            with socket.create_connection((HOST, _EXTRA[name]), timeout=5):
                pass


# --------------------------------------------------------------------------- #
# The leg has to be dialable before any of the above is a trust decision.
# Phase-116 moved `brix_upstream` onto the async DNS seam (`directives.c`
# registers the target, `start.c` reads it through `brix_dns_target_next()`),
# and seven of the eight planes spell their upstream as a name.  Between the
# listener binding and the first answer landing, those planes refuse every
# session with `cannot resolve` before a socket is dialled — which is exactly
# what most of this module asserts the *absence* of.
# --------------------------------------------------------------------------- #
class TestTheLegIsActuallyDialed:
    def test_the_leg_is_dialable_once_the_gate_has_passed(self, uptls):
        """Success: the fixture's readiness gate is what this module stands on,
        so it gets an assertion of its own rather than only being relied on."""
        _, _, kinds = _drive(uptls, "PORT", "good")
        assert "tls-established" in kinds, f"the gate passed but the leg is dead: {kinds}"
        assert "tls-login" in kinds

    def test_no_plane_is_judged_while_the_upstream_is_unresolved(self, uptls):
        """Error: every `cannot resolve` belongs to the gate's own warm-up.  A
        new one means a plane was judged on a leg that never dialled, and every
        absence assertion in this module was vacuous for that run."""
        after = _errlog(uptls).count(_UNRESOLVED)
        assert after == uptls["unresolved_at_gate"], (
            f"{after - uptls['unresolved_at_gate']} session(s) were refused "
            f"with an unresolved upstream after the readiness gate passed")

    def test_an_absence_alone_cannot_tell_a_refusal_from_an_undialled_leg(self, uptls):
        """Security-negative: this is the shape the module was reporting green
        in.  A path served from the export never starts a leg, so it satisfies
        every absence the refused peer does — no login, nothing forwarded.  The
        two are separable only by the positive witness, which is why the four
        refusal tests above now demand one."""
        _, _, served = _drive(uptls, "PORT", "good", path=LOCAL)
        _, _, refused = _drive(uptls, "EVIL_PORT", "evil")
        for kinds in (served, refused):
            assert "tls-login" not in kinds
            assert "forwarded-request" not in kinds
        assert served == [], f"a served path must not start a leg: {served}"
        assert "tls-refused" in refused, (
            "the refusal is indistinguishable from never having dialled")

    def test_the_address_literal_plane_never_waited_on_a_name(self, uptls):
        """The one plane the race cannot reach: an address literal is final at
        registration, so its verdict was never in question — and it is still
        the #104 refusal, not a resolve failure."""
        _drive(uptls, "IP_PIN_PORT", "good")
        log = _errlog(uptls)
        assert "certificate verify failed" in log
        assert f'{_UNRESOLVED}{HOST}"' not in log, \
            "the literal plane went through the resolver"

    def test_the_gate_absorbs_a_transport_error_but_still_refuses_to_pass(
            self, uptls, monkeypatch):
        """Error: the gate's own first live run errored all 36 tests at setup,
        because a session closed by a leg that was not ready yet propagated out
        of the retry loop instead of counting as "not yet".  A gate that cannot
        survive the very window it exists to absorb is worse than no gate — it
        converts a wait into 36 setup errors.  The other half matters just as
        much: absorbing the error must not become a way to pass.  Pointed at a
        port nothing listens on, the gate has to keep retrying and then fail
        loudly, naming the attempts and the last transport error.
        """
        dead = dict(uptls)
        dead["ports"] = dict(uptls["ports"], PORT=free_port())
        monkeypatch.setattr(sys.modules[__name__], "_LEG_READY_TIMEOUT", 1.0)
        with pytest.raises(pytest.fail.Exception) as caught:
            _wait_for_leg(dead)
        message = str(caught.value)
        assert "never became dialable" in message
        assert "attempt(s)" in message, "the gate must say how hard it tried"
        assert "vacuously" in message, \
            "the gate must say what a silent pass would have meant"
