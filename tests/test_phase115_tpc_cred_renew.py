"""phase-115 W8.2 — mid-transfer renewal of a native-TPC delegated credential.

A third-party copy that runs for hours outlives the credential that launched
it: `tpc_fetch_delegated_token()` is called exactly once, at bootstrap, and
nothing looked at the token's lifetime again.  W8.2 samples the credential once
per streamed chunk (`tpc_cred_renew_if_due`, src/tpc/outbound/tpc_token_renew.c)
and, when it is inside `brix_tpc_outbound_renew_lead` of expiry, mints a fresh
one and re-presents it to the source with a second ztn kXR_auth on the LIVE
connection — which works because `brix_handle_auth_inner()` accepts a repeat
kXR_auth on a logged-in session (src/auth/gsi/auth.c).

The pure decision half is proved exhaustively by tests/c/test_tpc_cred_renew.c
(`test_c_simple_unit[tpc_cred_renew]`).  This suite drives the wire leg live and
pins the four gates that stand between a chunk boundary and an issuer round
trip, each of which exists because of a distinct way renewal could do harm:

  * REN-01 success — a due credential is renewed mid-transfer and the copy
    completes byte-exact; the mock IdP is contacted twice (bootstrap + renewal).
  * REN-02 anti-storm — an issuer whose lifetime is shorter than the configured
    lead would otherwise mint once per megabyte; renewal disables itself for the
    transfer after one such renewal, with the reason in the log.
  * REN-03 off by default — with no `brix_tpc_outbound_renew_lead` the IdP is
    contacted exactly once, as before W8.2.
  * REN-04 ample lifetime — a lead well inside the credential's remaining life
    renews nothing.
  * REN-05 scoping — a pull that authenticated ANONYMOUSLY has no ztn credential
    in play and is never sent a renewal kXR_auth, whatever the lead says.
  * REN-06 error — an issuer that fails the renewal of an already-expired
    credential fails the pull with kXR_AuthFailed, rather than streaming on.
  * REN-07 security-negative — the DEFAULT token mode ("passthrough-opt")
    forwards a credential it has no authority to re-mint: the IdP is never
    contacted at all, and the pull continues.
  * REN-08 security-negative — the same pull under
    `brix_tpc_outbound_renew_strict on` is refused instead, and still never
    contacts the IdP.

Construction note: the sources run `brix_token_clock_skew 300`, so a token the
DESTINATION reads as expired is still accepted by the SOURCE.  That is what
makes "expired mid-transfer" reachable in a sub-second copy: the two sides
disagree about the same token on purpose, which is exactly the situation the
feature exists for (the destination notices before the source stops honouring
it).

300 is the CEILING, not a round number: `shared_conf_merge.h` rejects anything
above it with EMERG at `nginx -t` ("capped at 300s, security clamp against unit
confusion"), a phase-105 W8 clamp that moved out of webdav so every HTTP
protocol enforces it.  This file was written against 3600 and therefore never
started an instance at all — all nine tests ERRORed in the fixture, which is
why the value is pinned by `test_the_lab_skew_is_inside_the_security_clamp`
below rather than left as a literal nobody re-checks.
"""

import json
import os
import re
import struct
import threading
import time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS
from server_registry import NginxInstanceSpec
from settings import HOST, TOKENS_DIR
from tokenforge import TokenForge
from test_audit15c_tpc_token_exchange import (KXR_AUTH_FAILED, KXR_OK,
                                              _arm_source, _drive_pull,
                                              _wait_file)
from test_phase25_ratelimit import _xrd_login, _xrd_open, _xrd_recv_status

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-p115-tpc-renew")]

KXR_ERROR = 4003
MOCK_PORT = LIFECYCLE_SHARED_PORTS["lc-p115-renew-dst"]["extra"]["MOCK_PORT"]

#: 3 MiB — three 1 MiB read windows, so the renewal sample point is reached
#: more than once and a per-chunk mint storm would be visible as >2 IdP hits.
#: Repo root, for the two guards at the bottom that read the C clamp
#: rather than trusting a literal (see `_clamp_ceiling`).
REPO_ROOT = Path(__file__).resolve().parent.parent

SEED = (b"p115-w82-renewal-payload\n" * 40) * 3072
FRESH_TTL = 300      # the mock's "good" credential: valid, but inside the lead
STALE_TTL = -60      # expired for the destination, still inside the 300s source skew


def _issuer():
    """The signing forge whose JWKS the sources trust (`nginx_token_strict`
    idiom): issuer https://test.example.com, audience nginx-xrootd."""
    return TokenForge(TOKENS_DIR)


@pytest.fixture()
def idp():
    """A minting IdP, not merely a capturing one.

    Every path answers an RFC 8693-shaped body whose access_token is a REAL
    signed JWT from the conformance forge, because the destination now reads the
    token's own `exp` and the source validates its signature — an opaque string
    (what test_audit15c's mock returns) would leave the lifetime unknown and
    renewal permanently inert.  `/once` answers a token the first time and 500
    afterwards, which is how a renewal failure is made deterministic.
    """
    forge = _issuer()
    hits = []

    class Handler(BaseHTTPRequestHandler):
        def _drain(self):
            """Consume the request body, so the connection stays reusable."""
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)

        def _reply(self, code, body=b""):
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _spent(self):
            """True once /once has already answered — its second call is the
            deterministic renewal failure."""
            if not self.path.startswith("/once"):
                return False
            return sum(1 for h in hits
                       if h["path"].startswith("/once")) > 1

        def _ttl(self):
            return STALE_TTL if self.path.startswith(("/stale", "/once")) \
                else FRESH_TTL

        def _serve(self):
            self._drain()
            hits.append({"path": self.path, "at": time.time()})
            if self._spent():
                self._reply(500)
                return
            self._reply(200, json.dumps(
                {"access_token": forge.temporal(self._ttl())}).encode())

        do_GET = do_POST = _serve

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer((HOST, MOCK_PORT), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield hits
    server.shutdown()
    server.server_close()


# --------------------------------------------------------------------------- #
# Wire helpers                                                                 #
# --------------------------------------------------------------------------- #

def _auth_ztn(s, token):
    """kXR_auth with credtype `ztn`, framed as XrdCl frames it (the blob
    repeats the 4-byte tag ahead of the bearer).  The arm leg needs this
    because the renewal source demands token auth — which is the whole point:
    only a source that authenticates the destination makes `cred_presented`
    true, and only then may a renewal kXR_auth be sent."""
    cred = b"ztn\x00" + token.encode()
    s.sendall(struct.pack(">BBH12s4sI", 0, 1, 3000, b"\x00" * 12, b"ztn\x00",
                          len(cred)) + cred)
    return _xrd_recv_status(s)


def _arm_token_source(src_port, key, token):
    """`_arm_source` for a token-authenticating source: login, ztn, then the
    tpc.key read-open that registers the rendezvous."""
    s = _xrd_login(HOST, src_port)
    status, body = _auth_ztn(s, token)
    assert status == KXR_OK, ("arm ztn auth refused", status, body)
    status, body = _xrd_open(
        s, f"/src.bin?tpc.key={key}&tpc.dst=127.0.0.1&tpc.stage=placement")  # net-literal-allow: local TPC wire payload
    assert status == KXR_OK, ("TPC source arm open refused", status, body)
    return s


def _dst_open(s, path, src_port, key, mode=None):
    """Destination write-open.  `mode=None` deliberately omits tpc.token_mode
    so the server's own default ("passthrough-opt", launch_prepare.c) selects
    itself — that default is the subject of REN-07/REN-08."""
    opaque = (f"?tpc.src=127.0.0.1:{src_port}&tpc.key={key}"  # net-literal-allow: local TPC wire payload
              f"&tpc.lfn=/src.bin&tpc.stage=copy&oss.asize={len(SEED)}")
    if mode is not None:
        opaque += f"&tpc.token_mode={mode}"
    payload = (path + opaque).encode()
    # kXR_new | kXR_open_wrto | kXR_mkpath
    body = struct.pack(">HH12s", 0o644, 0x0008 | 0x4000 | 0x0100, b"\x00" * 12)
    s.sendall(struct.pack(">BBH", 0, 1, 3010) + body
              + struct.pack(">I", len(payload)) + payload)
    return _xrd_recv_status(s)


def _errcode(body):
    return struct.unpack(">I", body[:4])[0] if len(body) >= 4 else None


def _elog(endpoint):
    return os.path.join(endpoint.prefix, "logs", "error.log")


def _wait_log(endpoint, pattern, timeout=20.0):
    """Block until ``pattern`` appears in the instance's error log."""
    rx = re.compile(pattern)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(_elog(endpoint)) as fh:
                for line in fh:
                    if rx.search(line):
                        return True
        except FileNotFoundError:
            pass
        time.sleep(0.1)
    return False


def _log_count(endpoint, pattern):
    rx = re.compile(pattern)
    try:
        with open(_elog(endpoint)) as fh:
            return sum(1 for line in fh if rx.search(line))
    except FileNotFoundError:
        return 0


# --------------------------------------------------------------------------- #
# The lab                                                                      #
# --------------------------------------------------------------------------- #

def _indent(*lines):
    return "".join(f"        {line}\n" for line in lines)


@pytest.fixture()
def renewlab(lifecycle, tmp_path, idp):
    """One export, one token-demanding source, five outbound-credential shapes.

    The source is the only instance with `brix_auth token`: it is what makes the
    destination present a ztn credential at all, and therefore the only setting
    in which renewal is even reachable.  `brix_token_clock_skew 300` — the
    widest LEGAL grace, see the module docstring — is not laxity for its own
    sake: it is what lets one token be simultaneously
    ACCEPTED by the source and EXPIRED to the destination's own
    `brix_token_peek_exp`, which is the exact disagreement the feature is built
    to survive, reproduced in under a second instead of over an hour.
    """
    data = tmp_path / "data"
    data.mkdir()
    (data / "src.bin").write_bytes(SEED)

    forge = _issuer()
    subject = tmp_path / "subject.tok"
    subject.write_text("subject-token-p115-w82\n")
    subject.chmod(0o600)
    #: A signed bearer whose exp is already in the past.  The source takes it
    #: (skew), the destination reads it as EXPIRED — the REN-07/REN-08 subject.
    stale = tmp_path / "stale-bearer.tok"
    stale.write_text(forge.temporal(STALE_TTL))
    stale.chmod(0o600)

    base = f"http://{HOST}:{MOCK_PORT}"
    src_knobs = _indent(
        "brix_auth token;",
        "brix_ztn_cleartext on;   # lab opt-in: raw cleartext ztn drivers",
        f"brix_token_jwks     {forge.jwks_path};",
        'brix_token_issuer   "https://test.example.com";',
        'brix_token_audience "nginx-xrootd";',
        "brix_token_clock_skew 300;")

    def dest(name, *knobs):
        return lifecycle.start(NginxInstanceSpec(
            name=name,
            template="nginx_p115_tpc_renew.conf",
            data_root=str(data),
            template_values={"BIND_HOST": HOST,
                             "ROLE_KNOBS": _indent("brix_auth none;", *knobs)},
            reason="phase-115 W8.2 mid-transfer credential renewal"))

    src = lifecycle.start(NginxInstanceSpec(
        name="lc-p115-renew-src", template="nginx_p115_tpc_renew.conf",
        data_root=str(data),
        template_values={"BIND_HOST": HOST, "ROLE_KNOBS": src_knobs},
        reason="phase-115 W8.2 token-demanding TPC pull source"))

    exch = (f"brix_tpc_outbound_bearer_file {subject};",
            f"brix_tpc_outbound_token_endpoint {base}/token;")
    lab = {
        "src": src,
        # lead >> the mock's 300 s lifetime: due on the first chunk.
        "dst": dest("lc-p115-renew-dst", *exch,
                    "brix_tpc_outbound_renew_lead 3600;"),
        # the pre-W8.2 shape: no lead directive at all.
        "off": dest("lc-p115-renew-off", *exch),
        # lead well inside the lifetime: nothing is ever due.
        "ample": dest("lc-p115-renew-ample", *exch,
                      "brix_tpc_outbound_renew_lead 60;"),
        # mints once, then 500s: the renewal-failure arm.
        "once": dest("lc-p115-renew-once",
                     f"brix_tpc_outbound_bearer_file {subject};",
                     f"brix_tpc_outbound_token_endpoint {base}/once;",
                     "brix_tpc_outbound_renew_lead 3600;"),
        # no token endpoint at all: the default passthrough-opt mode forwards
        # the stale bearer file and has no authority to re-mint it.
        "lax": dest("lc-p115-renew-lax",
                    f"brix_tpc_outbound_bearer_file {stale};",
                    "brix_tpc_outbound_renew_lead 3600;"),
        "strict": dest("lc-p115-renew-strict",
                       f"brix_tpc_outbound_bearer_file {stale};",
                       "brix_tpc_outbound_renew_lead 3600;",
                       "brix_tpc_outbound_renew_strict on;"),
    }
    return lab, data, idp, forge


def _pull(lab, dst, dest_path, mode="token-exchange", src=None):
    """Drive one native TPC pull from the token source into `dst`."""
    key = "w82" + re.sub(r"[^a-z0-9]", "", dest_path.lower())
    src_ep = lab["src"] if src is None else lab[src]
    if src is None:
        arm = _arm_token_source(src_ep.port, key, _issuer().temporal(600))
    else:
        arm = _arm_source(src_ep.port, key)
    s = _xrd_login(HOST, lab[dst].port)
    s.settimeout(60)
    try:
        status, body = _dst_open(s, dest_path, src_ep.port, key, mode)
        assert status == KXR_OK, ("TPC dest-open refused", status, body)
        return _drive_pull(s, body[:4])
    finally:
        s.close()
        arm.close()


NOTICE_RX = r"TPC delegated credential renewed mid-transfer"
STORM_RX = r"renewed credential is still inside the .*renew_lead window"
GIVEUP_RX = r"TPC delegated credential expired mid-transfer: .* - continuing"


# --------------------------------------------------------------------------- #
# REN-01/02 — the feature, and the brake on the feature                        #
# --------------------------------------------------------------------------- #

def test_a_due_credential_is_renewed_mid_transfer(renewlab):
    """REN-01 success: the copy completes byte-exact AND the IdP was contacted
    a second time, on the live connection, after the first chunk."""
    lab, data, hits, _forge = renewlab
    status, body = _pull(lab, "dst", "/renewed.bin")
    assert status == KXR_OK, (status, body, _errcode(body))
    assert _wait_file(data / "renewed.bin", SEED), \
        "pull reported ok but the destination bytes never matched the seed"
    assert _wait_log(lab["dst"], NOTICE_RX), \
        "no mid-transfer renewal was logged"
    assert len(hits) == 2, \
        f"expected bootstrap + one renewal at the IdP, got {hits}"


def test_a_renewal_that_does_not_help_disables_itself(renewlab):
    """REN-02 anti-storm: the mock's lifetime (300 s) is shorter than the lead
    (3600 s), so every chunk would be due for ever.  One renewal is spent, the
    reason is logged, and the IdP is not contacted again for this transfer —
    the difference between two requests and one per megabyte."""
    lab, data, hits, _forge = renewlab
    status, body = _pull(lab, "dst", "/storm.bin")
    assert status == KXR_OK, (status, body, _errcode(body))
    assert _wait_log(lab["dst"], STORM_RX), \
        "renewal did not disable itself on a lead wider than the lifetime"
    assert len(hits) == 2, \
        f"renewal storm: {len(hits)} IdP requests for one 3 MiB pull: {hits}"
    assert _wait_file(data / "storm.bin", SEED), \
        "self-disabling renewal must not cost the transfer its bytes"


# --------------------------------------------------------------------------- #
# REN-03/04 — inert by default, and inert when there is nothing to do          #
# --------------------------------------------------------------------------- #

def test_without_a_lead_the_credential_is_never_resampled(renewlab):
    """REN-03: `brix_tpc_outbound_renew_lead` defaults to 0 (off), the house
    `0 = off` shape.  With the directive absent the pull is byte-for-byte the
    pre-W8.2 pull: one bootstrap fetch, no renewal, nothing logged."""
    lab, data, hits, _forge = renewlab
    status, body = _pull(lab, "off", "/nolead.bin")
    assert status == KXR_OK, (status, body, _errcode(body))
    assert _wait_file(data / "nolead.bin", SEED)
    assert len(hits) == 1, f"renewal fired with the feature off: {hits}"
    assert _log_count(lab["off"], NOTICE_RX) == 0


def test_a_lead_inside_the_lifetime_renews_nothing(renewlab):
    """REN-04: a 60 s lead against a 300 s credential is NOT_NEEDED on every
    chunk.  This separates "the feature is off" from "the kernel said no" —
    both must cost exactly one IdP request."""
    lab, data, hits, _forge = renewlab
    status, body = _pull(lab, "ample", "/ample.bin")
    assert status == KXR_OK, (status, body, _errcode(body))
    assert _wait_file(data / "ample.bin", SEED)
    assert len(hits) == 1, f"a credential with ample life was renewed: {hits}"
    assert _log_count(lab["ample"], NOTICE_RX) == 0


# --------------------------------------------------------------------------- #
# REN-05 — scoping: no ztn credential in play, no renewal kXR_auth             #
# --------------------------------------------------------------------------- #

def test_an_anonymous_pull_is_never_sent_a_renewal_auth(renewlab):
    """REN-05 security-negative.  `lc-p115-renew-off` runs `brix_auth none`, so
    the login reply carries no security token and `tpc_outbound_ztn` never
    runs: no credential was ever presented to this source.

    The destination still has a 3600 s lead and still holds a token from its
    bootstrap fetch, so without the `cred_presented` gate it would push an
    unsolicited kXR_auth at a source that never asked for one — turning a
    working anonymous pull into an auth exchange.  Exactly one IdP request and
    a clean copy is the proof that the gate holds.
    """
    lab, data, hits, _forge = renewlab
    # The instance is shared with REN-01/02, so count the delta, not the total.
    before = _log_count(lab["dst"], NOTICE_RX)
    status, body = _pull(lab, "dst", "/anonsrc.bin", src="off")
    assert status == KXR_OK, (status, body, _errcode(body))
    assert _wait_file(data / "anonsrc.bin", SEED)
    assert len(hits) == 1, \
        f"an anonymous pull reached the IdP for a renewal: {hits}"
    assert _log_count(lab["dst"], NOTICE_RX) == before, \
        "a renewal kXR_auth was sent to a source that never authenticated us"


# --------------------------------------------------------------------------- #
# REN-06 — the error arm: a renewal that fails on an already-dead credential   #
# --------------------------------------------------------------------------- #

def test_a_failed_renewal_of_an_expired_credential_fails_the_pull(renewlab):
    """REN-06 error.  `/once` mints an already-expired credential (the source
    takes it, the destination does not) and then answers 500, so the renewal
    attempt at the first chunk fails outright.

    Streaming on would be worse than failing: the source is entitled to stop
    honouring that credential at any moment, and a copy that dies at 90% with a
    transport error is far harder to diagnose than one refused up front with
    kXR_AuthFailed.  The offset in the message is what tells an operator this
    was mid-transfer and not a bootstrap failure.
    """
    lab, data, hits, _forge = renewlab
    status, body = _pull(lab, "once", "/once.bin")
    assert status == KXR_ERROR, ("a dead renewal must fail the pull",
                                 status, body)
    assert _errcode(body) == KXR_AUTH_FAILED, (_errcode(body), body)
    assert b"expired mid-transfer at offset" in body, body
    assert len(hits) == 2, \
        f"expected bootstrap + one failed renewal attempt, got {hits}"
    assert not (data / "once.bin").exists() \
        or (data / "once.bin").read_bytes() != SEED, \
        "a pull refused for an expired credential must not report a full copy"


def test_a_failed_renewal_is_not_retried_every_chunk(renewlab):
    """REN-06 corollary: the retry window (TPC_RENEW_RETRY_SECS) is what keeps
    a failing IdP from being hammered once per megabyte.  Because the verdict
    here is EXPIRED the first failure is already terminal, so the observable
    proof is that the IdP saw exactly one renewal attempt and no more — the
    same count as the test above, asserted from a second, independent pull so
    that a per-chunk retry would show up as a growing number."""
    lab, _data, hits, _forge = renewlab
    status, body = _pull(lab, "once", "/once-again.bin")
    assert status == KXR_ERROR, (status, body)
    assert len([h for h in hits if h["path"].startswith("/once")]) == 2, hits


# --------------------------------------------------------------------------- #
# REN-07/08 — security-negatives: a forwarded credential is never re-minted    #
# --------------------------------------------------------------------------- #

def test_the_default_mode_never_re_mints_a_forwarded_credential(renewlab):
    """REN-07 security-negative.  The DEFAULT outbound mode is
    "passthrough-opt" (launch_prepare.c) — the credential on the wire belongs
    to the client, or comes from the static bearer file, and the destination
    has no authority to mint a replacement for it.

    `brix_tpc_renew_mode_can_mint()` is an exact-match allow-list of exactly
    two modes for that reason.  If it were a deny-list, or matched a prefix,
    this pull would send the destination's own service credentials to an issuer
    in order to manufacture a token for somebody else's identity.  The
    assertion that matters is the IdP hit count: zero, not one.
    """
    lab, data, hits, _forge = renewlab
    status, body = _pull(lab, "lax", "/passthru.bin", mode=None)
    assert status == KXR_OK, (status, body, _errcode(body))
    assert _wait_file(data / "passthru.bin", SEED), \
        "renew_strict off must let an unrenewable credential finish its copy"
    assert _wait_log(lab["lax"], GIVEUP_RX), \
        "the refusal to re-mint must be visible to an operator"
    assert hits == [], f"a forwarded credential was sent to an issuer: {hits}"


def test_renew_strict_refuses_the_same_pull_and_still_never_mints(renewlab):
    """REN-08 security-negative.  `brix_tpc_outbound_renew_strict on` turns the
    warn-and-continue of REN-07 into kXR_AuthFailed — the setting a site uses
    when it would rather lose the copy than stream on an expired credential.

    The half that must NOT change is the IdP: tightening the policy must make
    the destination do LESS, never reach further.  Zero requests under both
    settings is what separates a stricter refusal from a wider authority.
    """
    lab, _data, hits, _forge = renewlab
    status, body = _pull(lab, "strict", "/passthru-strict.bin", mode=None)
    assert status == KXR_ERROR, ("renew_strict must refuse", status, body)
    assert _errcode(body) == KXR_AUTH_FAILED, (_errcode(body), body)
    assert b"expired mid-transfer at offset" in body, body
    assert hits == [], f"strict mode reached the IdP: {hits}"


def _clamp_ceiling() -> int:
    """The `brix_token_clock_skew` ceiling, read from the C that enforces it.

    Read rather than hardcoded so this file cannot drift away from the server a
    second time: if phase-105's clamp is ever retuned, the guard below retunes
    with it instead of pinning a number that used to be true.
    """
    source = (REPO_ROOT / "src" / "core" / "config"
              / "shared_conf_merge.h").read_text(encoding="utf-8")
    match = re.search(r"conf->token_clock_skew\s*<\s*0\s*\|\|\s*"
                      r"conf->token_clock_skew\s*>\s*(\d+)", source)
    assert match, "the token_clock_skew clamp is no longer where the lab reads it"
    return int(match.group(1))


def test_the_lab_skew_is_inside_the_security_clamp():
    """The bug this file shipped with, pinned so it cannot come back.

    Every test above shares one fixture, and that fixture asked for
    `brix_token_clock_skew 3600`.  `shared_conf_merge.h` has rejected anything
    over 300 with EMERG since phase-105 W8 — the clamp moved there out of
    webdav so that s3, which used to accept any value, is covered too — so
    `nginx -t` failed, `lifecycle.start()` raised, and all nine tests ERRORed in
    setup.  A file whose every test errors reports no failures, which is how a
    register row cited it as evidence while it had never once run.

    Reading the ceiling out of the C is the point: an assertion against a
    literal 300 would pass just as happily if the lab drifted back to 3600 and
    the clamp moved to 7200.
    """
    ceiling = _clamp_ceiling()
    body = (REPO_ROOT / "tests"
            / "test_phase115_tpc_cred_renew.py").read_text(encoding="utf-8")
    configured = [int(v) for v in
                  re.findall(r'"brix_token_clock_skew (\d+);"', body)]

    assert configured, "the lab no longer sets brix_token_clock_skew at all"
    assert max(configured) <= ceiling, (
        f"the renewal lab asks for skew {max(configured)}s but the server "
        f"clamps at {ceiling}s; every test in this file will ERROR at nginx -t")


def test_the_clamp_still_refuses_the_value_this_lab_used_to_use():
    """SECURITY-NEGATIVE: the clamp is what makes 300 meaningful.

    Correcting the lab to a legal value is only half the lesson — if the clamp
    were relaxed to accommodate labs like this one, `brix_token_clock_skew` would
    once again accept an hour of grace on token expiry, which is precisely the
    unit-confusion (3600 read as seconds-vs-minutes) the clamp exists to catch.
    So assert the server still REFUSES the value that broke this file.
    """
    assert _clamp_ceiling() < 3600, (
        "the token_clock_skew clamp now admits 3600s of grace; an expired "
        "token would be honoured for an hour")


def test_the_stale_credential_stays_inside_the_corrected_skew():
    """The lab's premise must survive the correction, not just its config.

    The whole construction needs one token that the SOURCE accepts and the
    DESTINATION calls expired.  That only works while the staleness is inside
    the source's skew: at `STALE_TTL = -60` and a 300 s skew it holds with room
    to spare, but a later edit that deepened the staleness past the clamp would
    turn every renewal test into a plain auth failure and still look green-ish.
    """
    assert -STALE_TTL < _clamp_ceiling(), (
        f"a token {-STALE_TTL}s expired is outside the {_clamp_ceiling()}s "
        "source skew; the source would reject it and no renewal is reachable")
