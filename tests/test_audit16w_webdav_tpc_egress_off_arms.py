"""
test_audit16w_webdav_tpc_egress_off_arms.py — the WebDAV HTTP-TPC egress
policy read from its OFF side (audit
docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-15.md, 16th
tranche: the WebDAV-plane twin of test_audit16v_tpc_off_arms.py).

A COPY is a request-forgery primitive by construction: the client names an
authority and this server dials it.  Four location flags decide what that
socket is allowed to reach and whose credential rides on it, and the corpus had
only ever written the arm that OPENS each control —

    brix_tpc_allow_local        default OFF.  Twenty-odd configs in the
                                       tree write `on` (a test source is always
                                       on loopback); the DEFAULT — the arm that
                                       actually ships — was asserted nowhere.
    brix_tpc_allow_private      default ON.  The `off` arm appears in no
                                       config, test or template anywhere.
    brix_tpc_source_guard       default OFF.  Only `on` was ever written,
                                       so what an allowlist does on a location
                                       whose guard is off — the shape of a
                                       plausible operator mistake — was untested.
    brix_webdav_tpc_credential_forward default ON.  Only `off` was ever written.

Every one of them is NGX_HTTP_LOC_CONF, so all thirteen planes live under one
`listen` (nginx_audit16w_wdegress.conf) and differ in nothing but the knob.

Three things this file measures that no arm-by-arm reading would reach:

  * **The written arm and the omission are one value.**  /deny/ omits
    allow_local and /localoff/ writes `off`; /guardabsent/ omits the guard and
    /guardoff/ writes `off`.  Until the pair agrees, a refusal cannot be
    attributed to either.

  * **The same refusal has two different shapes.**  On the plain path a blocked
    range is a 403.  On the 202-marker-streaming path the response was already
    committed before the preflight ran (tpc_marker_start.c:44-68), so the
    refusal is a `failure` trailer at the end of a 202 body — a client that
    reads only the status code cannot tell a blocked transfer from a completed
    one.  Both are pinned, and so is the fact that they disagree.

  * **Which control answers first.**  The naming guard runs on the request
    thread before any transfer starts (tpc.c:357/372); the range gates run
    inside it (tpc_thread.c:136-171).  /guardorder/ arms the naming guard and
    leaves the range gate at its default, so a refusal must carry the naming
    guard's audit line and NOT the preflight's — i.e. no thread was ever
    spawned, and no dial ever attempted.

The source is a capturing TLS mock: it answers a pull, sinks a push, and
records the credential (if any) that arrived.  That record is the only witness
for the property every refusal here actually claims — not "the client got a
403" but "the outbound socket was never opened".
"""

import os
import shutil
import ssl
import time

import pytest
import requests

from _test_audit15f_helpers import CapturingSource, gets, mint_localhost_cert, serve
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN

def _guard_wdegress_1():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

def _guard_wdegress_2():
    if shutil.which("openssl") is None:
        pytest.skip("openssl not found — cannot mint the mock source's cert")

def _guard_wdegress_3():
    if not _HAVE_TOKENFORGE:
        pytest.skip("tokenforge (cryptography) unavailable")


try:
    from tokenforge import TokenForge, write_scitokens_cfg
    _HAVE_TOKENFORGE = True
except Exception:                       # noqa: BLE001 — cryptography optional
    _HAVE_TOKENFORGE = False

NAME = "lc-audit16w-wdegress"
MOCK_PORT = LIFECYCLE_SHARED_PORTS[NAME]["extra"]["MOCK_PORT"]

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group(NAME)]

PAYLOAD = b"audit16w-webdav-tpc-egress-off-arms-" * 128

PLANES = ("deny", "localoff", "local", "denymark", "markok", "noprivate",
          "privok", "guardoff", "guardabsent", "guardon", "guardorder",
          "fwdon", "fwdguard")

# The RFC-1918 target the private-range gate is read against.  Nothing listens
# there and nothing needs to: the gate's whole subject is whether the policy
# decides before a connect is attempted.  It is the same address the existing
# naming-guard suite uses for the same reason.
PRIVATE_HOST = "10.255.255.1"

# The one host the configured allowlist names.  No test dials it — its only job
# is to be a name the loopback source does NOT match.
ALLOWLISTED = "storage.example.com"

# A COPY reads at the source and writes at the destination, so a caller's token
# has to carry both.
SCOPE = "storage.read:/ storage.create:/ storage.modify:/"

_SIGNAL = "signal=tpc_egress"          # the naming guard's audit line
_PREFLIGHT = "HTTP-TPC SSRF check blocked"   # tpc_thread.c
_MARKER_PREFLIGHT = "HTTP-TPC SSRF blocked"  # tpc_marker_start.c


class _SourceAndSink(CapturingSource):
    """The capturing pull source plus a PUT sink.

    A push leg needs somewhere to land, and what it delivered — recorded here
    rather than inferred from a status code — is the only positive evidence
    that an outbound leg ran at all.
    """

    def do_PUT(self):
        self._record()
        length = int(self.headers.get("Content-Length") or 0)
        self.server.pushed.append(self.rfile.read(length) if length else b"")
        self.send_response(201)
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture()
def wdegress(lifecycle, tmp_path):
    _guard_wdegress_1()
    _guard_wdegress_2()
    _guard_wdegress_3()

    mint = tmp_path / "mint"
    forge = TokenForge(str(mint))
    forge.init_keys()
    token_cfg = mint / "scitokens.cfg"
    write_scitokens_cfg(str(token_cfg), [{
        "name": "wdegress", "issuer": forge.issuer,
        "audience": forge.audience, "base_paths": ["/"],
        "jwks_path": forge.jwks_path, "strategy": "capability",
    }])
    cadir = tmp_path / "cadir"
    cadir.mkdir()

    cert, key = mint_localhost_cert(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    source = serve(_SourceAndSink, MOCK_PORT, tls=ctx, payload=PAYLOAD)
    source.pushed = []

    export = tmp_path / "export"
    for plane in PLANES:
        _plane_dir(export, plane).mkdir(parents=True)
    for path in (tmp_path, export, *(export / p for p in PLANES),
                 *(_plane_dir(export, p) for p in PLANES)):
        os.chmod(path, 0o777)

    try:
        ep = lifecycle.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_audit16w_wdegress.conf",
            protocol="webdav",
            data_root=str(export),
            template_values={"BIND_HOST": BIND_HOST,
                             "EXPORT_ROOT": str(export),
                             "CA_PEM": str(cert),
                             "CADIR": str(cadir),
                             "TOKEN_CFG": str(token_cfg)},
            reason="audit-16w WebDAV TPC egress policy off arms"))
        yield ep, export, source, forge
    finally:
        source.shutdown()
        source.server_close()


# ---------------------------------------------------------------------------
# Drive side
# ---------------------------------------------------------------------------

def _mock_url(obj="/obj.bin"):
    return f"https://{HOST}:{MOCK_PORT}{obj}"


def _copy(ep, plane, name, *, source_url=None, token=None, headers=None,
          timeout=60):
    """A COPY pull: `Source:` names where the destination must dial."""
    hdrs = {"Source": source_url if source_url is not None else _mock_url()}
    if token is not None:
        hdrs["Authorization"] = f"Bearer {token}"
    hdrs.update(headers or {})
    return requests.request("COPY", f"http://{HOST}:{ep.port}/{plane}/{name}",
                            headers=hdrs, timeout=timeout)


def _put(ep, plane, name, body=PAYLOAD, token=None):
    hdrs = {"Authorization": f"Bearer {token}"} if token else {}
    return requests.put(f"http://{HOST}:{ep.port}/{plane}/{name}",
                        data=body, headers=hdrs, timeout=30)


def _push(ep, plane, name, *, dest_url=None, timeout=60):
    """A COPY push: the request URI is the LOCAL object and `Destination:`
    names the remote authority this server must dial.

    `Credential:` is what CLASSIFIES the request as a push rather than an
    ordinary WebDAV COPY (dispatch.c:297-302) — a Destination alone routes to
    the local copy handler, which dials nothing and would make every egress
    assertion below vacuously true.
    """
    hdrs = {"Destination": dest_url if dest_url is not None
            else _mock_url("/pushed.bin"),
            "Credential": "none"}
    return requests.request("COPY", f"http://{HOST}:{ep.port}/{plane}/{name}",
                            headers=hdrs, timeout=timeout)


def _plane_dir(export, plane):
    """Each location has its own export root and the wire path keeps the
    location prefix, so plane P's objects land under <root-of-P>/P/."""
    return export / plane / plane


def _landed(export, plane, name):
    path = _plane_dir(export, plane) / name
    return path.read_bytes() if path.exists() else None


def _staging_leftovers(export, plane):
    """Temp names a pull stages through, which a refusal must not leave."""
    return [p.name for p in _plane_dir(export, plane).iterdir()
            if "-tpc." in p.name or p.name.startswith(".")]


def _errlog_path(ep):
    return os.path.join(ep.prefix, "logs", "error.log")


def _log_size(ep):
    try:
        return os.path.getsize(_errlog_path(ep))
    except OSError:
        return 0


def _log_tail(ep, offset):
    try:
        with open(_errlog_path(ep), "r", errors="replace") as fh:
            fh.seek(offset)
            return fh.read()
    except OSError:
        return ""


def _await_log(ep, offset, needle, timeout=5.0):
    """Poll the error log for `needle`; return the whole delta either way.

    The refusals under test are written by the transfer thread, so the response
    can beat its own log line to the client by a few milliseconds.
    """
    deadline = time.monotonic() + timeout
    delta = ""
    while time.monotonic() < deadline:
        delta = _log_tail(ep, offset)
        if needle in delta:
            return delta
        time.sleep(0.05)
    return delta


def _egress_line_for(delta, host):
    """True if the delta holds a naming-guard refusal audit line for `host`."""
    return any(_SIGNAL in line and f'path="{host}"' in line
               for line in delta.splitlines())


# ---------------------------------------------------------------------------
# The loopback range gate, read from its default
# ---------------------------------------------------------------------------

class TestTheLoopbackRangeGateDefault:
    """`brix_tpc_allow_local` ships OFF and every config in the tree
    turns it on, so the arm that actually protects a deployment had never been
    exercised: a COPY naming a loopback source must be refused."""

    def test_the_default_refuses_a_loopback_source(self, wdegress):
        ep, export, source, _forge = wdegress
        r = _copy(ep, "deny", "blocked.bin")
        assert r.status_code == 403, (r.status_code, r.text[:400])
        assert _landed(export, "deny", "blocked.bin") is None

    def test_the_written_off_arm_is_the_same_verdict_as_the_omission(
            self, wdegress):
        """The token and the omission must be one value.  Without this pair a
        refusal on /deny/ could be attributed to the missing directive and a
        refusal on /localoff/ to the written one, with neither reading proved."""
        ep, export, source, _forge = wdegress
        omitted = _copy(ep, "deny", "omitted.bin")
        written = _copy(ep, "localoff", "written.bin")
        assert omitted.status_code == written.status_code == 403, \
            (omitted.status_code, written.status_code)
        assert _landed(export, "localoff", "written.bin") is None

    def test_the_refusal_names_the_url_in_an_ssrf_log_line(self, wdegress):
        """An operator has to be able to tell a policy refusal from a transfer
        failure, so the preflight logs the URL it blocked (tpc_thread.c:166)."""
        ep, _export, _source, _forge = wdegress
        off = _log_size(ep)
        r = _copy(ep, "deny", "logged.bin")
        assert r.status_code == 403, r.status_code
        delta = _await_log(ep, off, _PREFLIGHT)
        assert _PREFLIGHT in delta, delta[-2000:]
        assert _mock_url() in delta, delta[-2000:]

    def test_the_refused_pull_never_dials_the_source(self, wdegress):
        """The property the 403 is a proxy for: the outbound socket was never
        opened.  A gate that refused only AFTER fetching would still return
        403 and would still be a request-forgery primitive."""
        ep, _export, source, _forge = wdegress
        r = _copy(ep, "deny", "undialled.bin")
        assert r.status_code == 403, r.status_code
        assert not source.recorded, \
            ("a refused pull still dialled the source", source.recorded)

    def test_the_refused_pull_commits_nothing(self, wdegress):
        """No object, and no staging temp left behind for a later run to
        commit or a sweeper to trip over."""
        ep, export, _source, _forge = wdegress
        r = _copy(ep, "deny", "nothing.bin")
        assert r.status_code == 403, r.status_code
        assert _landed(export, "deny", "nothing.bin") is None
        assert _staging_leftovers(export, "deny") == [], \
            _staging_leftovers(export, "deny")

    def test_opening_the_gate_lets_the_same_copy_through(self, wdegress):
        """Non-vacuity.  Same source, same object, same certificate — only the
        flag differs, so the refusals above are the flag and not a broken mock,
        an untrusted cert or an unreachable port."""
        ep, export, source, _forge = wdegress
        r = _copy(ep, "local", "allowed.bin")
        assert r.status_code == 201, (r.status_code, r.text[:400],
                                      _log_tail(ep, 0)[-2000:])
        assert _landed(export, "local", "allowed.bin") == PAYLOAD
        assert len(gets(source.recorded, "/obj.bin")) == 1, source.recorded

    def test_the_default_refuses_a_loopback_push_destination(self, wdegress):
        """The gate is direction-symmetric: a push dials the Destination
        authority, which is just as client-named as a pull's Source."""
        ep, _export, source, _forge = wdegress
        assert _put(ep, "deny", "pushsrc.bin").status_code in (201, 204)
        r = _push(ep, "deny", "pushsrc.bin")
        assert r.status_code == 403, (r.status_code, r.text[:400])
        assert not source.pushed, ("a refused push still uploaded",
                                   source.pushed)
        assert not source.recorded, source.recorded

    def test_opening_the_gate_lets_the_same_push_through(self, wdegress):
        """Push-side non-vacuity, asserted on the SOURCE's wire: the bytes
        arrived, so the refusal above is the policy and not a push path that
        never worked."""
        ep, _export, source, _forge = wdegress
        assert _put(ep, "local", "pushsrc.bin").status_code in (201, 204)
        r = _push(ep, "local", "pushsrc.bin")
        assert r.status_code in (201, 204), (r.status_code, r.text[:400],
                                             _log_tail(ep, 0)[-2000:])
        assert source.pushed == [PAYLOAD], \
            [len(b) for b in source.pushed]


# ---------------------------------------------------------------------------
# The same gate, one code path over
# ---------------------------------------------------------------------------

class TestTheSameGateOnTheMarkerPath:
    """`brix_webdav_tpc_marker_interval` answers 202 and streams performance
    markers while the transfer runs, which means the response is already
    committed when the preflight fires.  The refusal therefore cannot be a
    status code — the same policy verdict comes out in a different shape."""

    def _warm(self, ep, plane):
        """An ordinary threaded PUT resolves and caches this location's shared
        thread pool, which is what arms the marker path on a cold loc-conf
        (audit-15f defect candidate #9)."""
        assert _put(ep, plane, "warm.bin").status_code in (201, 204)

    def test_a_marker_transfer_is_accepted_before_it_is_refused(self, wdegress):
        ep, _export, _source, _forge = wdegress
        self._warm(ep, "denymark")
        r = _copy(ep, "denymark", "marked.bin")
        assert r.status_code == 202, (r.status_code, r.text[:400])

    def test_the_marker_body_ends_in_failure(self, wdegress):
        """The refusal's real carrier: the chunked body's trailer
        (tpc_marker.c:239).  Anything else and a blocked transfer is
        indistinguishable from a completed one."""
        ep, export, _source, _forge = wdegress
        self._warm(ep, "denymark")
        r = _copy(ep, "denymark", "trailer.bin")
        assert r.status_code == 202, (r.status_code, r.text[:400])
        assert r.text.rstrip().endswith("failure"), r.text[-400:]
        assert _landed(export, "denymark", "trailer.bin") is None

    def test_the_marker_refusal_never_dials_the_source(self, wdegress):
        """The marker path runs its own copy of the preflight
        (tpc_marker_start.c:44-68), so the containment property has to be
        measured here too and not inherited from the plain path."""
        ep, _export, source, _forge = wdegress
        self._warm(ep, "denymark")
        r = _copy(ep, "denymark", "undialled.bin")
        assert r.status_code == 202, r.status_code
        assert not source.recorded, source.recorded

    def test_the_marker_refusal_is_logged_by_its_own_preflight(self, wdegress):
        ep, _export, _source, _forge = wdegress
        self._warm(ep, "denymark")
        off = _log_size(ep)
        _copy(ep, "denymark", "logged.bin")
        delta = _await_log(ep, off, _MARKER_PREFLIGHT)
        assert _MARKER_PREFLIGHT in delta, delta[-2000:]

    def test_the_marker_path_streams_success_when_the_gate_is_open(
            self, wdegress):
        """Non-vacuity for the whole class: identical plane, gate open."""
        ep, export, _source, _forge = wdegress
        self._warm(ep, "markok")
        r = _copy(ep, "markok", "streamed.bin")
        assert r.status_code == 202, (r.status_code, r.text[:400])
        assert r.text.rstrip().endswith("success"), r.text[-400:]
        assert _landed(export, "markok", "streamed.bin") == PAYLOAD

    def test_a_status_only_client_cannot_tell_the_two_apart(self, wdegress):
        """The asymmetry stated as the operational hazard it is: a blocked
        transfer and a completed one carry the SAME status on this path, and
        differ only in the last line of the body.  A client that checks
        `resp.status_code == 202` and stops has learned nothing."""
        ep, _export, _source, _forge = wdegress
        self._warm(ep, "denymark")
        self._warm(ep, "markok")
        blocked = _copy(ep, "denymark", "same1.bin")
        allowed = _copy(ep, "markok", "same2.bin")
        assert blocked.status_code == allowed.status_code == 202, \
            (blocked.status_code, allowed.status_code)
        assert blocked.text.rstrip().endswith("failure"), blocked.text[-200:]
        assert allowed.text.rstrip().endswith("success"), allowed.text[-200:]


# ---------------------------------------------------------------------------
# The private range gate
# ---------------------------------------------------------------------------

class TestThePrivateRangeGate:
    """`brix_tpc_allow_private` ships ON — a gateway will happily pull
    from RFC-1918 space unless told otherwise.  The `off` arm is written in no
    config anywhere in the tree, so the control an operator on a private
    network would actually reach for had never been run."""

    def test_allow_private_off_refuses_an_rfc1918_source(self, wdegress):
        ep, export, _source, _forge = wdegress
        r = _copy(ep, "noprivate", "blocked.bin",
                  source_url=f"https://{PRIVATE_HOST}/obj.bin")
        assert r.status_code == 403, (r.status_code, r.text[:400])
        assert _landed(export, "noprivate", "blocked.bin") is None

    def test_the_private_refusal_is_an_ssrf_log_line(self, wdegress):
        ep, _export, _source, _forge = wdegress
        off = _log_size(ep)
        _copy(ep, "noprivate", "logged.bin",
              source_url=f"https://{PRIVATE_HOST}/obj.bin")
        delta = _await_log(ep, off, _PREFLIGHT)
        assert _PREFLIGHT in delta, delta[-2000:]
        assert PRIVATE_HOST in delta, delta[-2000:]

    def test_the_private_refusal_is_decided_before_any_dial(self, wdegress):
        """A policy verdict on a literal address needs no DNS and no connect,
        so it must come back immediately — not after the location's 3-second
        transfer bound has expired against an unreachable host.  The elapsed
        time is the evidence that nothing was dialled: there is no mock at
        10.255.255.1 to record the negative on."""
        ep, _export, _source, _forge = wdegress
        started = time.monotonic()
        r = _copy(ep, "noprivate", "fast.bin",
                  source_url=f"https://{PRIVATE_HOST}/obj.bin")
        elapsed = time.monotonic() - started
        assert r.status_code == 403, r.status_code
        assert elapsed < 2.0, \
            f"the refusal took {elapsed:.1f}s — that is a dial, not a policy"

    def test_allow_private_off_does_not_disturb_the_permitted_source(
            self, wdegress):
        """Closing one range must not close another: the same plane still
        pulls from the loopback source its allow_local arm permits."""
        ep, export, source, _forge = wdegress
        r = _copy(ep, "noprivate", "permitted.bin")
        assert r.status_code == 201, (r.status_code, r.text[:400],
                                      _log_tail(ep, 0)[-2000:])
        assert _landed(export, "noprivate", "permitted.bin") == PAYLOAD
        assert len(gets(source.recorded, "/obj.bin")) == 1, source.recorded

    def test_the_default_lets_the_same_private_target_through_to_the_dial(
            self, wdegress):
        """Non-vacuity, and the default's actual behaviour: with the flag left
        on, the very same RFC-1918 target is NOT refused by policy.  It fails
        later, at a connect the location's timeout bounds — a different
        failure, from a different layer, that names no SSRF verdict."""
        ep, _export, _source, _forge = wdegress
        off = _log_size(ep)
        r = _copy(ep, "privok", "dialled.bin",
                  source_url=f"https://{PRIVATE_HOST}/obj.bin")
        assert r.status_code != 403, \
            (r.status_code, "the permitted range was refused by policy")
        delta = _log_tail(ep, off)
        assert PRIVATE_HOST not in delta or _PREFLIGHT not in delta, \
            delta[-2000:]


# ---------------------------------------------------------------------------
# The naming allowlist when its guard is off
# ---------------------------------------------------------------------------

class TestTheNamingAllowlistWhenTheGuardIsOff:
    """`brix_tpc_source_guard` ships OFF, and its allowlist is a
    separate directive.  Writing the allowlist without arming the guard is the
    shape of a plausible operator mistake, and the corpus had never written the
    `off` arm at all — so what the allowlist does in that state was unmeasured.
    It does nothing: the location pulls from a host the allowlist never names."""

    def test_an_allowlist_with_the_guard_off_permits_a_host_it_does_not_name(
            self, wdegress):
        ep, export, source, _forge = wdegress
        r = _copy(ep, "guardoff", "through.bin")
        assert r.status_code == 201, (r.status_code, r.text[:400],
                                      _log_tail(ep, 0)[-2000:])
        assert _landed(export, "guardoff", "through.bin") == PAYLOAD
        assert len(gets(source.recorded, "/obj.bin")) == 1, source.recorded

    def test_the_disarmed_guard_emits_no_egress_audit_line(self, wdegress):
        """Fail-open is silent, which is the operational half of the hazard:
        nothing in the log tells the operator their allowlist is inert."""
        ep, _export, _source, _forge = wdegress
        off = _log_size(ep)
        _copy(ep, "guardoff", "silent.bin")
        delta = _log_tail(ep, off)
        assert not _egress_line_for(delta, HOST), delta[-2000:]
        assert _SIGNAL not in delta, delta[-2000:]

    def test_omitting_the_directive_is_the_same_verdict_as_writing_off(
            self, wdegress):
        """/guardabsent/ carries the identical allowlist and no guard
        directive.  Written-off and omitted must agree, or neither reading
        above is attributable."""
        ep, export, _source, _forge = wdegress
        r = _copy(ep, "guardabsent", "through.bin")
        assert r.status_code == 201, (r.status_code, r.text[:400])
        assert _landed(export, "guardabsent", "through.bin") == PAYLOAD

    def test_arming_the_guard_refuses_the_same_pull(self, wdegress):
        """Non-vacuity: the allowlist really does not name this source, so the
        two planes above were permitting something a guarded plane refuses."""
        ep, export, source, _forge = wdegress
        off = _log_size(ep)
        r = _copy(ep, "guardon", "refused.bin")
        assert r.status_code == 403, (r.status_code, r.text[:400])
        assert _landed(export, "guardon", "refused.bin") is None
        delta = _await_log(ep, off, _SIGNAL)
        assert _egress_line_for(delta, HOST), delta[-2000:]
        assert not source.recorded, source.recorded


# ---------------------------------------------------------------------------
# Which control answers first
# ---------------------------------------------------------------------------

class TestWhichControlAnswersFirst:
    """/guardorder/ arms the naming guard and leaves the range gate at its
    default, so both would refuse this pull.  Which one does is a fact about
    where each control lives: the naming guard on the request thread ahead of
    the transfer, the range gate inside it."""

    def test_the_naming_guard_answers_before_the_range_gate(self, wdegress):
        ep, _export, _source, _forge = wdegress
        off = _log_size(ep)
        r = _copy(ep, "guardorder", "first.bin")
        assert r.status_code == 403, (r.status_code, r.text[:400])
        delta = _await_log(ep, off, _SIGNAL)
        assert _egress_line_for(delta, HOST), delta[-2000:]
        assert _PREFLIGHT not in delta, \
            ("the transfer thread ran anyway — the naming guard is not the "
             "first control", delta[-2000:])

    def test_a_naming_refusal_starts_no_transfer(self, wdegress):
        """No dial, no object, no staging temp: the refusal happens before a
        transfer exists, not to one already under way."""
        ep, export, source, _forge = wdegress
        r = _copy(ep, "guardorder", "nothing.bin")
        assert r.status_code == 403, r.status_code
        assert not source.recorded, source.recorded
        assert _landed(export, "guardorder", "nothing.bin") is None
        assert _staging_leftovers(export, "guardorder") == [], \
            _staging_leftovers(export, "guardorder")


# ---------------------------------------------------------------------------
# Whose credential the outbound leg carries
# ---------------------------------------------------------------------------

class TestForwardingTheCallersCredential:
    """`brix_webdav_tpc_credential_forward` ships ON: by default the pull leg
    carries the CALLER's own bearer token to whatever authority the caller
    named.  Only the `off` arm had ever been written, so the arm that ships —
    and the fact that it composes with the egress controls above into a
    credential-exfiltration question — was never spelled out in a config."""

    def test_the_written_on_arm_forwards_the_callers_own_token(self, wdegress):
        ep, export, source, forge = wdegress
        token = forge.generate(sub="alice", scope=SCOPE)
        r = _copy(ep, "fwdon", "forwarded.bin", token=token)
        assert r.status_code == 201, (r.status_code, r.text[:400],
                                      _log_tail(ep, 0)[-2000:])
        assert _landed(export, "fwdon", "forwarded.bin") == PAYLOAD
        auths = [row["auth"] for row in gets(source.recorded, "/obj.bin")]
        assert auths == [f"Bearer {token}"], \
            ("the pull leg did not carry the caller's own token", auths)

    def test_the_token_travels_to_an_authority_the_operator_never_named(
            self, wdegress):
        """The composition, stated plainly: this location arms forwarding and
        leaves the naming guard off, so the ONLY party that chose where the
        user's credential went is the client that sent the COPY.  The mock is
        named in no directive of this plane."""
        ep, _export, source, forge = wdegress
        token = forge.generate(sub="alice", scope=SCOPE)
        r = _copy(ep, "fwdon", "unnamed.bin", token=token)
        assert r.status_code == 201, (r.status_code, r.text[:400])
        assert any(row["auth"] == f"Bearer {token}"
                   for row in source.recorded), source.recorded

    def test_an_unauthenticated_copy_forwards_nothing_and_dials_nothing(
            self, wdegress):
        """Error case: under `brix_webdav_auth required` there is no caller to
        forward, and — the part worth asserting — no leg either, so an
        anonymous client cannot use the destination as a pull proxy."""
        ep, export, source, _forge = wdegress
        r = _copy(ep, "fwdon", "anon.bin")
        assert r.status_code in (401, 403), r.status_code
        assert _landed(export, "fwdon", "anon.bin") is None
        assert not source.recorded, source.recorded

    def test_the_naming_guard_is_what_contains_the_token(self, wdegress):
        """Security-negative, and the reason the two flags belong in one file:
        with forwarding on, the naming allowlist is the control that decides
        whether the user's credential may leave this host at all.  The guarded
        plane refuses the same authenticated COPY the plane above completed,
        and the source records nothing — the token never travelled."""
        ep, export, source, forge = wdegress
        token = forge.generate(sub="alice", scope=SCOPE)
        off = _log_size(ep)
        r = _copy(ep, "fwdguard", "contained.bin", token=token)
        assert r.status_code == 403, (r.status_code, r.text[:400])
        assert _landed(export, "fwdguard", "contained.bin") is None
        assert not source.recorded, \
            ("the caller's token reached a non-allowlisted host",
             source.recorded)
        delta = _await_log(ep, off, _SIGNAL)
        assert _egress_line_for(delta, HOST), delta[-2000:]
        assert token not in delta, "the bearer token was logged verbatim"

    def test_the_guarded_plane_refuses_an_anonymous_caller_first(self, wdegress):
        """Ordering on the other side: authentication runs before the egress
        guard, so an anonymous COPY is an auth failure and never reaches — nor
        is audited by — the naming allowlist."""
        ep, _export, source, _forge = wdegress
        off = _log_size(ep)
        r = _copy(ep, "fwdguard", "anon.bin")
        assert r.status_code in (401, 403), r.status_code
        assert not source.recorded, source.recorded
        delta = _log_tail(ep, off)
        assert not _egress_line_for(delta, HOST), delta[-2000:]
