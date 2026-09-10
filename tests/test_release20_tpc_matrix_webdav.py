"""2.0 F18 — the TPC identity matrix on the WebDAV plane.

The matrix (`ofs.tpc allow|require|restrict|oids`, spelled
`brix_tpc_allow_identity` / `brix_tpc_require` / `brix_tpc_restrict` /
`brix_tpc_oids`) has TWO gate sites, and until this suite existed only one of
them was driven:

  * `tpc_matrix_gate()` in src/protocols/root/read/open_tpc.c — the native
    rendezvous leg, proven by test_release20_tpc_identity_matrix.py;
  * `webdav_tpc_matrix_gate()` in src/protocols/webdav/tpc.c — reached from
    `webdav_tpc_authorize()`, which BOTH `tpc_pull.c` and `tpc_push.c` call
    before anything is dialled.  Nothing exercised it.

An unexercised half of a confinement control is worse than no control: an
operator who writes `brix_tpc_restrict` on an `http{}` location would believe a
COPY was confined, and nothing in the tree would have contradicted them.  Every
fact below is therefore read on the wire, on this plane, in both directions.

What this suite pins that the native lab cannot:

  * **the path the path-stage sees is `r->uri`** — our LOCAL logical path,
    INCLUDING the `location` prefix.  `brix_tpc_restrict /restrict/allowed`
    under `location /restrict/` is the spelling that works; a rule written
    without the prefix would confine nothing, and the boundary arm proves the
    prefix is compared component-wise, not by `strncmp` (so `/restrict/allowed`
    never admits `/restrict/allowedx`).
  * **the party on this plane is always the CLIENT.**  A `brix_tpc_require dest
    <auth>` rule therefore constrains NOTHING here — the `/reqdest/` arm
    completes — which is the mirror image of the native lab, where the same
    rule refuses the destination's own leg.  If the party mapping were ever
    inverted, that arm turns red on this plane and the native lab's
    `destreq` arm turns green on the other.
  * **both callers are covered.**  A pull and a push are separate entry points
    into `webdav_tpc_authorize()`; each is driven refused and permitted, so
    neither can lose the gate without a red test.
  * **a refusal never dials.**  The mock source records every request it
    receives, so "the client got a 403" is not what is asserted: what is
    asserted is that the outbound socket was never opened, nothing landed in
    the export root, and no staging temporary was left behind.

The pure decision core (stage order, CSV element boundaries, the
component-aware prefix, the party scoping, the fixed refusal texts) is proven
without a server by tests/test_tpc_identity_matrix_unit.py.

One branch is deliberately NOT read here: the allow stage's PERMIT side.  This
lab is anonymous (`brix_webdav_auth none`) because that is what makes the DENY
side unambiguous — no DN, VO or group can be populated, so no rule can match by
accident.  The permit side needs a credential and is proven exhaustively by the
unit suite and on the wire by the native lab's credentialed legs.  The
`/restrict/` arm supplies the on-plane proof that a CONFIGURED matrix can still
say yes, so nothing here can pass by the gate simply refusing everything.
"""

import os
import shutil
import ssl
import time

import pytest
import requests

from _release20_tpc_helpers import log_since, log_size
from _test_audit15f_helpers import CapturingSource, mint_localhost_cert, serve
from fleet_lifecycle_ports import LIFECYCLE_EXCLUSIVE_PORTS
from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN

NAME = "lc-r20-tpcmx-dav"
MOCK_PORT = LIFECYCLE_EXCLUSIVE_PORTS[NAME]["extra"]["MOCK_PORT"]

pytestmark = [
    pytest.mark.serial,
    pytest.mark.timeout(240),
    pytest.mark.uses_lifecycle_harness,
    pytest.mark.xdist_group(NAME),
]

ARMS = ("open", "restrict", "allow", "require", "reqdest")

PAYLOAD = b"release20-tpc-matrix-webdav-" * 512

# The mock object every pull names.  A refusal is proven partly by this path
# NEVER appearing in the mock's request log.
SRC_OBJ = "/src.bin"

# The one error-log line the gate emits.  Nothing else in the tree writes it,
# so its presence or absence attributes a refusal to the matrix and to no
# other control on the request path.
NEEDLE = "brix webdav tpc refused: "

# The fixed refusal phrases (src/tpc/common/identity_matrix.c
# brix_tpc_matrix_verdict_text).  Each names the DIRECTIVE that refused and
# nothing derived from the request — INVARIANT 8, asserted directly by
# test_a_refusal_names_the_directive_and_nothing_else.
TEXT_IDENTITY = "TPC identity not permitted (brix_tpc_allow_identity)"
TEXT_AUTH = "TPC authentication method not permitted (brix_tpc_require)"
TEXT_PATH = "TPC path not permitted (brix_tpc_restrict)"


class _SourceAndSink(CapturingSource):
    """The recording pull source plus a PUT sink for the push leg.

    What the sink received — recorded, not inferred from a status code — is the
    only positive evidence that an outbound push leg ran at all, and its
    emptiness is the evidence that a refused one did not.
    """

    def do_PUT(self):
        self._record()
        length = int(self.headers.get("Content-Length") or 0)
        self.server.pushed.append(self.rfile.read(length) if length else b"")
        self.send_response(201)
        self.send_header("Content-Length", "0")
        self.end_headers()


def _guard_binary():
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")


def _guard_openssl():
    if shutil.which("openssl") is None:
        pytest.skip("openssl not found — cannot mint the mock source's cert")


def _make_export(tmp_path):
    """One export root per arm, plus the sub-directory the restrict prefix
    admits.  Separate roots mean a COPY that lands on the wrong arm is a
    missing file rather than a coincidence."""
    export = tmp_path / "export"
    for arm in ARMS:
        (export / arm / arm).mkdir(parents=True)
    (export / "restrict" / "restrict" / "allowed").mkdir()
    for path in export.rglob("*"):
        os.chmod(path, 0o777)
    os.chmod(tmp_path, 0o777)
    os.chmod(export, 0o777)
    return export


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    _guard_binary()
    _guard_openssl()
    tmp_path = tmp_path_factory.mktemp("lc_r20_tpcmx_dav")
    cert, key = mint_localhost_cert(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    source = serve(_SourceAndSink, MOCK_PORT, tls=ctx, payload=PAYLOAD)
    source.pushed = []
    export = _make_export(tmp_path)
    harness = LifecycleHarness()
    try:
        endpoint = harness.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_release20_tpc_matrix_webdav.conf",
            protocol="webdav",
            data_root=str(export),
            template_values={"BIND_HOST": BIND_HOST,
                             "EXPORT_ROOT": str(export),
                             "CA_PEM": str(cert)},
            reason="2.0 F18: the TPC identity matrix on the WebDAV plane."))
        yield {"endpoint": endpoint, "export": export, "source": source}
    finally:
        harness.close()
        source.shutdown()
        source.server_close()


# -- drive side -------------------------------------------------------------


def _source_url(obj=SRC_OBJ):
    return f"https://{HOST}:{MOCK_PORT}{obj}"


def _copy(lab, path, *, headers=None, timeout=30):
    """One COPY pull of the mock object into `path`, with the error-log delta
    it produced.  `path` is the full wire path, location prefix included —
    which is exactly the string the restrict stage evaluates."""
    hdrs = {"Source": _source_url()}
    hdrs.update(headers or {})
    mark = log_size(lab["endpoint"])
    resp = requests.request(
        "COPY", f"http://{HOST}:{lab['endpoint'].port}{path}",
        headers=hdrs, timeout=timeout)
    return resp, log_since(lab["endpoint"], mark)


def _push(lab, path, *, dest="/pushed.bin", timeout=30):
    """One COPY push of the LOCAL object at `path` to the mock.

    `Credential:` is what classifies the request as a push rather than an
    ordinary WebDAV COPY (dispatch.c) — a Destination alone routes to the local
    copy handler, which dials nothing and would make the assertions vacuous.
    """
    hdrs = {"Destination": _source_url(dest), "Credential": "none"}
    mark = log_size(lab["endpoint"])
    resp = requests.request(
        "COPY", f"http://{HOST}:{lab['endpoint'].port}{path}",
        headers=hdrs, timeout=timeout)
    return resp, log_since(lab["endpoint"], mark)


def _put(lab, path, body=PAYLOAD):
    return requests.put(f"http://{HOST}:{lab['endpoint'].port}{path}",
                        data=body, timeout=30)


def _landed(lab, path):
    """The bytes at wire path `path`, or None.  Each arm's export root is
    <export>/<arm>, and the wire path keeps the location prefix, so the object
    lands at <export>/<arm>/<arm>/..."""
    arm = path.lstrip("/").split("/", 1)[0]
    return _read(os.path.join(str(lab["export"]), arm, path.lstrip("/")))


def _read(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def _leftovers(lab, arm):
    """Staging temporaries a refused pull must never have created."""
    root = os.path.join(str(lab["export"]), arm, arm)
    return [name for name in os.listdir(root)
            if "-tpc." in name or name.startswith(".")]


def _mock_gets(lab):
    return [row for row in lab["source"].recorded
            if row["method"] in ("GET", "HEAD")]


# -- success ----------------------------------------------------------------


def test_an_unconfigured_matrix_is_a_noop(lab):
    """(success) the control: a location with no matrix directive copies
    byte-exact, so adopting 2.0 changes nothing for a site that never writes
    one of these directives — and every refusal below is falsifiable."""
    resp, log = _copy(lab, "/open/control.bin")
    assert resp.status_code in (200, 201), (resp.status_code, resp.text)
    assert _landed(lab, "/open/control.bin") == PAYLOAD
    assert NEEDLE not in log, log


def test_a_configured_matrix_still_permits_what_its_rule_admits(lab):
    """(success) `brix_tpc_restrict /restrict/allowed` is not a blanket denier:
    a path INSIDE the prefix completes.  Note the prefix carries the `location`
    prefix, because the stage evaluates r->uri — the local logical path."""
    resp, log = _copy(lab, "/restrict/allowed/ok.bin")
    assert resp.status_code in (200, 201), (resp.status_code, resp.text)
    assert _landed(lab, "/restrict/allowed/ok.bin") == PAYLOAD
    assert NEEDLE not in log, log


def test_a_dest_rule_does_not_constrain_the_client_party(lab):
    """(success) on this plane the requester is always the CLIENT party, so
    `brix_tpc_require dest gsi` names a party that never appears and leaves the
    client unconstrained — the COPY completes.

    This is the mirror of the native lab's `destreq` arm, where the same rule
    refuses the destination's own leg.  Inverting the party mapping turns this
    arm red here and that arm green there; neither test alone would catch it."""
    resp, log = _copy(lab, "/reqdest/ok.bin")
    assert resp.status_code in (200, 201), (resp.status_code, resp.text)
    assert _landed(lab, "/reqdest/ok.bin") == PAYLOAD
    assert NEEDLE not in log, log


def test_the_gate_also_permits_a_push_leg_its_rule_admits(lab):
    """(success) `webdav_tpc_authorize()` has two callers; this is the second.
    A push of a local object INSIDE the restrict prefix reaches the mock's PUT
    sink, so the push path's gate is proven to pass as well as to refuse."""
    assert _put(lab, "/restrict/allowed/push.bin").status_code in (201, 204)
    before = len(lab["source"].pushed)
    resp, log = _push(lab, "/restrict/allowed/push.bin")
    assert resp.status_code in (200, 201, 202), (resp.status_code, resp.text)
    assert NEEDLE not in log, log
    deadline = time.time() + 20.0
    while len(lab["source"].pushed) == before and time.time() < deadline:
        time.sleep(0.2)
    assert lab["source"].pushed[before:] == [PAYLOAD]


# -- error ------------------------------------------------------------------


def test_a_path_outside_the_prefix_is_refused(lab):
    """(error) the path stage fails CLOSED: a path the prefix does not admit is
    refused with 403 and the directive's own fixed phrase."""
    resp, log = _copy(lab, "/restrict/denied.bin")
    assert resp.status_code == 403, (resp.status_code, resp.text)
    assert NEEDLE + TEXT_PATH in log, log
    assert _landed(lab, "/restrict/denied.bin") is None


def test_the_prefix_stops_at_a_component_boundary(lab):
    """(error) `/restrict/allowed` does NOT admit `/restrict/allowedx`.

    Stock ofs.tpc compares the prefix with a plain strncmp, which silently
    widens every directory rule an operator writes (`/data` admitting
    `/database`).  BriX compares component-wise, which can only narrow — and
    narrowing is the safe direction for a confinement control.  This arm is the
    only place on this plane where that difference is visible."""
    resp, log = _copy(lab, "/restrict/allowedx.bin")
    assert resp.status_code == 403, (resp.status_code, resp.text)
    assert NEEDLE + TEXT_PATH in log, log
    assert _landed(lab, "/restrict/allowedx.bin") is None


def test_an_identity_no_rule_names_is_refused(lab):
    """(error) the identity stage fails CLOSED: this lab is anonymous, so the
    requester matches no `brix_tpc_allow_identity vo cms` rule and is DENIED
    rather than defaulted through."""
    resp, log = _copy(lab, "/allow/denied.bin")
    assert resp.status_code == 403, (resp.status_code, resp.text)
    assert NEEDLE + TEXT_IDENTITY in log, log
    assert _landed(lab, "/allow/denied.bin") is None


def test_an_unsatisfiable_client_auth_rule_is_refused(lab):
    """(error) `brix_tpc_require client gsi` names THIS party, and an anonymous
    requester carries no auth label, so the stage refuses."""
    resp, log = _copy(lab, "/require/denied.bin")
    assert resp.status_code == 403, (resp.status_code, resp.text)
    assert NEEDLE + TEXT_AUTH in log, log
    assert _landed(lab, "/require/denied.bin") is None


# -- security negatives -----------------------------------------------------


def test_a_refused_copy_never_dials_the_source(lab):
    """(security negative) the refusal is not "the client got a 403" — it is
    "the outbound socket was never opened".

    The mock records every request it answers.  A refused pull must leave that
    log untouched, must land nothing, and must leave no staging temporary: the
    gate runs before `brix_staged_open()` (tpc_pull.c), so a refusal that
    somehow reached the transfer would show up as a stray `-tpc.` name even if
    the copy itself then failed."""
    before = len(_mock_gets(lab))
    for path in ("/restrict/ssrf.bin", "/allow/ssrf.bin", "/require/ssrf.bin"):
        resp, _ = _copy(lab, path)
        assert resp.status_code == 403, (path, resp.status_code)
    time.sleep(1.0)
    assert len(_mock_gets(lab)) == before, lab["source"].recorded[before:]
    for arm in ("restrict", "allow", "require"):
        assert _leftovers(lab, arm) == [], arm


def test_a_refused_push_never_leaves_the_object(lab):
    """(security negative) the push leg's twin: a local object OUTSIDE the
    restrict prefix is refused before any dial, so the mock's sink never
    receives it.

    The object exists and is readable — the PUT below succeeds — so nothing but
    the matrix can be what stopped it leaving.  Without this arm the push
    caller could lose its gate entirely and every other test here would stay
    green, since they all drive the pull path."""
    assert _put(lab, "/restrict/leak.bin").status_code in (201, 204)
    before = len(lab["source"].pushed)
    resp, log = _push(lab, "/restrict/leak.bin", dest="/leaked.bin")
    assert resp.status_code == 403, (resp.status_code, resp.text)
    assert NEEDLE + TEXT_PATH in log, log
    time.sleep(1.0)
    assert lab["source"].pushed[before:] == []


def _module_message(line):
    """The part of an error-log line the MODULE composed.

    nginx appends its own context to every ngx_log_error() line — `, client:
    …, server: …, request: "COPY <uri> …", host: …` — and that context always
    carries the request URI, for every request this server has ever logged.
    It is not what INVARIANT 8 governs: the invariant is about the string the
    module builds, which is what reaches the client and what would become a
    metric label or a dashboard row.  Splitting the two here is what keeps this
    test honest about which half it is reading.
    """
    body = line.split(NEEDLE, 1)[1]
    return body.split(", client: ", 1)[0]


def test_a_refusal_names_the_directive_and_nothing_else(lab):
    """(security negative) INVARIANT 8: the refusal text is a FIXED phrase
    naming the directive.  Nothing derived from the request — no DN, VO, group,
    peer hostname or path — may ride out on it, because the same string is what
    a caller sees and what an operator would key a dashboard on.

    A path the operator considers secret is the easiest thing to leak here, so
    it is what this drives with; nginx's own log context is excluded by
    _module_message(), which documents why."""
    secret = "/restrict/inv8-secret-path.bin"
    resp, log = _copy(lab, secret)
    assert resp.status_code == 403, (resp.status_code, resp.text)
    assert "inv8-secret-path" not in resp.text, resp.text
    refusals = [ln for ln in log.splitlines() if NEEDLE in ln]
    assert refusals, log
    assert {_module_message(ln) for ln in refusals} == {TEXT_PATH}, refusals
