"""brix_backend_delegation at VALUE granularity — audit §Method, 15th tranche.

WHY THIS FILE EXISTS
--------------------
The audit's Method (steps 1-2) counts directive NAMES.  Re-running the
measurement per (directive, VALUE) over the 36 ``ngx_conf_enum_t`` tables in
``src/`` turned 93 pairs into 48 written and 45 never written.
``brix_backend_delegation`` contributes three of those 45 — and they are half
the directive:

    select       written — by omission on every export in the suite
    passthrough  written — the credential-forwarding labs
                 (test_audit15f_tpc_cred_forward.py, the per-user-backend labs)
    exchange     written — test_audit15c_tpc_token_exchange.py
    delegate     NEVER written, on any plane
    mint         NEVER written, on any plane
    auto         NEVER written, on any plane

So the directive whose entire job is choosing which credential authenticates
the backend leg had three of its six answers untested, including the one
(``auto``) an operator is most likely to reach for precisely because it
promises not to have to choose.

WHAT THE VALUE SELECTS
----------------------
The token is stored as ``conf->common.backend_delegation`` and read at three
kinds of site:

    protocols/webdav/access.c:256   the front door.  Any mode except SELECT
                                    arms X-Brix-Delegate-Proxy capture.
    protocols/webdav/access.c:515   the bind.  Any mode except SELECT binds the
                                    caller's captured bearer onto the VFS ctx
                                    (via brix_proto_deleg_gate_bearer, which is
                                    the backend-audience gate).
    fs/vfs/vfs_cred.c:119-132       the USE.  Only PASSTHROUGH and EXCHANGE are
                                    consumed here; its own doc comment says
                                    "DELEGATE/MINT are left to fall through to
                                    select+mint for now."

The gap between the second site and the third is what this file measures.

WHAT THE TABLE ESTABLISHES
--------------------------
Twelve WebDAV locations on ONE listener, all pointed at ONE capturing http://
origin that records the Authorization header of every request it is asked for.
"the caller's credential reached the backend" is then a header at the origin,
not an inference.  Measured, with a token-authenticated caller and an empty
per-user credential directory:

    leg           mode          origin saw    error.log            metric moved
    /select/      (absent)      no auth       "falling back"       select_fallback
    /passthrough/ passthrough   the CALLER'S  (silent)             deleg{passthrough,user}
    /exchange/    exchange      the CALLER'S  (silent)             deleg{exchange,user}
    /delegate/    delegate      no auth       "falling back"       select_fallback
    /mint/        mint          no auth       "falling back"       select_fallback
    /auto/        auto          no auth       "falling back"       select_fallback

Three of the six modes are byte-for-byte indistinguishable from not
configuring the directive at all — same origin request, same log line, same
counter.  Hardening the export with ``brix_storage_credential_fallback deny``
does not separate them either: ``delegate`` and ``auto`` then refuse every
request exactly as a plain ``select`` export does, while ``passthrough`` (whose
credential is live) keeps serving.

FINDING — DEFECT CANDIDATE #56
------------------------------
(a) ``delegate``, ``mint`` and ``auto`` BIND the caller's credential and then
    drop it.  The front door does the capture, the audience gate runs, the
    bearer is bound onto the VFS ctx — and ``vfs_cred_live_bag`` handles two of
    the six modes, so the bag is never opened and the request proceeds on the
    service credential.  Nothing warns at parse time and nothing distinguishes
    it at run time: the INFO line an operator sees ("no per-user backend
    credential ... falling back to the service credential") is the same line a
    non-delegating export writes.

(b) ``mint`` neither arms minting nor is required for it.  ``vfs_cred_maybe_mint``
    (vfs_cred.c:152-174) never reads the mode: minting is armed solely by
    ``brix_storage_credential_mint_ca``.  §C measures both halves — ``mint``
    with no CA mints nothing, and the same CA mints identically under
    ``select``.

(c) The mode-labelled counter cannot see any of this.  ``brix_cred_deleg_total``
    is emitted only from the live-bag path and from a successful mint, so a
    ``delegate`` export that drops the caller's credential moves
    ``brix_cred_select_fallback_total`` — which carries no mode label at all.
    §E measures the whole ten-leg counter table.

The documentation (docs/10-reference/backend-delegation.md, "Modes") is honest
about ``delegate`` ("Partial — exists for TPC; not VFS-driven for non-TPC
clients") and over-claims the other two: ``mint`` is LANDED but not by way of
the mode, and ``auto`` is "Best available of the above for the backend / LANDED
(resolves through the same gate)" while measured ``auto`` is the WORST
available — it drops a bearer that ``passthrough`` forwards to the same origin
on the same request.  §G pins the two sides against each other.

WHAT THIS FILE DOES NOT CLAIM
-----------------------------
The RFC-8693 exchange leg has an owner (test_audit15c_tpc_token_exchange.py);
``brix_backend_token_exchange_endpoint`` is HTTPS-only and load-validated, so
/exchange/ here carries no endpoint and measures the documented §5.4 verbatim
fallback instead.  The TPC push leg and its X-Brix-Delegate-Proxy plumbing
belong to nginx_audit15h_wdpush.conf, and the backend audience gate's
fail-open belongs to test_audit15j_zero_coverage_stragglers.py (DEFECT #34) —
which is also why it cannot mask a forwarded bearer here.
"""

import os
import time
from pathlib import Path

import pytest
import requests

import x509forge as xf
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import HOST, BIND_HOST, NGINX_BIN
from config_parse import nginx_t
from utils.make_token import TokenIssuer
# The capturing origin is the shared one: PacedSource already answers
# HEAD/ranged-GET/PUT and records every request, so this file adds a witness
# rather than a second mock.
from _test_audit15g_helpers import serve_paced

pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15x-deleg")]

NAME = "lc-audit15x-deleg"
ORIGIN_PORT = LIFECYCLE_SHARED_PORTS[NAME]["extra"]["ORIGIN_PORT"]
ROOT = Path(__file__).resolve().parents[1]

ISSUER = "https://audit15x.example.com"
AUD = "audit15x-gateway"
PAYLOAD = b"audit15x-backend-delegation-payload\n" * 8

# The six tokens, by the location that carries each.  /select/ leaves the
# directive out entirely, which is what pins the merge default (SELECT).
SELECT, PASSTHROUGH, EXCHANGE = "select", "passthrough", "exchange"
DELEGATE, MINT, AUTO = "delegate", "mint", "auto"
ALL_MODES = (SELECT, PASSTHROUGH, EXCHANGE, DELEGATE, MINT, AUTO)
# The two the live-cred bag implements, and the three it does not.
FORWARDING = (PASSTHROUGH, EXCHANGE)
DROPPING = (DELEGATE, MINT, AUTO)

# vfs_cred.c:298 / :285 — the two lines the select path writes.
FALLBACK_LINE = "falling back to the service credential"
REFUSE_LINE = "(fallback=deny) - refusing"


# --------------------------------------------------------------------------- #
# The instance                                                                 #
# --------------------------------------------------------------------------- #

@pytest.fixture
def deleg(lifecycle, tmp_path):
    """(endpoint, origin, dirs, issuer) — the twelve-location listener, its
    capturing origin, the four credential directories the legs are split
    across, and the issuer every caller's bearer is minted from."""
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    data.mkdir()

    # Four directories, never one.  A minted credential is a FILE, so a shared
    # directory could not say which leg wrote it; and 0700 is what the server
    # asks for (it warns about a group-readable credential store, which would
    # be a real finding on a real deployment and is noise here).
    dirs = {}
    for key in ("empty", "mint", "sel", "deny"):
        path = tmp_path / f"creds-{key}"
        path.mkdir(mode=0o700)
        dirs[key] = path

    ca = xf.make_ca("/DC=test/DC=brix/CN=audit15x Mint CA")
    cert_path = tmp_path / "mintca.pem"
    key_path = tmp_path / "mintca.key"
    cert_path.write_bytes(ca.pem)
    key_path.write_bytes(ca.key_pem)
    os.chmod(key_path, 0o600)

    issuer = TokenIssuer(str(tmp_path / "tokens"), issuer=ISSUER, audience=AUD)
    issuer.init_keys()

    origin = serve_paced(ORIGIN_PORT, PAYLOAD)
    try:
        endpoint = lifecycle.start(NginxInstanceSpec(
            name=NAME,
            template="nginx_audit15x_deleg.conf",
            protocol="http",
            data_root=str(data),
            template_values={
                "BIND_HOST": BIND_HOST,
                "JWKS": issuer.jwks_path,
                "ISSUER": ISSUER,
                "AUD": AUD,
                "CRED_EMPTY": str(dirs["empty"]),
                "CRED_MINT": str(dirs["mint"]),
                "CRED_SEL": str(dirs["sel"]),
                "CRED_DENY": str(dirs["deny"]),
                "MINT_CERT": str(cert_path),
                "MINT_KEY": str(key_path)},
            reason="audit-15x brix_backend_delegation at value granularity"))
        yield endpoint, origin, dirs, issuer
    finally:
        origin.hold.set()
        origin.shutdown()
        origin.server_close()


# --------------------------------------------------------------------------- #
# Drive                                                                        #
# --------------------------------------------------------------------------- #

def _get(endpoint, leg, token, headers=None, path="obj.bin"):
    hdrs = {"Authorization": f"Bearer {token}"}
    hdrs.update(headers or {})
    return requests.get(f"http://{HOST}:{endpoint.port}/{leg}/{path}",
                        headers=hdrs, timeout=30)


def _tag(record, token):
    """What the origin was shown: the caller's own bearer, nothing, or a third
    thing — which would be a credential neither end of this test issued."""
    value = record.get("authorization")
    if not value:
        return "none"
    if token in value:
        return "CALLER"
    return f"other:{value[:24]}"


def _probe(endpoint, origin, leg, token, headers=None, path="obj.bin"):
    """(http status, [tag per origin request]) for one GET through `leg`.

    The origin is shared by all twelve locations, so its log is cleared first:
    the whole file runs in one xdist group, in file order, on one worker.
    """
    del origin.recorded[:]
    response = _get(endpoint, leg, token, headers=headers, path=path)
    return response.status_code, [_tag(rec, token) for rec in origin.recorded]


def _saw(endpoint, origin, leg, token, **kwargs):
    """The DISTINCT credentials the origin was shown on one request, as a sorted
    list.  A leg that forwards must show the caller's bearer on EVERY request it
    makes (a WebDAV GET is a HEAD plus a GET), so collapsing to the distinct set
    states "all of them" without pinning how many the backend chose to issue."""
    status, tags = _probe(endpoint, origin, leg, token, **kwargs)
    assert tags, f"/{leg}/ never reached the origin (http={status})"
    return status, sorted(set(tags))


def _token(issuer, sub, **kwargs):
    return issuer.generate(sub=sub, scope="storage.read:/", **kwargs)


# --------------------------------------------------------------------------- #
# The log and the metrics                                                      #
# --------------------------------------------------------------------------- #

def _message(line):
    """The brix message out of an nginx error-log line, without the request
    context nginx appends.  That context quotes the URI, and this file's URIs
    are named after the modes — so a test asking "does the log name the mode?"
    would otherwise be answering with its own request line."""
    return line.split("brix:", 1)[-1].split(", client:", 1)[0]


def _errlog(endpoint):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        with open(os.path.join(endpoint.prefix, "logs", "error.log")) as fh:
            return fh.read()
    except OSError:
        return "(error log unavailable)"


def _await(endpoint, needle, timeout=15):
    """Wait for `needle` to reach the log; returns the whole log either way.

    The credential lines are written by the worker on the backend leg, which
    can land after the response body has already been read by the client.
    """
    deadline = time.time() + timeout
    text = ""
    while time.time() < deadline:
        text = _errlog(endpoint)
        if needle in text:
            return text
        time.sleep(0.25)
    return text


def _scrape(endpoint):
    """Every brix_cred_* sample as {series: value}."""
    response = requests.get(f"http://{HOST}:{endpoint.port}/metrics",
                            timeout=30)
    assert response.status_code == 200, response.status_code
    out = {}
    for line in response.text.splitlines():
        if line.startswith("brix_cred_"):
            series, _, value = line.rpartition(" ")
            out[series] = int(value)
    return out


def _moved(endpoint, before):
    """Which brix_cred_* series moved since `before`, and by how much.  Counters
    are process-wide and this instance is shared by the whole file, so every
    metric claim here is a delta around one request."""
    after = _scrape(endpoint)
    return {series: after[series] - before.get(series, 0)
            for series in after
            if after[series] - before.get(series, 0) != 0}


def _deleg(mode, outcome):
    return (f'brix_cred_deleg_total{{proto="webdav",mode="{mode}",'
            f'outcome="{outcome}"}}')


SELECT_FALLBACK = 'brix_cred_select_fallback_total{proto="webdav"}'
SELECT_DENY = 'brix_cred_select_deny_total{proto="webdav"}'
SELECT_USER = 'brix_cred_select_user_total{proto="webdav"}'


# --------------------------------------------------------------------------- #
# §A — what the origin is shown                                                #
# --------------------------------------------------------------------------- #

class TestWhatTheOriginIsShown:
    """The directive's only purpose is the credential on the outbound leg, so
    every case here reads that leg directly.  All six locations share one
    origin, one JWKS and one empty credential directory: the mode is the only
    thing that differs."""

    def test_passthrough_forwards_the_callers_own_bearer(self, deleg):
        """success: the mode that works, and the reference every other row is
        read against.  The origin is shown the exact bytes the client
        presented — not a re-issued token, not the service credential."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        status, saw = _saw(endpoint, origin, PASSTHROUGH, token)
        assert status == 200, status
        assert saw == ["CALLER"], (
            "brix_backend_delegation passthrough stopped forwarding the "
            f"caller's bearer to the backend: origin saw {saw}")

    def test_exchange_without_an_endpoint_forwards_verbatim(self, deleg):
        """success: the documented §5.4 fallback (deleg_wire.c:49-54).  With no
        endpoint to exchange AT, EXCHANGE is the second live-bag mode and
        behaves as passthrough — which is worth pinning, because the failure
        mode of a misconfigured exchange must be "forwarded the original", not
        "forwarded nothing"."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        status, saw = _saw(endpoint, origin, EXCHANGE, token)
        assert status == 200, status
        assert saw == ["CALLER"], (
            "exchange without an endpoint no longer forwards the bearer "
            f"verbatim: origin saw {saw}")

    def test_the_absent_directive_sends_no_credential(self, deleg):
        """The control.  With no per-user credential on disk the SELECT export
        proceeds on the service credential, and this backend has none — so the
        origin is asked without any Authorization at all."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        status, saw = _saw(endpoint, origin, SELECT, token)
        assert status == 200, status
        assert saw == ["none"], (
            f"a non-delegating export put a credential on the wire: {saw}")

    @pytest.mark.parametrize("mode", DROPPING)
    def test_the_three_unwritten_modes_forward_nothing(self, deleg, mode):
        """DEFECT CANDIDATE #56(a), the core measurement.

        Each of these locations differs from /select/ by exactly one line — the
        delegation mode — and the outbound leg is identical.  The caller's
        bearer was captured at the front door and bound onto the VFS ctx
        (access.c:515); vfs_cred_live_bag (vfs_cred.c:119-132) handles
        PASSTHROUGH and EXCHANGE only, so the bag is never opened."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        status, saw = _saw(endpoint, origin, mode, token)
        assert status == 200, status
        assert saw == ["none"], (
            f"brix_backend_delegation {mode} now puts something on the backend "
            f"leg ({saw}).  If the mode was implemented, this file's table, "
            "§D's fail-closed rows and §E's counters all change with it")

    def test_the_six_row_table(self, deleg):
        """success + error in one measurement: the shape of the claim is the
        SPLIT, not any single row.  Six locations, one caller, one token."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        expected = {mode: (["CALLER"] if mode in FORWARDING else ["none"])
                    for mode in ALL_MODES}
        got = {mode: _saw(endpoint, origin, mode, token)[1]
               for mode in ALL_MODES}
        assert got == expected, (
            "the mode -> forwarded-credential table moved:\n"
            + "\n".join(f"  {mode:<12} {str(got[mode]):>28}"
                        f"  (expected {expected[mode]})"
                        for mode in ALL_MODES if got[mode] != expected[mode]))

    def test_a_dropping_mode_logs_what_a_plain_export_logs(self, deleg):
        """DEFECT CANDIDATE #56(a), the operator's half: there is no line to
        find.  The INFO written on a /delegate/ request is the same sentence a
        /select/ request writes, and it names neither the mode nor the
        credential that was captured and discarded."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "delegwitness")
        _probe(endpoint, origin, DELEGATE, token)
        text = _await(endpoint, 'principal="delegwitness"')
        lines = [ln for ln in text.splitlines()
                 if 'principal="delegwitness"' in ln]
        assert lines, f"the delegate leg logged nothing at all\n{text[-2000:]}"
        assert all(FALLBACK_LINE in ln for ln in lines), (
            "the delegate leg now says something other than the plain "
            "service-credential fallback — pin the new wording here\n"
            + "\n".join(lines))
        assert not any("delegat" in _message(ln) for ln in lines), (
            "the log now names the delegation mode; #56(a) is diagnosable and "
            "this assertion should become the pin for the new line\n"
            + "\n".join(lines))


# --------------------------------------------------------------------------- #
# §B — the front door DOES know the mode                                       #
# --------------------------------------------------------------------------- #

class TestTheFrontDoorKnowsTheMode:
    """The three modes are not inert everywhere: access.c:256 arms
    X-Brix-Delegate-Proxy capture for every mode except SELECT, and the shared
    parser refuses that header outright over a cleartext transport
    (deleg_capture.c:78-84).  So they change a verdict — just not the one the
    directive exists to change."""

    PROXY_HEADER = "X-Brix-Delegate-Proxy"
    # Never a real proxy: the transport check runs first, so the bytes are only
    # ever required to be present.
    JUNK = "bm90LWEtcHJveHkK"

    @pytest.mark.parametrize("mode", DROPPING)
    def test_a_dropping_mode_still_refuses_a_cleartext_proxy_header(
            self, deleg, mode):
        """security-negative, and the only measurable difference these three
        modes make on this plane: a private key must never ride cleartext, so
        the header is 403'd before the request reaches storage."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        status, tags = _probe(endpoint, origin, mode, token,
                              headers={self.PROXY_HEADER: self.JUNK})
        assert status == 403, (
            f"a delegating export ({mode}) accepted {self.PROXY_HEADER} over "
            f"cleartext (http={status})")
        assert tags == [], (
            "the request was refused but the origin was contacted anyway: "
            f"{tags}")

    def test_passthrough_refuses_it_too(self, deleg):
        """The contrast within the delegating half: the gate is keyed on
        "not SELECT", not on "the mode the live bag implements"."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        status, tags = _probe(endpoint, origin, PASSTHROUGH, token,
                              headers={self.PROXY_HEADER: self.JUNK})
        assert (status, tags) == (403, []), (status, tags)

    def test_a_non_delegating_export_ignores_the_header(self, deleg):
        """success: /select/ never runs the capture, so the same header on the
        same listener is served — which is what makes the 403s above an
        observable property of the MODE rather than of the header."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        status, saw = _saw(endpoint, origin, SELECT, token,
                           headers={self.PROXY_HEADER: self.JUNK})
        assert status == 200, (
            "a plain SELECT export started policing X-Brix-Delegate-Proxy; "
            "the capture gate is supposed to be skipped for it")
        assert saw == ["none"], saw


# --------------------------------------------------------------------------- #
# §C — minting: the mode, or the CA?                                           #
# --------------------------------------------------------------------------- #

def _minted(directory, sub):
    path = Path(directory) / f"{sub}.pem"
    return path if path.exists() else None


class TestWhatIsMinted:
    """``mint`` is documented LANDED.  It is — but nothing about it is driven
    by the mode: vfs_cred_maybe_mint (vfs_cred.c:152-174) reads the mint CA and
    never the mode.  /mintca/ and /selmint/ are identical configurations except
    for that one line, over two separate directories."""

    def test_the_mode_alone_mints_nothing(self, deleg):
        """error: /mint/ carries the token and no mint CA.  Nothing is written,
        and the request completes on the service credential — the same outcome
        as /select/."""
        endpoint, origin, dirs, issuer = deleg
        token = _token(issuer, "mintnoca")
        status, saw = _saw(endpoint, origin, MINT, token)
        assert (status, saw) == (200, ["none"]), (status, saw)
        assert list(dirs["empty"].iterdir()) == [], (
            "brix_backend_delegation mint minted into a directory with no mint "
            f"CA configured: {sorted(p.name for p in dirs['empty'].iterdir())}")

    def test_the_ca_mints_under_mint_mode(self, deleg):
        """success: with a CA, the leg mints a per-user proxy keyed on the
        token subject and re-resolves it in the same request."""
        endpoint, origin, dirs, issuer = deleg
        token = _token(issuer, "mintca")
        status, _tags = _saw(endpoint, origin, "mintca", token)
        assert status == 200, status
        assert _minted(dirs["mint"], "mintca"), (
            "a mint CA + mint mode minted nothing: "
            f"{sorted(p.name for p in dirs['mint'].iterdir())}")

    def test_the_same_ca_mints_under_select_too(self, deleg):
        """DEFECT CANDIDATE #56(b): the mode is neither necessary nor
        sufficient.  /selmint/ writes ``brix_backend_delegation select`` beside
        the same CA and mints the identical artefact."""
        endpoint, origin, dirs, issuer = deleg
        token = _token(issuer, "selmint")
        status, _tags = _saw(endpoint, origin, "selmint", token)
        assert status == 200, status
        assert _minted(dirs["sel"], "selmint"), (
            "the mint CA no longer mints under SELECT — if minting became "
            "mode-gated, #56(b) is closed and this test states the new rule: "
            f"{sorted(p.name for p in dirs['sel'].iterdir())}")

    def test_the_minted_credential_is_not_world_readable(self, deleg):
        """security-negative: what is minted is a private key on disk.  0600 is
        the only acceptable mode for it, and the check is worth making on the
        artefact rather than trusting the umask that produced it."""
        endpoint, origin, dirs, issuer = deleg
        token = _token(issuer, "mintperm")
        _saw(endpoint, origin, "mintca", token)
        path = _minted(dirs["mint"], "mintperm")
        assert path is not None, "nothing was minted to inspect"
        assert path.stat().st_mode & 0o077 == 0, (
            f"minted credential {path.name} is group/other-accessible "
            f"(mode {path.stat().st_mode & 0o777:04o})")

    def test_the_minted_credential_never_reaches_a_cleartext_origin(self, deleg):
        """security-negative, and the honest limit of minting on this plane: an
        x509 proxy is not a bearer, and this backend speaks http.  So the mint
        succeeds, a private key is written per principal, and the outbound leg
        carries no credential at all — the cost is paid and the benefit is
        not."""
        endpoint, origin, dirs, issuer = deleg
        token = _token(issuer, "mintwire")
        status, saw = _saw(endpoint, origin, "mintca", token)
        assert status == 200, status
        assert _minted(dirs["mint"], "mintwire"), "nothing was minted"
        assert saw == ["none"], (
            "a minted x509 proxy reached an http:// origin as an "
            f"Authorization header: {saw}")


# --------------------------------------------------------------------------- #
# §D — the fail-closed posture                                                 #
# --------------------------------------------------------------------------- #

class TestTheFailClosedPosture:
    """``brix_storage_credential_fallback deny`` is how an operator hardens a
    delegated export: never touch the origin on the service credential.  A mode
    that really carries the caller's credential satisfies it.  The four /deny*/
    locations share one empty credential directory and differ only in mode."""

    def test_passthrough_survives_the_fail_closed_posture(self, deleg):
        """success: the live bag is a credential, so the deny policy is
        satisfied without any file on disk."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        status, saw = _saw(endpoint, origin, "denypass", token)
        assert (status, saw) == (200, ["CALLER"]), (status, saw)

    def test_a_hardened_select_export_refuses(self, deleg):
        """error: the control.  No per-user credential, deny policy, so the
        request is refused BEFORE the origin is contacted."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        status, tags = _probe(endpoint, origin, "denyselect", token)
        assert status == 403, status
        assert tags == [], f"a refused request still contacted the origin: {tags}"

    @pytest.mark.parametrize("leg", ["denydeleg", "denyauto"])
    def test_a_hardened_delegating_export_refuses_identically(self, deleg, leg):
        """DEFECT CANDIDATE #56(a), the deployment shape.  An operator who
        writes ``delegate`` (or ``auto``) and then hardens the export gets an
        export that refuses every request — the mode contributed no credential,
        so the deny policy has nothing to accept."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        status, tags = _probe(endpoint, origin, leg, token)
        assert (status, tags) == (403, []), (
            f"/{leg}/ no longer refuses like a plain hardened export "
            f"(http={status}, origin={tags})")

    def test_the_refusal_names_the_directory_and_the_policy(self, deleg):
        """The one thing the operator IS told, pinned so the diagnostic cannot
        regress into a bare 403: the principal, the key, the directory that was
        searched, and that the fallback policy is what refused."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "denywitness")
        _probe(endpoint, origin, "denydeleg", token)
        text = _await(endpoint, 'principal="denywitness"')
        lines = [ln for ln in text.splitlines()
                 if 'principal="denywitness"' in ln]
        assert lines, f"the refusal was not logged\n{text[-2000:]}"
        assert all(REFUSE_LINE in ln for ln in lines), (
            "the fail-closed refusal changed wording\n" + "\n".join(lines))

    def test_the_hardened_table(self, deleg):
        """The whole posture in one measurement: hardening separates the modes
        that carry a credential from the modes that only claim to."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        got = {leg: _probe(endpoint, origin, leg, token)[0]
               for leg in ("denyselect", "denydeleg", "denyauto", "denypass")}
        assert got == {"denyselect": 403, "denydeleg": 403,
                       "denyauto": 403, "denypass": 200}, got


# --------------------------------------------------------------------------- #
# §E — what Prometheus reports                                                 #
# --------------------------------------------------------------------------- #

class TestWhatPrometheusReports:
    """``brix_cred_deleg_total`` is the only mode-labelled credential counter.
    Its emitters are the live-bag path (vfs_deleg.c) and a successful mint
    (vfs_cred.c:166) — so what an operator can and cannot see from a dashboard
    is decided by which modes reach those two sites."""

    @pytest.mark.parametrize("mode", FORWARDING)
    def test_a_forwarding_mode_moves_its_own_row(self, deleg, mode):
        """success: exactly one counter moves, and it carries the mode."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        before = _scrape(endpoint)
        _saw(endpoint, origin, mode, token)
        moved = _moved(endpoint, before)
        assert moved == {_deleg(mode, "user"): 1}, (
            f"the {mode} leg no longer records exactly one delegation "
            f"outcome: {moved}")

    @pytest.mark.parametrize("mode", DROPPING)
    def test_a_dropping_mode_moves_the_mode_blind_counter(self, deleg, mode):
        """DEFECT CANDIDATE #56(c): the drop is invisible on a dashboard.

        No row of brix_cred_deleg_total moves for these three; what moves is
        brix_cred_select_fallback_total, which carries a proto label and no
        mode label — the same series a non-delegating export moves."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        before = _scrape(endpoint)
        _saw(endpoint, origin, mode, token)
        moved = _moved(endpoint, before)
        assert moved == {SELECT_FALLBACK: 1}, (
            f"the {mode} leg's counters changed: {moved}.  If a mode-labelled "
            "row moved, #56(c) is closed and this test should assert it")

    def test_the_hardened_refusal_is_mode_blind_too(self, deleg):
        """security-negative: a fail-closed delegating export refuses, and the
        refusal is counted under the mode-blind deny series.  An operator
        alerting on brix_cred_deleg_total{outcome="deny"} would see nothing at
        all while every request was being refused."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        before = _scrape(endpoint)
        status, tags = _probe(endpoint, origin, "denydeleg", token)
        assert (status, tags) == (403, []), (status, tags)
        moved = _moved(endpoint, before)
        assert moved == {SELECT_DENY: 1}, moved

    def test_the_select_control_is_indistinguishable(self, deleg):
        """The comparison that makes the three rows above a finding rather than
        a description: a plain export with no delegation directive at all moves
        the SAME series by the same amount."""
        endpoint, origin, _dirs, issuer = deleg
        token = _token(issuer, "alice")
        before = _scrape(endpoint)
        _saw(endpoint, origin, SELECT, token)
        assert _moved(endpoint, before) == {SELECT_FALLBACK: 1}

    def test_every_mode_name_is_exported_whether_or_not_it_fires(self, deleg):
        """INVARIANT #8.  The label vocabulary is a closed set rendered from a
        fixed table (unified.c:126-134), so the exposition carries a row for
        every (proto, mode, outcome) triple — including the modes that can
        never increment.  A mode rendered from user input, or a row that
        appeared only after first use, would be an unbounded label."""
        endpoint, _origin, _dirs, _issuer = deleg
        series = _scrape(endpoint)
        missing = [mode for mode in ALL_MODES
                   for outcome in ("user", "fallback", "deny")
                   if _deleg(mode, outcome) not in series]
        assert not missing, (
            f"brix_cred_deleg_total is missing rows for: {sorted(set(missing))}")

    def test_no_row_carries_a_mode_outside_the_table(self, deleg):
        """security-negative: an out-of-range mode renders "unknown" by design
        rather than emitting whatever integer was stored.  Nothing on this
        listener should produce even that."""
        endpoint, _origin, _dirs, _issuer = deleg
        known = set(ALL_MODES)
        seen = set()
        for series in _scrape(endpoint):
            if series.startswith("brix_cred_deleg_total") and 'mode="' in series:
                seen.add(series.split('mode="', 1)[1].split('"', 1)[0])
        assert seen == known, (
            f"brix_cred_deleg_total's mode label vocabulary is {sorted(seen)}, "
            f"expected exactly {sorted(known)}")


# --------------------------------------------------------------------------- #
# §F — per-caller isolation                                                    #
# --------------------------------------------------------------------------- #

class TestPerCallerIsolation:
    """A forwarding mode is only useful if it forwards the RIGHT credential.
    One listener, one location, three requests from two callers."""

    def test_each_caller_gets_its_own_bearer_on_the_backend_leg(self, deleg):
        """success: alice, then bob, then alice again — the origin sees each
        caller's own token, and the first caller's credential is not still in
        play when the second arrives."""
        endpoint, origin, _dirs, issuer = deleg
        alice = _token(issuer, "alice")
        bob = _token(issuer, "bob")
        for who, token in (("alice", alice), ("bob", bob), ("alice", alice)):
            status, saw = _saw(endpoint, origin, PASSTHROUGH, token)
            assert (status, saw) == (200, ["CALLER"]), (
                f"{who}'s request forwarded something else: {saw}")

    def test_a_second_callers_token_is_never_the_first_callers(self, deleg):
        """security-negative, stated on the bytes rather than on a tag: bob's
        request must not carry alice's token.  A per-conf credential cache keyed
        on anything but the caller would fail exactly here."""
        endpoint, origin, _dirs, issuer = deleg
        alice = _token(issuer, "alice")
        bob = _token(issuer, "bob")
        _get(endpoint, PASSTHROUGH, alice)
        del origin.recorded[:]
        _get(endpoint, PASSTHROUGH, bob)
        headers = [rec.get("authorization") or "" for rec in origin.recorded]
        assert headers, "bob's request never reached the origin"
        assert all(bob in value for value in headers), \
            "bob's request did not carry bob's token"
        assert not any(alice in value for value in headers), (
            "alice's bearer was replayed on bob's request — the forwarded "
            "credential is being cached across callers")

    def test_a_caller_the_front_door_refuses_never_reaches_the_origin(
            self, deleg):
        """security-negative: a token for a different audience is refused at the
        WebDAV auth gate, so no delegation decision is ever taken.  Worth
        measuring on the origin: a mode that forwarded first and authorised
        afterwards would leak a rejected caller's token to the backend."""
        endpoint, origin, _dirs, issuer = deleg
        wrong = _token(issuer, "mallory", audience="somewhere-else.example")
        status, tags = _probe(endpoint, origin, PASSTHROUGH, wrong)
        assert status == 401, (
            f"a wrong-audience token was not refused at the front door: {status}")
        assert tags == [], (
            f"a refused caller's request reached the backend anyway: {tags}")


# --------------------------------------------------------------------------- #
# §G — the documentation against the C                                         #
# --------------------------------------------------------------------------- #

VFS_CRED_C = ROOT / "src" / "fs" / "vfs" / "vfs_cred.c"
DELEG_DOC = ROOT / "docs" / "10-reference" / "backend-delegation.md"
FALLTHROUGH = "DELEGATE/MINT are left to fall through to select+mint for now."


def _mode_row(text, mode):
    for line in text.splitlines():
        if line.startswith(f"| `{mode}`"):
            return line
    return ""


class TestTheDocumentationAgainstTheC:
    """Static, and deliberately so: the run-time sections above measure what
    happens, and these two measure what a reader is told it will.  Both sides
    are pinned, so closing the gap from either end fails this class."""

    def test_the_c_still_says_two_modes_fall_through(self):
        """The source of truth for §A.  When this comment goes, either the
        modes were implemented (and §A's table changes) or the comment rotted
        away from the code (and this test is the only thing that would say
        so)."""
        assert VFS_CRED_C.exists(), VFS_CRED_C
        assert FALLTHROUGH in VFS_CRED_C.read_text(encoding="utf-8"), (
            f"{VFS_CRED_C.name} no longer documents the fall-through; if "
            "DELEGATE/MINT are now live-bag modes, §A's table is the thing to "
            "update")

    def test_the_live_bag_still_handles_exactly_two_modes(self):
        """The comment could be true and the code not.  vfs_cred_live_bag's
        condition is the actual gate, so it is read directly."""
        text = VFS_CRED_C.read_text(encoding="utf-8")
        assert "if (m == BRIX_CRED_PASSTHROUGH || m == BRIX_CRED_EXCHANGE) {" \
            in text, ("vfs_cred_live_bag's mode test changed shape — re-measure "
                      "§A before trusting this file's table")

    def test_the_docs_are_honest_about_delegate(self):
        """The one row that already says so.  Kept as a positive assertion so
        the finding below is scoped to the two rows that do not."""
        row = _mode_row(DELEG_DOC.read_text(encoding="utf-8"), "delegate")
        assert row, "the Modes table lost its `delegate` row"
        assert "Partial" in row, (
            f"the `delegate` row's status changed: {row.strip()}")

    def test_the_docs_over_claim_auto(self):
        """DEFECT CANDIDATE #56, the documentation half.

        `auto` is documented as "Best available of the above for the backend"
        and LANDED.  Measured (§A), it is the worst available: on the same
        listener, with the same caller and the same origin, `auto` forwards
        nothing where `passthrough` forwards the caller's own bearer.  Pinned
        rather than tolerated — when the row is corrected this test fails, and
        the fix is to assert the new status."""
        row = _mode_row(DELEG_DOC.read_text(encoding="utf-8"), "auto")
        assert row, "the Modes table lost its `auto` row"
        assert "LANDED" in row, (
            "the `auto` row no longer claims LANDED — update this test to the "
            f"corrected status and close #56: {row.strip()}")

    def test_the_docs_credit_the_mode_for_what_the_ca_does(self):
        """DEFECT CANDIDATE #56(b), the documentation half: the `mint` row
        reads as though the mode drives the minting.  §C measures that the CA
        does, under any mode."""
        row = _mode_row(DELEG_DOC.read_text(encoding="utf-8"), "mint")
        assert row, "the Modes table lost its `mint` row"
        assert "LANDED" in row and "brix_storage_credential_mint_ca" in row, (
            f"the `mint` row changed; re-read §C against it: {row.strip()}")


# --------------------------------------------------------------------------- #
# §H — the parse tier                                                          #
# --------------------------------------------------------------------------- #

def _knobs(*lines):
    return "".join(f"            {line}\n" for line in lines)


def _diagnostics(out):
    """The lines of an `nginx -t` transcript that would tell an operator
    something is wrong.  Matching on the transcript as a whole cannot work: the
    prefix is a tmp_path named after the test, so every mode name this file
    tests appears in the output as part of a directory."""
    return [ln for ln in out.splitlines()
            if any(sev in ln for sev in ("[warn]", "[error]", "[crit]",
                                         "[emerg]"))]


def _parse(tmp_path, knobs="", http_extra="", outer=""):
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    result = nginx_t("nginx_audit15x_delegparse.conf", tmp_path,
                     PORT=PARSE_PLACEHOLDER_PORT, DATA_ROOT=str(data),
                     LOG_DIR=str(tmp_path), KNOBS=knobs,
                     HTTP_EXTRA=http_extra, OUTER=outer)
    return result.returncode, ((result.stdout or "") + (result.stderr or ""))


class TestTheParseTier:
    """What the enum accepts and refuses.  Nothing here starts a server, and
    every case damages only its own tmp_path copy of the scaffold."""

    @pytest.mark.parametrize("token", ALL_MODES)
    def test_every_token_in_the_table_parses(self, tmp_path, token):
        """success: the enum table, the stream-plane mirror
        (protocols/root/stream/module.c:56-67) and the documentation all agree
        on the spelling of all six — including the three no config writes."""
        rc, out = _parse(tmp_path, _knobs(f"brix_backend_delegation {token};"))
        assert rc == 0, f"brix_backend_delegation {token} was rejected\n{out}"

    @pytest.mark.parametrize("token", ["PassThrough", "AUTO"])
    def test_the_token_is_case_insensitive(self, tmp_path, token):
        """ngx_conf_set_enum_slot compares with ngx_strcasecmp, so the config
        language is case-insensitive here while the audit's own grep for
        written values is not — which is the reason a value-granularity sweep
        has to read the enum table rather than the configs alone."""
        rc, out = _parse(tmp_path, _knobs(f"brix_backend_delegation {token};"))
        assert rc == 0, f"the enum rejected {token!r}\n{out}"

    def test_an_unknown_token_is_refused(self, tmp_path):
        """error: a misspelt mode must not silently leave SELECT in place — the
        failure mode would be an export that quietly stops delegating."""
        rc, out = _parse(tmp_path, _knobs("brix_backend_delegation forward;"))
        assert rc != 0 and 'invalid value "forward"' in out, out

    def test_the_enum_number_is_not_a_token(self, tmp_path):
        """error: the mode is a small integer internally and appears as one in
        conf dumps.  The enum takes names only, and says so."""
        rc, out = _parse(tmp_path, _knobs("brix_backend_delegation 1;"))
        assert rc != 0 and 'invalid value "1"' in out, out

    def test_an_empty_value_is_refused(self, tmp_path):
        """security-negative: an unset shell variable expanding to "" must not
        quietly become SELECT — an operator templating the mode per site would
        silently un-delegate every export."""
        rc, out = _parse(tmp_path, _knobs('brix_backend_delegation "";'))
        assert rc != 0 and 'invalid value ""' in out, out

    @pytest.mark.parametrize("line", ["brix_backend_delegation;",
                                      "brix_backend_delegation select mint;"])
    def test_the_directive_takes_exactly_one_argument(self, tmp_path, line):
        """error: NGX_CONF_TAKE1.  "select mint" is the shape an operator
        reaches for when they want `auto`, and it must not parse as either."""
        rc, out = _parse(tmp_path, _knobs(line))
        assert rc != 0, f"{line!r} parsed\n{out}"
        assert 'invalid number of arguments in "brix_backend_delegation"' \
            in out, out

    def test_a_duplicate_directive_is_refused(self, tmp_path):
        """security-negative: two modes in one location would leave which one
        wins to the parser's ordering — and the two might differ in whether the
        caller's credential is forwarded at all."""
        rc, out = _parse(tmp_path, _knobs("brix_backend_delegation select;",
                                          "brix_backend_delegation mint;"))
        assert rc != 0 and \
            '"brix_backend_delegation" directive is duplicate' in out, out

    def test_the_directive_is_accepted_at_http_level(self, tmp_path):
        """success: BRIX_HTTP_ALL_CONF — a site-wide default is a legitimate
        way to write this, and brix_shared_adopt_unified (http_common.c:428)
        carries it down to a location that does not restate it."""
        rc, out = _parse(tmp_path,
                         http_extra="    brix_backend_delegation delegate;\n")
        assert rc == 0, f"an http-level brix_backend_delegation was rejected\n{out}"

    def test_the_directive_is_refused_outside_http(self, tmp_path):
        """security-negative: written at the top of the file it reads like a
        global default and would apply to nothing.  nginx must refuse it rather
        than ignore it."""
        rc, out = _parse(tmp_path, outer="brix_backend_delegation delegate;\n")
        assert rc != 0, f"a main-context brix_backend_delegation parsed\n{out}"
        assert '"brix_backend_delegation" directive is not allowed here' in out, \
            out

    @pytest.mark.parametrize("token", DROPPING)
    def test_an_unimplemented_mode_parses_without_a_word(self, tmp_path, token):
        """DEFECT CANDIDATE #56, parse-time half.

        Config parse is the last moment the fall-through is diagnosable: the
        mode is a compile-time-known constant and the C already knows it is not
        wired.  Nothing is said — no warning, no notice, nothing naming the
        directive — so an operator's only feedback is a backend leg that
        silently carries the service credential (§A)."""
        rc, out = _parse(tmp_path, _knobs(f"brix_backend_delegation {token};"))
        assert rc == 0, f"the mode stopped parsing\n{out}"
        assert _diagnostics(out) == [], (
            "the unimplemented mode is now diagnosed at parse time — pin the "
            f"new diagnostic here and close #56\n{out}")

    def test_mint_mode_without_a_mint_ca_parses_without_a_word(self, tmp_path):
        """DEFECT CANDIDATE #56(b), parse-time half: `mint` with nothing to
        mint with is accepted in silence, and so is a mint CA with no `mint`
        mode.  Neither half of the pair is checked against the other."""
        rc, out = _parse(tmp_path, _knobs("brix_backend_delegation mint;"))
        assert rc == 0, f"mint without a CA stopped parsing\n{out}"
        assert _diagnostics(out) == [], (
            f"the incomplete mint configuration is now diagnosed\n{out}")
