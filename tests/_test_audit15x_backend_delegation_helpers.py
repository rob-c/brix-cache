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

