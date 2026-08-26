"""``brix_webdav_proxy_certs`` at VALUE granularity — audit §Method, 16th
tranche, file 16.

WHY THIS FILE EXISTS
--------------------
The audit's Method (steps 1-2) counts directive NAMES.  Re-running the same
measurement per (directive, VALUE) over every ``ngx_conf_set_flag_slot``
directive in ``src/`` leaves a residue of flags whose second arm no config, test
or document in the tree has ever written.  Files 14 and 15 closed eight of
``brix_webdav``'s nine.  The ninth is this one::

    { ngx_string("brix_webdav_proxy_certs"),                              :228
      NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, proxy_certs),
      NULL },

The corpus writes ``on`` in 88 places and, before this file's template, ``off``
in none.  It is the only one of the nine that needs a TLS listener doing
client-certificate verification, which is why files 14 and 15 left it here.

WHY THE OBSERVABLE IS A TLS VERDICT, AND WHY THREE SOCKETS
----------------------------------------------------------
The flag's whole effect is one OpenSSL call, made once per ``server{}`` at
postconfiguration time (postconfig.c:247-253)::

    if (wdcf->proxy_certs) {
        param = SSL_CTX_get0_param(sslcf->ssl.ctx);
        if (param) {
            X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_ALLOW_PROXY_CERTS);

Without that flag OpenSSL refuses an RFC 3820 proxy chain during the handshake
— the certificate is well-formed and its issuer is trusted, and it is still
refused, because a proxy certificate is only admissible when the verifier has
been told to admit one.  So the arms cannot be read from a log line or a status
code alone: the reading is whether a GSI proxy chain gets through the door.

An SSL_CTX belongs to a listening server, and its verify parameters are in place
before the first byte of a ClientHello — before any Host header exists.  Two arms
therefore cannot share a socket the way file 15's vhosts shared one, and each arm
buys a port: {PORT} writes ``on`` at server scope, {OFF_PORT} writes ``off``
(and, after a reconfigure that empties the slot, nothing at all), and {LOC_PORT}
writes ``on`` inside a ``location{}`` instead.

WHAT THE SECTIONS ESTABLISH
---------------------------
§A  The grid, measured: four client credentials × three arms.  The armed
    listener admits an RFC 3820 proxy chain and serves the seeded bytes; the
    ``off`` listener refuses it with ``40:proxy certificates not allowed``.  A
    plain EEC is admitted by all three — the attribution control that keeps the
    proxy row from being read as "TLS works here and not there".

§B  What ``on`` does NOT admit.  A legacy (pre-RFC 3820) proxy — no
    proxyCertInfo extension, ``CN=proxy`` appended — is refused on every arm,
    and the reason is a different one: ``32:key usage does not include
    certificate signing``.  X509_V_FLAG_ALLOW_PROXY_CERTS admits RFC 3820
    proxies, not "proxies".

§C  ``off`` and ABSENT are the same configuration, measured on one socket by
    emptying the directive in place: the merge default is 0 (config_merge.c:85)
    and the initialiser is NGX_CONF_UNSET (config.c:128), so the two routes to a
    clear flag carry different values and must reach the same verdict.

§D  The finding: the ``location{}``-scoped write is inert, in BOTH directions.

§E  The config-time advertisement, which disagrees with §D.

§F  The parse tier — every scope the declaration names and every one it does
    not, plus values, arity and duplicates.

§G  The declarations and the corpus census every reading above depends on.

FINDING — DEFECT CANDIDATE #91
------------------------------
``NGX_HTTP_LOC_CONF`` is in the scope mask, so ``brix_webdav_proxy_certs on;``
inside a ``location{}`` parses without a word of complaint.  It then does
nothing, because the hook that would act on it reads the SERVER's loc_conf::

    wdcf = ctx->loc_conf[ngx_http_brix_webdav_module.ctx_index];       :237

with ``ctx = cscf->ctx``, called once per entry of ``cmcf->servers``
(postconfig.c:349-353) and never walking a location tree.  Measured, on
{LOC_PORT} against {PORT}:

    | client credential          | server-scope `on` | location-scope `on` |
    |----------------------------|-------------------|---------------------|
    | RFC 3820 proxy chain       | 200 + seed bytes  | 400 Bad Request     |
    | plain EEC                  | 200 + seed bytes  | 200 + seed bytes    |

and the location-scoped listener logs the refusal the ``off`` arm logs —
``40:proxy certificates not allowed, please set the appropriate flag`` — while
the startup census names only ``pc-srv-on`` as a server whose SSL context was
armed.  The mirror is inert too: ``off`` in a location under a server that wrote
``on`` (``/noproxy/`` on {PORT}) still admits the proxy chain, so the placement
cannot restrict acceptance either.  A GSI deployment that scopes the flag per
export — which the declaration invites, and which is how every other
``brix_webdav_*`` flag in the module behaves — silently accepts no proxy at all.

The cure is to narrow the declaration to ``NGX_HTTP_SRV_CONF`` (the placement
the hook can honour, and the one the sibling's comment already claims), or to
diagnose a location-scoped write at merge time.  Either is a one-line change;
the tests below pin the measurement whichever way it goes, because §D asserts
what the code does today and names the arm it is measuring.

THE SHARPENING — an inert write still advertises
-------------------------------------------------
``webdav_log_endpoint_summary`` computes its credential census from the
LOCATION's own flag (config.c:247-248)::

    ngx_uint_t  has_x509  = (conf->cadir.len > 0 || conf->cafile.len > 0
                             || conf->proxy_certs);

so the inert location is the one export in the template that announces
``credentials accepted: x509/GSI-proxy`` and earns ``NOTE: x509/GSI is accepted
but no CRL is configured — REVOKED certificates will be ACCEPTED`` — an
advertisement of proxy acceptance, and a revocation warning about it, for a
socket that refuses every proxy chain.  The subtree that wrote ``off`` is the
inverse: it advertises nothing while its socket admits proxies.  §E measures
both, and they are the only two locations in the template where the config-time
claim and the runtime verdict disagree.

WHAT THIS FILE DOES NOT CLAIM
-----------------------------
* Nothing about GSI authorization — what a DN maps to, what a VOMS attribute
  grants, whether a proxy is delegated.  Every export here is
  ``brix_webdav_auth none``: the only gate under test is the TLS layer's, and an
  export with an opinion about the client's DN would answer first.
* Nothing about CRLs beyond the fact that the NOTE is emitted; test_crl.py owns
  revocation.
* Nothing about which LOCATION handled a request.  A TLS verdict is reached
  before a location is selected, so the ``/noproxy/`` row is a statement about
  the socket.  That the location exists and carries ``off`` is established at
  config time, by §E's census, not by the body it served.
* Nothing about ``brix_ssl_client_capath``, the sibling declared in the same
  two scopes and read from the same server-level ``wdcf`` (module_commands.c:239,
  whose own comment says "Server-level, like brix_webdav_proxy_certs above").
  §G pins that it shares the hook; a location-scoped capath needs its own
  credential tree and is a file of its own.

Ledger: lc-audit16p-proxy-certs (fleet_ports_shared_phase5.py) — three TLS
listeners in one process: PORT, OFF_PORT, LOC_PORT.

Run:
    PYTHONPATH=tests python3 -m pytest tests/test_audit16p_proxy_certs.py -v
"""

import os
import time
from pathlib import Path

import pytest
import requests
import urllib3

from config_parse import nginx_t
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN, url_host
# The diagnostic filter belongs to tranche file 10; a substring search over the
# whole `nginx -t` output would match the temp directory rather than a message.
from test_audit16j_root_caps_flags import _diagnostics
from x509forge import make_ca, make_eec, make_proxy

# Every arm dials a host certificate whose CN is `localhost` from a URL that may
# name an IP literal, and the subject is the server verifying the CLIENT — the
# other direction is deliberately not checked.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

pytestmark = [pytest.mark.timeout(900),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit16p-proxy-certs")]

NAME = "lc-audit16p-proxy-certs"
PORT = LIFECYCLE_SHARED_PORTS[NAME]["port"]

ROOT = Path(__file__).resolve().parents[1]
MODULE_COMMANDS_C = ROOT / "src/protocols/webdav/module_commands.c"
CONFIG_MERGE_C = ROOT / "src/protocols/webdav/config_merge.c"
CONFIG_C = ROOT / "src/protocols/webdav/config.c"
POSTCONFIG_C = ROOT / "src/protocols/webdav/postconfig.c"
CONFIGS_DIR = Path(__file__).resolve().parent / "configs"

DIRECTIVE = "brix_webdav_proxy_certs"
TEMPLATE = "nginx_audit16p_proxy_certs.conf"

# The three arms, as the ledger key each one's port comes from.  A name here is
# the ARM, not an address: `srv-on` is the listener whose server{} writes the
# directive, and `loc-on` the one that writes it inside a location instead.
ARMS = ("srv-on", "srv-off", "loc-on")
# The arms on which the flag is clear at server scope, however it got that way —
# written `off`, or written somewhere the hook does not read.
CLEAR_ARMS = ("srv-off", "loc-on")

# The four client credentials, as the key each one's PEM pair is stored under.
CREDS = ("rfc3820", "legacy", "eec", "none")

# What every cell of §A's grid measures, taken from the live probe and asserted
# rather than derived: an HTTP status, and whether the seeded bytes came back.
# The only cell that moves between the arms is the RFC 3820 proxy chain.
GRID = {
    ("srv-on", "rfc3820"): 200,
    ("srv-on", "legacy"): 400,
    ("srv-on", "eec"): 200,
    ("srv-on", "none"): 400,
    ("srv-off", "rfc3820"): 400,
    ("srv-off", "legacy"): 400,
    ("srv-off", "eec"): 200,
    ("srv-off", "none"): 400,
    ("loc-on", "rfc3820"): 400,
    ("loc-on", "legacy"): 400,
    ("loc-on", "eec"): 200,
    ("loc-on", "none"): 400,
}

# The bodies.  Distinct constants, so a 200 says WHICH file answered.
SEED = b"PROXY-CERT-ARM-SEED\n"
SUBTREE_SEED = b"PROXY-CERT-SUBTREE-SEED\n"
URI = "/seed.txt"
SUBTREE_URI = "/noproxy/seed.txt"

# The two OpenSSL verify failures this file distinguishes, spelled as they reach
# the error log.  Both are 400s on the wire, and reading only the status would
# make §B's row look like §A's.
NO_PROXY_ALLOWED = "40:proxy certificates not allowed"
NO_CERT_SIGN = "32:key usage does not include certificate signing"
NO_CERT_SENT = "client sent no required SSL certificate"

# The server_name of each listener — matched by the census in §D/§E, never
# dialled, so the literals are configuration and not addresses.
SERVER_NAMES = {"srv-on": "pc-srv-on",     # net-literal-allow: the template's own server_name, matched not dialled
                "srv-off": "pc-srv-off",   # net-literal-allow: the template's own server_name, matched not dialled
                "loc-on": "pc-loc-on"}     # net-literal-allow: the template's own server_name, matched not dialled

# The config-time lines §D and §E read.
ARMED_MARK = ("enabled X509_V_FLAG_ALLOW_PROXY_CERTS on SSL context for "
              "server ")
READY_MARK = "WebDAV (davs://) endpoint ready"
CREDS_MARK = "credentials accepted:"
X509_MARK = "x509/GSI-proxy"
CRL_NOTE_MARK = "x509/GSI is accepted but no CRL is configured"

# One (x509, crl) pair per WebDAV location of the template, in configuration
# order: pc-srv-on's `/` (inherits the server's `on`), pc-srv-on's `/noproxy/`
# (wrote `off`), pc-srv-off's `/` (inherits `off`), pc-loc-on's `/` (wrote `on`
# itself).  Locations are merged in configuration order, which is why this is a
# LIST and not a set — and why the second entry differing from the first is what
# makes the order self-evident.
EXPECTED_SUMMARY = [(True, True), (False, False), (False, False), (True, True)]

_needs_nginx = pytest.mark.skipif(
    not os.access(NGINX_BIN, os.X_OK),
    reason=f"nginx not executable: {NGINX_BIN}")


def _squashed(path):
    """A config's text with every run of whitespace collapsed.

    The corpus census below greps for ``<directive> <value>;`` exactly as the
    audit's step-1/step-2 measurement does, and the corpus aligns its values in
    columns; without this, an aligned write would read as absent.
    """
    return " ".join(path.read_text(errors="replace").split())


def _server_block(rendered, arm):
    """The rendered configuration of one listener, by the server_name it carries.

    A ``server_name`` line is the first thing each block writes after its
    ``listen``, and the three names appear nowhere else in the file, so the text
    from one to the next is that listener and nothing else.  Reading the block
    rather than counting tokens keeps §C's precondition independent of how the
    template indents its arms.
    """
    head = rendered.index(f"server_name {SERVER_NAMES[arm]};")
    rest = rendered[head:]
    nxt = rest.find("server_name ", 1)
    return rest if nxt < 0 else rest[:nxt]


# --------------------------------------------------------------------------- #
# The credentials, the instance, and the one way this file asks a question      #
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def creds(tmp_path_factory):
    """One CA, one host certificate, one EEC, and two proxies off that EEC.

    Minted once for the module and with x509forge rather than xrdgsiproxy: the
    difference between the two proxies IS the subject of §B, and only the forge
    can produce a legacy proxy on demand.  Nothing here touches the shared test
    PKI, so a parallel fleet is never disturbed (the same reasoning as
    test_audit16l_relay_flag_arms.py's ``ca_pem``).

    Each credential is a (chain, key) pair of paths, ready for ``requests``'
    ``cert=`` — the chain file carries the leaf first and the EEC behind it,
    which is the chain a GSI client presents.
    """
    base = tmp_path_factory.mktemp("a16p-pki")
    ca = make_ca("/O=XrdTest/CN=audit16p CA", not_after_days=3000)
    host = make_eec(ca,
                    "/O=XrdTest/CN=localhost",  # net-literal-allow: certificate subject CN, never dialled and never verified
                    not_after_days=3000)
    eec = make_eec(ca, "/O=XrdTest/CN=audit16p user", not_after_days=3000)
    # x509forge counts its day offsets from a FROZEN epoch (2026-01-01), not from
    # now, so every credential here gets the same long-dated window as the CA:
    # a lifetime measured in days from today would already be expired, and an
    # expired proxy is refused with error 10 before the proxy policy is reached —
    # which would make §A's rows read as §B's.
    rfc3820 = make_proxy(eec, kind="rfc3820", not_after_days=3000)
    legacy = make_proxy(eec, kind="legacy", not_after_days=3000)

    def _write(stem, chain, key):
        chain_pem = base / f"{stem}.pem"
        key_pem = base / f"{stem}.key"
        chain_pem.write_bytes(b"".join(c.pem for c in chain))
        key_pem.write_bytes(key)
        key_pem.chmod(0o600)
        return str(chain_pem), str(key_pem)

    ca_pem = base / "ca.pem"
    ca_pem.write_bytes(ca.pem)
    host_pair = _write("host", [host], host.key_pem)
    return {
        "ca": str(ca_pem),
        "host_cert": host_pair[0],
        "host_key": host_pair[1],
        # The leaf a GSI login presents, with its issuer behind it.
        "rfc3820": _write("proxy", [rfc3820, eec], rfc3820.key_pem),
        "legacy": _write("legacy", [legacy, eec], legacy.key_pem),
        # The same identity WITHOUT a proxy: the attribution control.
        "eec": _write("eec", [eec], eec.key_pem),
        "none": None,
        "certs": {"ca": ca, "eec": eec, "rfc3820": rfc3820, "legacy": legacy},
    }


class _Arms:
    """The three started listeners, the one export behind them, and the log they
    share."""

    def __init__(self, endpoint, creds, data):
        self.endpoint = endpoint
        self.creds = creds
        self.data = data
        self.ports = {"srv-on": endpoint.port,
                      "srv-off": endpoint.extra_ports["OFF_PORT"],
                      "loc-on": endpoint.extra_ports["LOC_PORT"]}
        self.logs = Path(endpoint.prefix) / "logs"

    # -- asking -------------------------------------------------------------- #

    def get(self, arm, cred, uri=URI, timeout=30):
        """One GET at `arm`, presenting `cred`.

        Every non-200 below is an HTTP status and not an exception: with
        ``ssl_verify_client on`` nginx completes the handshake, then answers 400
        at the HTTP layer, so the verdict is readable on the wire and the REASON
        is readable in the log.
        """
        kwargs = {}
        pair = self.creds[cred]
        if pair is not None:
            kwargs["cert"] = pair
        return requests.get(
            f"https://{url_host(HOST)}:{self.ports[arm]}{uri}",
            verify=False, timeout=timeout, **kwargs)

    def grid(self, uri=URI):
        """Every (arm, credential) cell in one pass, as (status, got_seed)."""
        out = {}
        for arm in ARMS:
            for cred in CREDS:
                r = self.get(arm, cred, uri)
                out[(arm, cred)] = (r.status_code, r.content == SEED)
        return out

    # -- reading the log ----------------------------------------------------- #

    def errlog(self):
        """Instance prefixes are wiped at teardown, so failures quote inline."""
        try:
            return (self.logs / "error.log").read_text(errors="replace")
        except OSError:                          # pragma: no cover - diagnostic
            return "(error log unavailable)"

    def verify_reasons(self, arm):
        """Every client-certificate refusal the log attributes to `arm`."""
        needle = f"server: {SERVER_NAMES[arm]},"
        return [line for line in self.errlog().splitlines()
                if needle in line
                and (NO_PROXY_ALLOWED in line or NO_CERT_SIGN in line
                     or NO_CERT_SENT in line)]

    def awaited_reasons(self, arm, needle, timeout=3.0):
        """`verify_reasons(arm)` once `needle` is among them, or at the deadline.

        The 400 leaves the worker before the log write is necessarily visible to
        another process, so a refusal reason is polled for rather than read once.
        """
        deadline = time.monotonic() + timeout
        while True:
            reasons = self.verify_reasons(arm)
            if any(needle in line for line in reasons) \
                    or time.monotonic() > deadline:
                return reasons
            time.sleep(0.1)

    def armed_servers(self):
        """The server_names whose SSL context the postconfig hook armed.

        One line per server per config pass, so the reading is the SET: the
        launcher's `nginx -t` and the start itself are two passes over the same
        configuration.
        """
        return {line.split(ARMED_MARK, 1)[1].strip()
                for line in self.errlog().splitlines() if ARMED_MARK in line}

    def summary_groups(self):
        """(x509, crl_note) per WebDAV location, in merge order, per pass.

        ``webdav_log_endpoint_summary`` prints one NOTICE per location and then
        the credential census and warnings for that location, so grouping on the
        "endpoint ready" line reassembles per-location blocks without needing a
        line number — every merge-time diagnostic reports the same one.
        """
        groups = []
        for line in self.errlog().splitlines():
            if READY_MARK in line:
                groups.append([False, False])
            elif not groups:
                continue
            elif CREDS_MARK in line:
                groups[-1][0] = X509_MARK in line
            elif CRL_NOTE_MARK in line:
                groups[-1][1] = True
        return [tuple(g) for g in groups]

    def passes(self):
        """The per-location census split into config passes, newest last."""
        n = len(EXPECTED_SUMMARY)
        groups = self.summary_groups()
        return [groups[i:i + n] for i in range(0, len(groups), n)]


@pytest.fixture
def arms(lifecycle, creds, tmp_path):
    """Three TLS listeners, one export, one log.

    The export is shared by every arm on purpose: identical bytes behind
    identical WebDAV locations, so a verdict that differs between two arms
    cannot be explained by anything but the arm.
    """
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    (data / "noproxy").mkdir(parents=True)
    (data / "seed.txt").write_bytes(SEED)
    (data / "noproxy" / "seed.txt").write_bytes(SEED)
    (data / "noproxy" / "subtree.txt").write_bytes(SUBTREE_SEED)

    endpoint = lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template=TEMPLATE,
        protocol="https",
        readiness="tcp",
        data_root=str(data),
        # Spelled out rather than assembled from DIRECTIVE: the audit's own
        # step-1/step-2 measurement is a grep for `<directive> <value>;` over the
        # corpus, so an arm built at runtime would still read as unwritten in the
        # very measurement this file exists to close.
        template_values={"BIND_HOST": BIND_HOST,
                         "HOST_CERT": creds["host_cert"],
                         "HOST_KEY": creds["host_key"],
                         "CA_CERT": creds["ca"],
                         "SRV_ARM": "brix_webdav_proxy_certs on;",
                         "OFF_ARM": "brix_webdav_proxy_certs off;"},
        reason="audit-16p brix_webdav_proxy_certs at value granularity: three "
               "client-cert-verifying TLS listeners"))
    return _Arms(endpoint, creds, data)


# --------------------------------------------------------------------------- #
# §A — the grid                                                               #
# --------------------------------------------------------------------------- #

