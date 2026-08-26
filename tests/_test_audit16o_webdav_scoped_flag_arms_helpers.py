"""The three MAIN|SRV|LOC WebDAV flags at VALUE granularity — audit §Method,
16th tranche, file 15.

WHY THIS FILE EXISTS
--------------------
The audit's Method (steps 1-2) counts directive NAMES.  Re-running the same
measurement per (directive, VALUE) over every ``ngx_conf_set_flag_slot``
directive in ``src/`` leaves a residue of flags whose ``off`` arm no config, test
or document in the tree has ever written.  ``brix_webdav_commands``
(src/protocols/webdav/module_commands.c) held nine such arms; file 14 closed the
five that are declared ``NGX_HTTP_LOC_CONF`` and nothing else.  Three of the
remaining four share a wider declaration::

    { ngx_string("brix_webdav_zip_access"),                              :405
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_brix_webdav_loc_conf_t, zip_access),
      NULL },

    ... and the same five lines for brix_webdav_require_digest (:440)
        and brix_webdav_dig (:454).

The fourth, ``brix_webdav_proxy_certs``, needs a TLS listener with client-cert
verification and is not this file's subject.

WHY THE OPT-OUT IS THE SUBJECT AND THE BARE LOCATION IS NOT
-----------------------------------------------------------
All three merge to 0::

    ngx_conf_merge_value(conf->zip_access,     prev->zip_access,     0);  :99
    ngx_conf_merge_value(conf->dig_enable,     prev->dig_enable,     0);  :111
    ngx_conf_merge_value(conf->require_digest, prev->require_digest, 0);  :112

so in a location with nothing above it, ``off`` and absent are the same
configuration — writing ``off`` there proves only that the parser accepts the
token.  What makes these three different from file 14's five is that they are
legal in THREE scopes, and ``NGX_HTTP_LOC_CONF_OFFSET`` means a value written in
``server{}`` or ``http{}`` lands in that scope's loc_conf and becomes the parent
of every location below it.  So there is a configuration only ``off`` can
express:

    server { brix_webdav_zip_access on;
             location /inherit/ { }                            -> inherits `on`
             location /opt-out/  { brix_webdav_zip_access off; } -> the reading }

Absence in ``/opt-out/`` inherits the server's ``on``.  ``off`` is the ONLY
spelling that turns the feature off for one location of an otherwise-enabled
server, and until this file nothing in the tree had ever written it — so the
per-location opt-out had never been executed for any of the three.

The second thing three scopes buy is the SERVER-scope setter itself, in either
arm: ``srv-off.test`` writes all of ``brix_webdav_zip_access off`` and
``brix_webdav_require_digest off`` in a ``server{}``, and ``dig-srvoff.test``
writes ``brix_webdav_dig off`` there.  The corpus had never written any of the
three in a ``server{}`` at all.

WHAT THE TABLES ESTABLISH
-------------------------
Every row below is measured, not predicted.  The arms are the same location body
with one token changed, so a verdict that differs between two of them is the flag
and nothing else.

§A  brix_webdav_zip_access — get_zip_member_serve (get.c:152-172) is reached only
    when the flag is set; without it the query argument is never looked at::

      GET a.zip?xrdcl.unzip=m.txt        on -> 200 the MEMBER (16 bytes)
                                        off -> 200 the WHOLE ARCHIVE (124 bytes)
      GET a.zip (no argument)          both -> 200 the whole archive
      ?xrdcl.unzip=../secret.txt         on -> 400   off -> 200 whole archive
      ?xrdcl.unzip=%2E%2E%2Fsecret.txt   on -> 400   off -> 200 whole archive
      ?xrdcl.unzip=/etc/passwd           on -> 400   off -> 200 whole archive
      ?xrdcl.unzip= (empty)              on -> 400   off -> 200 whole archive
      ?xrdcl.unzip=nope.txt              on -> 404   off -> 200 whole archive

    Both arms answer 200 for the same URI, which is why this flag has to be read
    on the BODY and not on the status: it decides which bytes a request receives.

§B  brix_webdav_require_digest — the flag is consulted at exactly one place,
    ``WEBDAV_DIGEST_NONE`` (put_body_digest.c:264-265), and the table shows it::

      PUT with no digest header at all    on -> 400 nothing stored   off -> 201
      Digest: adler32=<correct>          both -> 201
      Digest: md5=<correct b64>          both -> 201
      Digest: sha-256=<correct b64>      both -> 201
      Content-MD5: <correct b64>        both -> 201
      Digest: adler32=deadbeef          both -> 400 nothing stored
      Content-MD5: <wrong>              both -> 400 nothing stored
      Digest: md5=not-base64!!          both -> 400 nothing stored
      Digest: sha3-512=AAAA (unknown)     on -> 400   off -> 201
      Digest: (empty value)               on -> 400   off -> 201
      Digest: adler32 (no '=')            on -> 400   off -> 201

    The middle block is the attribution: VERIFYING an asserted digest is not
    gated by this flag, and a wrong one is refused either way.  The flag decides
    only what happens when there is nothing usable to verify — which is why the
    three malformed-but-unreadable rows land with the missing-header row and not
    with the mismatch rows.

§C  brix_webdav_dig — dig_precheck (dig.c:158-174) declines before anything else
    when the flag is clear, so the reserved prefix returns to the export::

      GET  /.well-known/dig/conf/server.cfg, authorized token
                                          on -> 200 the DIG export's bytes
                                         off -> 200 the EXPORT's bytes
      ... unlisted principal              on -> 403   off -> 200 export's bytes
      ... anonymous                       on -> 403   off -> 200 export's bytes
      PUT  /.well-known/dig/conf/x.bin    on -> 405 nothing written
                                         off -> 201 written INTO the export
      DELETE, PROPFIND under the prefix   on -> 405
      GET  /.well-known/dig/nosuch/f      both -> 404   (does NOT discriminate)
      GET  /.well-known/dig/conf          on -> 404   off -> 403
      GET  /.well-known/dig/  (the prefix itself)     both -> 403
      GET  /secret.txt (outside the prefix)           both -> 200

    The two 404/403 rows are the boundary of what the flag captures.
    ``r->uri.len <= BRIX_DIG_PREFIX_LEN`` (dig.c:164) declines the prefix itself,
    so ``/.well-known/dig/`` is a collection in the export on BOTH arms;
    ``/.well-known/dig/conf`` is a dig target with no file part (404 from
    dig_parse_target) on the ``on`` arm and a collection (403) on the ``off``
    arm.  The unknown-export row agrees on both arms for two unrelated reasons —
    dig_match_export misses, and the export has no such file — so it is recorded
    here as a row that carries no information about the flag.

§D  the parse tier — all three are legal in a location, a server and http{}, and
    nowhere else.  Reuses file 14's scaffold (nginx_audit16nparse.conf), which
    takes no position on which slot should accept; the expectation table is this
    file's, because it is a property of the declaration.

FINDING — DEFECT CANDIDATE #90
------------------------------
``webdav_put_verify_ingest_digest`` (put_body_digest.c:241-266) returns NGX_OK on
any non-empty ``Content-Encoding`` BEFORE it consults ``require_digest`` or
verifies an asserted digest::

    ce = brix_http_find_header(r, "Content-Encoding", sizeof("Content-Encoding") - 1);
    if (ce != NULL && ce->value.len > 0) {
        return NGX_OK;
    }
    kind = webdav_digest_select(r, &alg, exp_hex, sizeof(exp_hex));
    if (kind == WEBDAV_DIGEST_BAD)  { return NGX_HTTP_BAD_REQUEST; }
    if (kind == WEBDAV_DIGEST_NONE) {
        return conf->require_digest ? NGX_HTTP_BAD_REQUEST : NGX_OK;
    }

Skipping verification for a body the server is about to decode is deliberate —
the digest describes the decoded bytes.  But ``identity`` is a REGISTERED,
available codec (core/compat/codec_core.c:65-67, ``http_token = "identity"``) that takes no
decode path at all, so ``Content-Encoding: identity`` is a pure
verification-skip switch.  Measured on ``/rd-on/``, which writes
``brix_webdav_require_digest on``::

    no digest, no Content-Encoding                  -> 400, nothing stored
    no digest + Content-Encoding: identity          -> 201, body stored verbatim
    Digest: adler32=deadbeef, no Content-Encoding   -> 400, nothing stored
    Digest: adler32=deadbeef + C-E: identity        -> 201, body stored verbatim

Both halves are bypasses: a digest-less write is accepted on an export configured
to refuse writes it cannot verify, and an asserted digest that does not match the
body is never checked.  The stored bytes are the request body unchanged, so
nothing was decoded — there was no transformation for the skip to be about.

Two adjacent rows bound the defect and are pinned as regression fences:
``Content-Encoding:`` with an EMPTY value is 400 under ``require_digest on`` (the
``ce->value.len > 0`` half of the guard), and ``Content-Encoding: deflate`` over
a body that is not deflate-coded is 400 on both arms — a codec that really
decodes fails honestly.  Only a no-op codec token bypasses, which is also the
shape of the cure: gate the skip on the codec actually transforming the body
(``put_body.c`` already computes ``bctx->put_codec != BRIX_CODEC_IDENTITY``), and
make "cannot verify" mean 400 whenever ``require_digest`` is set.

OBSERVATION — THE DIG FLAG MOVES A URI SUBTREE BETWEEN TWO AUTHORIZATION REGIMES
--------------------------------------------------------------------------------
With ``brix_webdav_dig on`` the subtree under ``/.well-known/dig/`` is governed
by dig's own fail-closed allow-file: an anonymous or unlisted principal is
refused 403 (dig.c:58-113).  With the flag off — including by a per-location
opt-out under an otherwise-enabled server — the same subtree is governed by the
EXPORT's policy, whatever that is; here ``brix_webdav_auth optional``, so the
same anonymous request that was refused is answered 200.  The export is the
operator's and the bytes are theirs to publish, so this is not a defect.  It is
worth recording because the two regimes are not comparable: the flag is not a
feature switch layered on top of the export's authorization, it REPLACES the
authorization for that subtree, and turning it off is not a reduction in what the
server does there.  The test seeds a real object under the reserved prefix whose
bytes differ from the dig export's file of the same name, so the reading is which
FILE answered and under which policy — not merely that something did.

WHAT THIS FILE DOES NOT CLAIM
-----------------------------
* Nothing about ``http{}`` main scope at RUNTIME.  A value written there is the
  top of the merge chain for every server in the configuration, so it cannot
  coexist with the bare arms that read the merge default of 0; §D reads main
  scope at parse time and the runtime tier reads the default.
* Nothing about ZIP central-directory limits, deflate members, ranges or the
  ``brix_webdav_zip_cd_max_bytes`` cap — those are test_zip_member.py and
  test_audit15c_zip_cd_caps.py.  §A uses one stored member because the subject is
  whether the argument is consulted, not how a member is served.
* Nothing about digest algorithm coverage or hex normalisation beyond the four
  header forms it takes as given — that is test_webdav_put_digest.py.  What is
  new here is the ``off`` arm, the server-scope arms, and #90.
* Nothing about dig's symlink-escape confinement or its allow-file grammar —
  test_dig.py owns those.  §C reuses that file's export/allow-file recipe and
  asks only what the flag decides.

Ledger: lc-audit16o-webdav-scoped (fleet_ports_shared_phase5.py) — ONE http
listener, eleven locations across seven ``server_name`` vhosts.

Run:
    PYTHONPATH=tests python3 -m pytest \\
        tests/test_audit16o_webdav_scoped_flag_arms.py -v
"""

import base64
import hashlib
import os
import zipfile
import zlib
from pathlib import Path

import pytest
import requests

from config_parse import nginx_t
from fleet_lifecycle_ports import LIFECYCLE_SHARED_PORTS, PARSE_PLACEHOLDER_PORT
from server_registry import NginxInstanceSpec
from settings import BIND_HOST, HOST, NGINX_BIN, TOKENS_DIR
# The diagnostic filter belongs to tranche file 10; a substring search over the
# whole `nginx -t` output would match the temp directory rather than a message.
from test_audit16j_root_caps_flags import _diagnostics
from utils.make_token import TokenIssuer

pytestmark = [pytest.mark.timeout(900),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit16o-webdav-scoped")]

NAME = "lc-audit16o-webdav-scoped"
PORT = LIFECYCLE_SHARED_PORTS[NAME]["port"]

ROOT = Path(__file__).resolve().parents[1]
MODULE_COMMANDS_C = ROOT / "src/protocols/webdav/module_commands.c"
CONFIG_MERGE_C = ROOT / "src/protocols/webdav/config_merge.c"
GET_C = ROOT / "src/protocols/webdav/get.c"
PUT_BODY_DIGEST_C = ROOT / "src/protocols/webdav/put_body_digest.c"
DIG_C = ROOT / "src/protocols/dig/dig.c"
CODEC_CORE_C = ROOT / "src/core/compat/codec_core.c"

# The three, and the loc_conf field each setter writes.
FLAGS = (
    ("brix_webdav_zip_access", "zip_access"),
    ("brix_webdav_require_digest", "require_digest"),
    ("brix_webdav_dig", "dig_enable"),
)
FLAG_NAMES = [name for name, _ in FLAGS]

# The reserved URI space brix_webdav_dig takes over, spelled once.
DIG_PREFIX = "/.well-known/dig/"
DIG_TARGET = "/.well-known/dig/conf/server.cfg"
DIG_NO_FILE_PART = "/.well-known/dig/conf"
DIG_UNKNOWN_EXPORT = "/.well-known/dig/nosuch/server.cfg"

# The vhosts, keyed by the arm each one carries.  A server_name is matched by the
# Host header, never dialled, so the literal is the configuration and not an
# address.
DEFAULT_VHOST = "localhost"             # net-literal-allow: the template's own server_name, matched not dialled
SRV_ON = "srv-on.test"                  # net-literal-allow: the template's own server_name, matched not dialled
SRV_OFF = "srv-off.test"                # net-literal-allow: the template's own server_name, matched not dialled
DIG_VHOSTS = {
    "dig-on": "dig-on.test",            # net-literal-allow: the template's own server_name, matched not dialled
    "dig-locoff": "dig-locoff.test",    # net-literal-allow: the template's own server_name, matched not dialled
    "dig-srvoff": "dig-srvoff.test",    # net-literal-allow: the template's own server_name, matched not dialled
    "dig-bare": "dig-bare.test",        # net-literal-allow: the template's own server_name, matched not dialled
}
# The three arms on which the flag is clear, however it got that way.
DIG_OFF_ARMS = ("dig-locoff", "dig-srvoff", "dig-bare")

# Every (vhost, location prefix) pair the runtime tier addresses, and the arm the
# flags take there.  The default vhost writes nothing at server scope, so its
# `bare` rows read the merge default; srv-on writes both flags `on` in server{}.
ZIP_ON = ((DEFAULT_VHOST, "/zp-on/"), (SRV_ON, "/inherit/"))
ZIP_OFF = ((DEFAULT_VHOST, "/zp-off/"), (DEFAULT_VHOST, "/zp-bare/"),
           (SRV_ON, "/opt-out/"), (SRV_OFF, "/"))
DIGEST_ON = ((DEFAULT_VHOST, "/rd-on/"), (SRV_ON, "/inherit/"))
DIGEST_OFF = ((DEFAULT_VHOST, "/rd-off/"), (DEFAULT_VHOST, "/rd-bare/"),
              (SRV_ON, "/opt-out/"), (SRV_OFF, "/"))
# Every location of the template reached through a Host header, as the relative
# directory it maps to under the one posix export.
EXPORT_ARMS = ("zp-on", "zp-off", "zp-bare", "rd-on", "rd-off", "rd-bare",
               "inherit", "opt-out", "")

# One stored member in a one-member archive: the subject is whether the query
# argument is consulted, not how a member is served.
MEMBER_NAME = "m.txt"
MEMBER = b"ZIP-MEMBER-BODY\n"
# A real file next to the archive, so an escape that succeeded would be visible.
SECRET_NAME = "secret.txt"
SECRET = b"OUTSIDE-THE-ARCHIVE\n"

# The two files that share DIG_TARGET's URI: one in the dig export (outside the
# WebDAV export entirely) and one inside the WebDAV export under the reserved
# prefix.  Distinct constants, so a 200 says WHICH file answered.
DIG_BODY = b"DIG-EXPORT-CONTENT\n"
SHADOW_BODY = b"EXPORT-SHADOW-CONTENT\n"

# The PUT body every digest row asserts about, and its correct digests.
BODY = b"digest-arm-body-0123456789"
ADLER32 = f"{zlib.adler32(BODY) & 0xffffffff:08x}"
MD5_B64 = base64.b64encode(hashlib.md5(BODY).digest()).decode()
SHA256_B64 = base64.b64encode(hashlib.sha256(BODY).digest()).decode()
WRONG_MD5_B64 = base64.b64encode(b"\x00" * 16).decode()

_needs_nginx = pytest.mark.skipif(
    not os.access(NGINX_BIN, os.X_OK),
    reason=f"nginx not executable: {NGINX_BIN}")


# --------------------------------------------------------------------------- #
# The instance, the seeded trees, and the one way this file asks a question     #
# --------------------------------------------------------------------------- #

class _Scoped:
    """The started listener, the one posix export behind eleven locations, and
    the dig export that lives outside it."""

    def __init__(self, endpoint, data, digexp, issuer):
        self.endpoint = endpoint
        self.data = data
        self.digexp = digexp
        self.issuer = issuer
        self.port = endpoint.port
        self.logs = Path(endpoint.prefix) / "logs"
        self._seq = 0

    # -- addressing --------------------------------------------------------- #

    def request(self, method, uri, host=DEFAULT_VHOST, **kwargs):
        headers = {"Host": host, **kwargs.pop("headers", {})}
        return requests.request(method, f"http://{HOST}:{self.port}{uri}",
                                headers=headers, timeout=30,
                                allow_redirects=False, **kwargs)

    def token(self, sub):
        """A bearer header for `sub`; the dig allow-file lists only "diguser"."""
        scope = "storage.read:/ storage.modify:/"
        return {"Authorization":
                f"Bearer {self.issuer.generate(sub=sub, scope=scope)}"}

    # -- the tree ----------------------------------------------------------- #

    def unique(self, prefix, stem="o"):
        """A target name no other row has used, so `stored()` is unambiguous."""
        self._seq += 1
        return f"{prefix}{stem}{self._seq}.bin"

    def stored(self, uri):
        """What is on disk at the export path `uri` maps to, or None."""
        target = self.data / uri.lstrip("/")
        return target.read_bytes() if target.is_file() else None

    # -- the logs ----------------------------------------------------------- #

    def errlog(self):
        """Instance prefixes are wiped at teardown, so failures quote inline."""
        try:
            return (self.logs / "error.log").read_text(errors="replace")
        except OSError:                          # pragma: no cover - diagnostic
            return "(error log unavailable)"


def _issuer():
    """The suite's shared test JWKS, minted once if this is the first user.

    Same recipe as test_dig.py's ``_issuer`` — dig keys its allow-file on the
    token subject, so §C needs a verifier and two distinct principals.
    """
    iss = TokenIssuer(TOKENS_DIR)
    if not os.path.exists(iss.key_path) or not os.path.exists(iss.jwks_path):
        iss.init_keys()
    return iss


@pytest.fixture
def sc(lifecycle, tmp_path):
    """Eleven locations, seven vhosts, one listener.

    Every arm gets an identical archive and an identical parent collection under
    its own prefix, so a verdict that differs between two arms cannot be
    explained by their contents.  The dig export is a sibling of the WebDAV
    export, never inside it, which is what makes the shadow reading in §C a
    statement about two different files.
    """
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    data.mkdir()
    for arm in EXPORT_ARMS:
        (data / arm).mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(data / arm / "a.zip", "w") as z:
            z.writestr(MEMBER_NAME, MEMBER, compress_type=zipfile.ZIP_STORED)
        (data / arm / SECRET_NAME).write_bytes(SECRET)

    # The object the dig prefix shadows.  Its parent collections also make the
    # `off`-arm PUT row in §C a write into an existing collection, so a 201 is
    # about the flag and not about RFC 4918 §9.7.1.
    shadow = data / DIG_TARGET.lstrip("/")
    shadow.parent.mkdir(parents=True, exist_ok=True)
    shadow.write_bytes(SHADOW_BODY)

    digexp = tmp_path / "digexp"
    digexp.mkdir()
    (digexp / "server.cfg").write_bytes(DIG_BODY)
    allow = tmp_path / "dig.allow"
    allow.write_text("# principal export\ndiguser conf\n")

    issuer = _issuer()
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit16o_webdav_scoped.conf",
        protocol="http",
        data_root=str(data),
        template_values={"BIND_HOST": BIND_HOST,
                         "DIG_EXPORT": str(digexp),
                         "DIG_ALLOW": str(allow),
                         "JWKS_PATH": issuer.jwks_path,
                         "ISSUER": issuer.issuer,
                         "AUDIENCE": issuer.audience},
        reason="audit-16o the three MAIN|SRV|LOC webdav flags at value "
               "granularity"))
    return _Scoped(endpoint, data, digexp, issuer)


# --------------------------------------------------------------------------- #
# §A — brix_webdav_zip_access                                                  #
# --------------------------------------------------------------------------- #

def _unzip(sc, host, prefix, member):
    """GET the arm's archive asking for `member`."""
    return sc.request("GET", f"{prefix}a.zip?xrdcl.unzip={member}", host=host)

