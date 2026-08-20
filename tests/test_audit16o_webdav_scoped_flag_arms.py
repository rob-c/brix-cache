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


class TestTheZipAccessArm:
    """``get_zip_member_serve`` (get.c:152-172) returns NGX_DECLINED before it
    looks at the query string when the flag is clear, so the GET falls through to
    the whole-file path.  Both arms therefore answer 200 for the same URI and the
    reading is the BODY — a status-only table would say the flag does nothing."""

    @pytest.mark.parametrize("host,prefix", ZIP_ON)
    def test_the_enabled_arm_serves_the_member(self, sc, host, prefix):
        """The control every row below is measured against: with the flag set,
        `xrdcl.unzip` selects one member of the archive."""
        r = _unzip(sc, host, prefix, MEMBER_NAME)
        assert r.status_code == 200, (r.status_code, sc.errlog()[-2000:])
        assert r.content == MEMBER, r.content[:80]

    @pytest.mark.parametrize("host,prefix", ZIP_OFF)
    def test_the_disabled_arm_serves_the_whole_archive(self, sc, host, prefix):
        """The same request on every clear arm — written `off` in a location,
        absent, written `off` in a location under a server that wrote `on`, and
        written `off` in a server{} — yields the archive itself.  The argument is
        not refused, it is not read."""
        r = _unzip(sc, host, prefix, MEMBER_NAME)
        assert r.status_code == 200, (r.status_code, sc.errlog()[-2000:])
        assert r.content.startswith(b"PK\x03\x04"), r.content[:80]
        assert r.content != MEMBER
        assert MEMBER in r.content, "the member is IN the archive it served"

    def test_the_opt_out_is_the_reading_absence_cannot_express(self, sc):
        """The whole point of three legal scopes, in one comparison.

        ``/inherit/`` and ``/opt-out/`` are the same body under the same server;
        the only difference is that one writes ``off``.  The server wrote ``on``,
        so absence in ``/inherit/`` inherits it — which is exactly why ``off`` in
        ``/opt-out/`` is not a redundant spelling of saying nothing.
        """
        inherited = _unzip(sc, SRV_ON, "/inherit/", MEMBER_NAME)
        opted_out = _unzip(sc, SRV_ON, "/opt-out/", MEMBER_NAME)
        assert inherited.status_code == opted_out.status_code == 200
        assert inherited.content == MEMBER, inherited.content[:80]
        assert opted_out.content.startswith(b"PK\x03\x04"), opted_out.content[:80]

    def test_a_bare_location_matches_a_location_that_wrote_off(self, sc):
        """And the other half: where there is nothing above it to inherit, the
        merge default makes ``off`` and absent the same configuration.  Both
        halves are true at once, which is why the ladder needs both rows."""
        wrote_off = _unzip(sc, DEFAULT_VHOST, "/zp-off/", MEMBER_NAME)
        wrote_nothing = _unzip(sc, DEFAULT_VHOST, "/zp-bare/", MEMBER_NAME)
        assert wrote_off.status_code == wrote_nothing.status_code == 200
        assert wrote_off.content == wrote_nothing.content

    @pytest.mark.parametrize("host,prefix", ZIP_ON + ZIP_OFF)
    def test_no_argument_is_the_whole_archive_on_every_arm(self, sc, host,
                                                           prefix):
        """The attribution control.  ``zr == 0`` is NGX_DECLINED on the enabled
        arm too (get.c:170-171), so a request that carries no `xrdcl.unzip` is
        answered identically everywhere — the flag changes the handling of
        requests that ask for a member, and of nothing else."""
        r = sc.request("GET", f"{prefix}a.zip", host=host)
        assert r.status_code == 200, (r.status_code, sc.errlog()[-2000:])
        assert r.content.startswith(b"PK\x03\x04"), r.content[:80]

    @pytest.mark.parametrize("member", ("../secret.txt",
                                        "%2E%2E%2Fsecret.txt",
                                        "/etc/passwd",
                                        "a/../../secret.txt",
                                        ""))
    @pytest.mark.parametrize("host,prefix", ZIP_ON)
    def test_the_enabled_arm_refuses_a_member_name_that_escapes(self, sc, host,
                                                                prefix, member):
        """The security negative for the ``on`` arm.  ``zip_http_name_ok``
        (zip_http.c:24-40) rejects a leading '/', a leading or embedded '../' and
        an empty name, and ``brix_zip_http_member_arg`` URL-DECODES before that
        check (zip_http.c:61-65) — so the percent-encoded form is refused too,
        with 400 and not with the escaped file."""
        r = _unzip(sc, host, prefix, member)
        assert r.status_code == 400, (r.status_code, sc.errlog()[-2000:])
        assert SECRET not in r.content, "an escape served the file next door"
        assert b"root:" not in r.content

    @pytest.mark.parametrize("member", ("../secret.txt",
                                        "%2E%2E%2Fsecret.txt",
                                        "/etc/passwd"))
    @pytest.mark.parametrize("host,prefix", ZIP_OFF)
    def test_the_disabled_arm_never_reads_the_escape_at_all(self, sc, host,
                                                            prefix, member):
        """The mirror of it, and the reason the flag's ``off`` arm is not a
        weaker security posture: the argument is never parsed, so there is no
        name to escape with.  The archive is served and the file next door is
        not."""
        r = _unzip(sc, host, prefix, member)
        assert r.status_code == 200, (r.status_code, sc.errlog()[-2000:])
        assert r.content.startswith(b"PK\x03\x04"), r.content[:80]
        assert SECRET not in r.content

    @pytest.mark.parametrize("host,prefix", ZIP_ON)
    def test_the_enabled_arm_404s_a_member_that_is_not_there(self, sc, host,
                                                             prefix):
        """A well-formed name for a member the archive does not contain is
        BRIX_ZIP_NOMEMBER -> 404 (zip_http.c:153), which is the third status this
        flag can produce and separates "malformed" from "absent"."""
        r = _unzip(sc, host, prefix, "nope.txt")
        assert r.status_code == 404, (r.status_code, sc.errlog()[-2000:])

    @pytest.mark.parametrize("host,prefix", ZIP_OFF)
    def test_the_disabled_arm_serves_the_archive_for_a_missing_member(
            self, sc, host, prefix):
        """The same name on a clear arm is a 200, because the 404 comes from the
        central-directory walk the flag gates."""
        r = _unzip(sc, host, prefix, "nope.txt")
        assert r.status_code == 200, (r.status_code, sc.errlog()[-2000:])
        assert r.content.startswith(b"PK\x03\x04"), r.content[:80]


# --------------------------------------------------------------------------- #
# §B — brix_webdav_require_digest                                              #
# --------------------------------------------------------------------------- #

def _put(sc, host, prefix, headers, body=BODY):
    """PUT `body` to a name nothing else has used, returning (response, stored)."""
    uri = sc.unique(prefix)
    r = sc.request("PUT", uri, host=host, data=body, headers=headers)
    return r, sc.stored(uri)


# The header forms that carry a digest the server can read and check.  Each is
# correct for BODY, so `on` and `off` must both accept them.
GOOD_DIGESTS = (
    ("adler32", {"Digest": f"adler32={ADLER32}"}),
    ("md5", {"Digest": f"md5={MD5_B64}"}),
    ("sha-256", {"Digest": f"sha-256={SHA256_B64}"}),
    ("content-md5", {"Content-MD5": MD5_B64}),
)
# Forms that carry a digest the server can read and that does NOT match.
BAD_DIGESTS = (
    ("adler32 mismatch", {"Digest": "adler32=deadbeef"}),
    ("content-md5 mismatch", {"Content-MD5": WRONG_MD5_B64}),
    ("md5 not base64", {"Digest": "md5=not-base64!!"}),
)
# Forms that carry NOTHING the server can use — WEBDAV_DIGEST_NONE, the one
# outcome this flag decides.
UNUSABLE_DIGESTS = (
    ("no header at all", {}),
    ("unknown algorithm", {"Digest": "sha3-512=AAAA"}),
    ("empty Digest value", {"Digest": ""}),
    ("Digest with no '='", {"Digest": "adler32"}),
)


class TestTheRequireDigestArm:
    """``webdav_put_verify_ingest_digest`` (put_body_digest.c:241-266) consults
    the flag at exactly one place — the ``WEBDAV_DIGEST_NONE`` arm — so the
    table has to separate "nothing usable was asserted" from "something was
    asserted and it was wrong"."""

    @pytest.mark.parametrize("label,headers", UNUSABLE_DIGESTS,
                             ids=[x[0] for x in UNUSABLE_DIGESTS])
    @pytest.mark.parametrize("host,prefix", DIGEST_ON)
    def test_the_enabled_arm_refuses_a_write_it_cannot_verify(
            self, sc, host, prefix, label, headers):
        """Four header forms, one outcome: the server has no digest it can check,
        and the flag turns that into a refusal that stores nothing.  The three
        malformed forms land here and not with the mismatches because
        ``webdav_digest_select`` reports them as NONE, not BAD."""
        r, stored = _put(sc, host, prefix, headers)
        assert r.status_code == 400, (label, r.status_code,
                                      sc.errlog()[-2000:])
        assert stored is None, f"{label}: a refused PUT left bytes on disk"

    @pytest.mark.parametrize("label,headers", UNUSABLE_DIGESTS,
                             ids=[x[0] for x in UNUSABLE_DIGESTS])
    @pytest.mark.parametrize("host,prefix", DIGEST_OFF)
    def test_the_disabled_arm_accepts_a_write_it_cannot_verify(
            self, sc, host, prefix, label, headers):
        """The same four forms on every clear arm commit — best-effort interop is
        the default, and that is what the flag exists to switch off."""
        r, stored = _put(sc, host, prefix, headers)
        assert r.status_code == 201, (label, r.status_code,
                                      sc.errlog()[-2000:])
        assert stored == BODY, label

    @pytest.mark.parametrize("label,headers", GOOD_DIGESTS,
                             ids=[x[0] for x in GOOD_DIGESTS])
    @pytest.mark.parametrize("host,prefix", DIGEST_ON + DIGEST_OFF)
    def test_a_correct_digest_commits_on_every_arm(self, sc, host, prefix,
                                                   label, headers):
        """The first attribution control: the flag is a requirement, not a
        verifier.  Four readable header forms that match the body are accepted
        identically on all six arms."""
        r, stored = _put(sc, host, prefix, headers)
        assert r.status_code == 201, (label, r.status_code,
                                      sc.errlog()[-2000:])
        assert stored == BODY, label

    @pytest.mark.parametrize("label,headers", BAD_DIGESTS,
                             ids=[x[0] for x in BAD_DIGESTS])
    @pytest.mark.parametrize("host,prefix", DIGEST_ON + DIGEST_OFF)
    def test_a_wrong_digest_is_refused_on_every_arm(self, sc, host, prefix,
                                                     label, headers):
        """The second, and the one that matters: VERIFICATION is not gated by
        this flag.  A digest the server can read and that does not match the body
        is 400 with nothing stored whether the flag is set or clear — so a
        deployment that leaves it off has not turned off integrity checking, only
        the requirement to assert one."""
        r, stored = _put(sc, host, prefix, headers)
        assert r.status_code == 400, (label, r.status_code,
                                      sc.errlog()[-2000:])
        assert stored is None, f"{label}: a refused PUT left bytes on disk"

    def test_the_opt_out_is_the_reading_absence_cannot_express(self, sc):
        """Same comparison as §A, on the other flag: ``/inherit/`` writes nothing
        and inherits the server's ``on``; ``/opt-out/`` writes ``off`` and is the
        only spelling that could have done so."""
        inherited, in_stored = _put(sc, SRV_ON, "/inherit/", {})
        opted_out, out_stored = _put(sc, SRV_ON, "/opt-out/", {})
        assert inherited.status_code == 400, sc.errlog()[-2000:]
        assert in_stored is None
        assert opted_out.status_code == 201, sc.errlog()[-2000:]
        assert out_stored == BODY

    def test_the_server_scope_off_arm_reaches_the_setter(self, sc):
        """``srv-off.test`` writes ``brix_webdav_require_digest off`` in a
        ``server{}``, which nothing in the tree had ever done in either arm.  Its
        one location writes neither flag, so the 201 is the server-scope value
        merging down and not a location default."""
        r, stored = _put(sc, SRV_OFF, "/", {})
        assert r.status_code == 201, (r.status_code, sc.errlog()[-2000:])
        assert stored == BODY


# --------------------------------------------------------------------------- #
# §B2 — DEFECT CANDIDATE #90: Content-Encoding skips the requirement            #
# --------------------------------------------------------------------------- #

class TestTheContentEncodingSkip:
    """The security negative for ``require_digest``, and a defect.

    put_body_digest.c:253-258 returns NGX_OK on any non-empty
    ``Content-Encoding`` before the flag is consulted.  For a codec that really
    decodes, skipping is correct — the asserted digest describes the decoded
    bytes.  ``identity`` is a registered available codec that decodes nothing
    (core/compat/codec_core.c:65-67), so the header is a bare verification-skip switch.
    """

    IDENTITY = {"Content-Encoding": "identity"}

    @pytest.mark.parametrize("host,prefix", DIGEST_ON)
    def test_identity_defeats_the_requirement_entirely(self, sc, host, prefix):
        """Half one: a digest-less PUT is accepted on an export configured to
        refuse writes it cannot verify.  The stored bytes are the request body
        unchanged, so nothing was decoded — there was no transformation for the
        skip to be about."""
        r, stored = _put(sc, host, prefix, dict(self.IDENTITY))
        assert r.status_code == 201, (r.status_code, sc.errlog()[-2000:])
        assert stored == BODY, "the body was stored verbatim, undecoded"

    @pytest.mark.parametrize("label,headers", BAD_DIGESTS,
                             ids=[x[0] for x in BAD_DIGESTS])
    @pytest.mark.parametrize("host,prefix", DIGEST_ON + DIGEST_OFF)
    def test_identity_also_defeats_verification_of_a_wrong_digest(
            self, sc, host, prefix, label, headers):
        """Half two, and the worse half: a digest the client ASSERTED and that
        does not match the body is never checked.  The same three headers are
        400 on every arm without the Content-Encoding (see
        ``test_a_wrong_digest_is_refused_on_every_arm``), so this is the header
        and not the flag."""
        r, stored = _put(sc, host, prefix, {**headers, **self.IDENTITY})
        assert r.status_code == 201, (label, r.status_code,
                                      sc.errlog()[-2000:])
        assert stored == BODY, label

    @pytest.mark.parametrize("host,prefix", DIGEST_ON)
    def test_an_empty_content_encoding_does_not_skip(self, sc, host, prefix):
        """The first fence around the defect: the guard is
        ``ce != NULL && ce->value.len > 0``, so a present-but-empty header falls
        through to the digest check and the requirement still bites.  Pinning
        this says the bypass needs a VALUE and is not merely the header's
        presence."""
        r, stored = _put(sc, host, prefix, {"Content-Encoding": ""})
        assert r.status_code == 400, (r.status_code, sc.errlog()[-2000:])
        assert stored is None

    @pytest.mark.parametrize("host,prefix", DIGEST_ON + DIGEST_OFF)
    def test_a_codec_that_really_decodes_fails_honestly(self, sc, host, prefix):
        """The second fence, and the shape of the cure.  ``deflate`` over a body
        that is not deflate-coded is 400 on BOTH arms — the decode is attempted
        and it fails.  Only a no-op codec turns the skip into a bypass, which is
        why gating it on ``put_codec != BRIX_CODEC_IDENTITY`` would close the
        defect without changing any legitimate transfer."""
        r, stored = _put(sc, host, prefix, {"Content-Encoding": "deflate"})
        assert r.status_code == 400, (r.status_code, sc.errlog()[-2000:])
        assert stored is None

    @pytest.mark.parametrize("host,prefix", DIGEST_ON + DIGEST_OFF)
    def test_an_unregistered_codec_is_refused_before_any_of_this(self, sc, host,
                                                                  prefix):
        """The boundary of the bypass: an unknown token is 415 on both arms
        (put_body.c:316-329), so the skip is reachable only through a codec the
        server actually registered.  ``identity`` is one of them, which is
        exactly the defect."""
        r, stored = _put(sc, host, prefix, {"Content-Encoding": "no-such-codec"})
        assert r.status_code == 415, (r.status_code, sc.errlog()[-2000:])
        assert stored is None


# --------------------------------------------------------------------------- #
# §C — brix_webdav_dig                                                         #
# --------------------------------------------------------------------------- #

class TestTheDigArm:
    """``dig_precheck`` (dig.c:158-174) is consulted from the WebDAV content
    dispatcher (dispatch.c:158-163) and returns NGX_DECLINED when the flag is
    clear, so the reserved prefix is not refused — it stops being a diagnostics
    endpoint and becomes part of the export again."""

    def test_the_enabled_arm_serves_the_dig_export(self, sc):
        """The control.  An authorized principal reads the file from the DIG
        export, which lives outside the WebDAV export entirely."""
        r = sc.request("GET", DIG_TARGET, host=DIG_VHOSTS["dig-on"],
                       headers=sc.token("diguser"))
        assert r.status_code == 200, (r.status_code, sc.errlog()[-2000:])
        assert r.content == DIG_BODY, r.content[:80]

    @pytest.mark.parametrize("arm", DIG_OFF_ARMS)
    def test_every_clear_arm_serves_the_export_instead(self, sc, arm):
        """The same URI, the same token, on the three ways the flag can be clear
        — a per-location opt-out under a server that wrote ``on``, a server that
        wrote ``off``, and a server that wrote nothing while still declaring the
        export and the allow-file.  All three serve the OTHER file, so the flag
        decides which of two trees owns the URI."""
        r = sc.request("GET", DIG_TARGET, host=DIG_VHOSTS[arm],
                       headers=sc.token("diguser"))
        assert r.status_code == 200, (arm, r.status_code, sc.errlog()[-2000:])
        assert r.content == SHADOW_BODY, (arm, r.content[:80])

    def test_the_opt_out_is_the_reading_absence_cannot_express(self, sc):
        """``dig-locoff.test`` writes ``brix_webdav_dig on`` in its ``server{}``
        and ``off`` in the one location that can hold the reserved prefix.  Its
        sibling ``dig-on.test`` is the same server without that location, so the
        difference in which file answers is the location's ``off`` and nothing
        else — and absence there would have inherited the ``on``."""
        enabled = sc.request("GET", DIG_TARGET, host=DIG_VHOSTS["dig-on"],
                             headers=sc.token("diguser"))
        opted_out = sc.request("GET", DIG_TARGET,
                               host=DIG_VHOSTS["dig-locoff"],
                               headers=sc.token("diguser"))
        assert enabled.status_code == opted_out.status_code == 200
        assert enabled.content == DIG_BODY
        assert opted_out.content == SHADOW_BODY

    @pytest.mark.parametrize("sub", ("otheruser", None))
    def test_the_enabled_arm_is_fail_closed_for_anyone_unlisted(self, sc, sub):
        """dig_authz (dig.c:58-113) allows only an explicitly listed principal;
        an authenticated principal the allow-file does not name and an anonymous
        request are both 403."""
        headers = sc.token(sub) if sub else {}
        r = sc.request("GET", DIG_TARGET, host=DIG_VHOSTS["dig-on"],
                       headers=headers)
        assert r.status_code == 403, (sub, r.status_code, sc.errlog()[-2000:])
        assert DIG_BODY not in r.content

    @pytest.mark.parametrize("arm", DIG_OFF_ARMS)
    @pytest.mark.parametrize("sub", ("otheruser", None))
    def test_a_clear_arm_answers_the_principals_dig_refuses(self, sc, arm, sub):
        """The observation in the header docstring, measured.  The flag does not
        layer on top of the export's authorization — it REPLACES it for this
        subtree.  Clear the flag and the same anonymous or unlisted principal
        that dig refused is answered by the export's own policy, which here is
        ``brix_webdav_auth optional``."""
        headers = sc.token(sub) if sub else {}
        r = sc.request("GET", DIG_TARGET, host=DIG_VHOSTS[arm], headers=headers)
        assert r.status_code == 200, (arm, sub, r.status_code,
                                      sc.errlog()[-2000:])
        assert r.content == SHADOW_BODY, (arm, sub, r.content[:80])

    @pytest.mark.parametrize("method", ("PUT", "DELETE", "PROPFIND"))
    def test_the_enabled_arm_refuses_every_write_method(self, sc, method):
        """dig is read-only at its own gate (dig.c:170-172), and the export
        beneath it permits writes — so this 405 is the flag's and not
        ``brix_allow_write``'s.  A write-disabled export would have answered 403
        in the access phase before the content handler ran at all."""
        uri = sc.unique(f"{DIG_PREFIX}conf/", stem="w")
        r = sc.request(method, uri, host=DIG_VHOSTS["dig-on"], data=BODY,
                       headers=sc.token("diguser"))
        assert r.status_code == 405, (method, r.status_code,
                                      sc.errlog()[-2000:])
        assert sc.stored(uri) is None, f"{method} wrote through a 405"

    @pytest.mark.parametrize("arm", DIG_OFF_ARMS)
    def test_a_clear_arm_makes_the_reserved_prefix_writable(self, sc, arm):
        """The security negative, and the sharpest row in §C: with the flag set,
        a PUT under the reserved prefix is refused and nothing lands; with it
        clear the identical request is a plain WebDAV write INTO the export, at
        the URI the diagnostics endpoint would otherwise own."""
        uri = sc.unique(f"{DIG_PREFIX}conf/", stem="w")
        r = sc.request("PUT", uri, host=DIG_VHOSTS[arm], data=BODY,
                       headers=sc.token("diguser"))
        assert r.status_code == 201, (arm, r.status_code, sc.errlog()[-2000:])
        assert sc.stored(uri) == BODY, arm

    def test_the_prefix_itself_is_not_captured_on_either_arm(self, sc):
        """``r->uri.len <= BRIX_DIG_PREFIX_LEN`` (dig.c:164-169) declines a URI
        that is exactly the prefix, so ``/.well-known/dig/`` is a collection in
        the export on BOTH arms.  The flag captures strictly longer URIs only,
        and the boundary is worth a row because an off-by-one there would move a
        whole subtree."""
        for arm in ("dig-on",) + DIG_OFF_ARMS:
            r = sc.request("GET", DIG_PREFIX, host=DIG_VHOSTS[arm],
                           headers=sc.token("diguser"))
            assert r.status_code == 403, (arm, r.status_code,
                                          sc.errlog()[-2000:])

    def test_nothing_outside_the_prefix_moves_on_either_arm(self, sc):
        """The attribution control for the vhosts: a URI that is not under the
        reserved prefix is served by the export identically on all four arms, so
        no §C row can be explained by the vhost rather than the flag."""
        for arm in ("dig-on",) + DIG_OFF_ARMS:
            r = sc.request("GET", f"/{SECRET_NAME}", host=DIG_VHOSTS[arm],
                           headers=sc.token("diguser"))
            assert r.status_code == 200, (arm, r.status_code,
                                          sc.errlog()[-2000:])
            assert r.content == SECRET, arm

    def test_a_target_with_no_file_part_reads_differently_on_each_arm(self, sc):
        """``/.well-known/dig/conf`` has an export name and no file, which
        dig_parse_target (dig.c:190-196) reports as 404.  On a clear arm the same
        URI names a collection in the export, which WebDAV GET refuses with 403.
        Two different components, same URI, and the flag chooses which one
        answers."""
        enabled = sc.request("GET", DIG_NO_FILE_PART,
                             host=DIG_VHOSTS["dig-on"],
                             headers=sc.token("diguser"))
        assert enabled.status_code == 404, (enabled.status_code,
                                            sc.errlog()[-2000:])
        for arm in DIG_OFF_ARMS:
            r = sc.request("GET", DIG_NO_FILE_PART, host=DIG_VHOSTS[arm],
                           headers=sc.token("diguser"))
            assert r.status_code == 403, (arm, r.status_code,
                                          sc.errlog()[-2000:])

    def test_an_unknown_export_name_carries_no_information(self, sc):
        """Recorded because it is a row a reader would expect to discriminate and
        it does not.  ``dig_match_export`` misses (dig.c:242) on the enabled arm
        and the export has no such file on the clear arms, so all four answer 404
        for two unrelated reasons.  A table that counted this as agreement
        between the arms would be measuring a coincidence."""
        for arm in ("dig-on",) + DIG_OFF_ARMS:
            r = sc.request("GET", DIG_UNKNOWN_EXPORT, host=DIG_VHOSTS[arm],
                           headers=sc.token("diguser"))
            assert r.status_code == 404, (arm, r.status_code,
                                          sc.errlog()[-2000:])


# --------------------------------------------------------------------------- #
# §D — the parse tier                                                          #
# --------------------------------------------------------------------------- #

def _parse(tmp_path, **slots):
    """`nginx -t` on file 14's scaffold with the named slots filled.

    Every slot defaults to empty so a case names only what it is about; the
    scaffold's probe location writes none of the three, so a negative about one
    of them is never answered by a duplicate diagnostic first.
    """
    data = tmp_path / "parse-data"
    data.mkdir(exist_ok=True)
    values = {"PORT": PARSE_PLACEHOLDER_PORT,
              "STREAM_PORT": PARSE_PLACEHOLDER_PORT + 1,
              "LOG_DIR": str(tmp_path),
              "DATA": str(data),
              "LOC_KNOBS": "", "SRV_KNOBS": "", "HTTP_KNOBS": "",
              "OUTER": "", "STREAM_KNOBS": "", "STREAM_MAIN": "",
              "EXTRA_LOC": ""}
    values.update(slots)
    result = nginx_t("nginx_audit16nparse.conf", str(tmp_path), **values)
    return result.returncode, (result.stdout or "") + (result.stderr or "")


# The three scopes the declaration names, and the slot each one is.
RIGHT_SCOPES = ("LOC_KNOBS", "SRV_KNOBS", "HTTP_KNOBS")
# Every placement the declaration does NOT name.
WRONG_SCOPES = ("OUTER", "STREAM_KNOBS", "STREAM_MAIN")


@_needs_nginx
class TestTheParseTier:
    """Values, arity, duplicates, and the placement matrix — asked once per scope
    the declaration names, because the runtime tier can only carry two of the
    three at a time."""

    @pytest.mark.parametrize("scope", RIGHT_SCOPES)
    @pytest.mark.parametrize("arm", ("on", "off"))
    @pytest.mark.parametrize("flag", FLAG_NAMES)
    def test_both_arms_are_accepted_in_every_declared_scope(self, tmp_path,
                                                             flag, arm, scope):
        """The audit's step-1 question, asked at all three scopes.  Nine of these
        eighteen cases are the ``off`` arm the corpus never wrote, and three of
        them are a scope no arm of these directives had ever been written in."""
        rc, out = _parse(tmp_path, **{scope: f"        {flag} {arm};\n"})
        assert rc == 0, out

    @pytest.mark.parametrize("scope", RIGHT_SCOPES)
    @pytest.mark.parametrize("flag", FLAG_NAMES)
    def test_the_off_arm_advises_nothing(self, tmp_path, flag, scope):
        """Writing the value that disables a feature must not produce a
        diagnostic of any severity, in any scope — an operator who turns
        something off is not misconfiguring anything."""
        rc, out = _parse(tmp_path, **{scope: f"        {flag} off;\n"})
        assert rc == 0, out
        assert _diagnostics(out) == [], out

    def test_a_server_on_with_a_location_off_parses_clean(self, tmp_path):
        """The file's whole subject, at the parse tier: the opt-out is not a
        conflict to be diagnosed.  All three flags written ``on`` in the server
        and ``off`` in a location beneath it is an ordinary configuration."""
        srv = "".join(f"        {f} on;\n" for f in FLAG_NAMES)
        loc = "".join(f"            {f} off;\n" for f in FLAG_NAMES)
        rc, out = _parse(tmp_path, SRV_KNOBS=srv, LOC_KNOBS=loc)
        assert rc == 0, out
        assert _diagnostics(out) == [], out

    @pytest.mark.parametrize("value", ("1", "0", "yes", "enabled", "true"))
    @pytest.mark.parametrize("flag", FLAG_NAMES)
    def test_only_on_and_off_are_accepted(self, tmp_path, flag, value):
        """``ngx_conf_set_flag_slot`` compares against exactly two tokens, so
        every other spelling of a boolean is refused rather than guessed at."""
        rc, out = _parse(tmp_path, LOC_KNOBS=f"            {flag} {value};\n")
        assert rc != 0, out
        assert 'invalid value "%s"' % value in out, out

    @pytest.mark.parametrize("flag", FLAG_NAMES)
    def test_two_arguments_are_refused(self, tmp_path, flag):
        """NGX_CONF_FLAG is NGX_CONF_TAKE1 plus a value check; a second argument
        is an arity error and not a silently ignored token."""
        rc, out = _parse(tmp_path, LOC_KNOBS=f"            {flag} on off;\n")
        assert rc != 0, out
        assert "invalid number of arguments" in out, out

    @pytest.mark.parametrize("flag", FLAG_NAMES)
    def test_a_second_write_in_the_same_scope_is_a_duplicate(self, tmp_path,
                                                              flag):
        """Two values in one scope is a duplicate, which is what makes the
        server/location pair above the ONLY way to write both arms of one flag in
        one configuration."""
        rc, out = _parse(tmp_path,
                         LOC_KNOBS=f"            {flag} on;\n"
                                   f"            {flag} off;\n")
        assert rc != 0, out
        assert "duplicate" in out, out

    @pytest.mark.parametrize("scope", WRONG_SCOPES)
    @pytest.mark.parametrize("arm", ("on", "off"))
    @pytest.mark.parametrize("flag", FLAG_NAMES)
    def test_no_other_placement_is_allowed(self, tmp_path, flag, arm, scope):
        """The main context and the stream plane must refuse, and the refusal
        must be about the CONTEXT: nginx searches every module's command table
        before it checks scope, so "unknown directive" here would mean the
        directive had been dropped from the table rather than misplaced."""
        rc, out = _parse(tmp_path, **{scope: f"    {flag} {arm};\n"})
        assert rc != 0, out
        assert "is not allowed here" in out, out
        assert "unknown directive" not in out, out


# --------------------------------------------------------------------------- #
# §E — the declarations this file's readings depend on                          #
# --------------------------------------------------------------------------- #

class TestTheDeclarationsAreWhatTheFileSays:
    """Every reading above is an inference from four lines of C.  If any of them
    changes, the tests would keep passing while measuring something else, so the
    lines themselves are pinned."""

    @pytest.mark.parametrize("flag,field", FLAGS,
                             ids=[f for f, _ in FLAGS])
    def test_the_scope_is_all_three_and_the_setter_is_the_flag_slot(self, flag,
                                                                     field):
        """The declaration is what makes the opt-out reachable: three legal
        scopes, and ``NGX_HTTP_LOC_CONF_OFFSET`` so a server-scope value becomes
        the parent of every location below it."""
        text = MODULE_COMMANDS_C.read_text()
        marker = f'{{ ngx_string("{flag}"),'
        assert marker in text, flag
        block = text.split(marker, 1)[1]
        # splitlines()[0] is the tail of the marker's own line, which is empty.
        lines = [ln.strip() for ln in block.splitlines()[1:5]]
        assert lines[0] == ("NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | "
                            "NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,"), lines
        assert lines[1] == "ngx_conf_set_flag_slot,", lines
        assert lines[2] == "NGX_HTTP_LOC_CONF_OFFSET,", lines
        assert f"offsetof(ngx_http_brix_webdav_loc_conf_t, {field})" in lines[3], \
            lines

    @pytest.mark.parametrize("field", [f for _, f in FLAGS])
    def test_all_three_merge_to_zero(self, field):
        """The bare arms read this 0.  A merge default of 1 would make the
        ``on`` arm the redundant one instead — which is the case for
        ``brix_webdav_upload_resume`` one file over, so the direction is not a
        given."""
        squashed = " ".join(CONFIG_MERGE_C.read_text().split())
        assert (f"ngx_conf_merge_value(conf->{field}, prev->{field}, 0);"
                in squashed), field

    def test_the_digest_skip_still_precedes_the_requirement(self):
        """The pin for #90: the Content-Encoding early return is still ABOVE the
        ``require_digest`` consultation, and still keyed on the header's length
        rather than on the codec doing any work.  When that changes, the four
        rows in §B2 change with it and should be revisited rather than
        adjusted."""
        text = PUT_BODY_DIGEST_C.read_text()
        skip = text.index('brix_http_find_header(r, "Content-Encoding"')
        guard = text.index("ce->value.len > 0", skip)
        gate = text.index("conf->require_digest", guard)
        assert skip < guard < gate, (skip, guard, gate)

    def test_identity_is_a_registered_codec_token(self):
        """And the other half of #90: ``identity`` reaching the skip at all is
        what makes the header a bypass rather than a description of a transfer
        encoding the server is about to undo."""
        assert '"identity"' in CODEC_CORE_C.read_text()

    def test_the_dig_prefix_boundary_is_strict(self):
        """The prefix-itself row in §C depends on the comparison being ``<=``
        against the prefix length, so a URI equal to the prefix declines."""
        text = DIG_C.read_text()
        assert "r->uri.len <= BRIX_DIG_PREFIX_LEN" in text

    def test_zip_member_selection_is_gated_before_the_argument_is_read(self):
        """The §A readings all rest on the flag being checked BEFORE
        ``brix_zip_http_member_arg``, which is why the ``off`` arm cannot 400 an
        escape: it never parses one."""
        text = GET_C.read_text()
        body = text.split("get_zip_member_serve(ngx_http_request_t *r,", 1)[1]
        body = body.split("\n}\n", 1)[0]
        assert body.index("!conf->zip_access") < \
            body.index("brix_zip_http_member_arg"), body
