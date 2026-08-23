"""
test_audit15k_s3_coresidency.py — §Method step 3, re-run at the granularity the
step declares (docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-15.md).

§E's third method note is a self-assessment:

    "Unit granularity is per-file; a pair counts as co-tested even if the two
     features sit in different server blocks of one conf.  Zero counts are
     therefore *conservative* — every zero really is a zero."

The zeros are conservative.  The NON-zeros are not, and that half is not
stated.  Step 3's declared semantics are "one server instance runs both
features at once"; scored per file, a pair reads "covered" when its two markers
live in two different `server {}` blocks that never share a request path.
Re-running the matrix at both granularities over the same corpus returns **24
pairs the 08-15 pass recorded as covered that no single server block in the
tree actually runs** — counting a block's markers as its own body PLUS the
`http {}` context it inherits from, without which the measurement invents 21
further gaps that nginx's own merge closes.  Eight of the 24 are one cluster:
the S3 plane's security options.  `auth:token × proto:s3` alone spans 11 files
and 0 blocks.

That cluster is worth the block because CLAUDE.md INVARIANT 6 ("S3 SigV4 ≠ WLCG
token auth") makes the question sharp: when a WebDAV security directive is
written inside an `brix_s3 on` location, is it refused, or is it accepted and
silently ignored?  It is accepted and silently ignored — and the plane's own
equivalents (`brix_s3_token*`, `brix_read_only`, `brix_authdb`) behave three
different ways, which is why they are measured here side by side in ONE server
block (`nginx_audit15k_s3cores.conf`) rather than one file at a time.

WHAT THE BLOCK ESTABLISHES

- `brix_read_only` **is** wired on this plane and is order-independent: a signed
  PUT/DELETE reads 403 `AccessDenied` "Write access is disabled." whether the
  directive is written before or after `brix_allow_write on`, because
  `brix_shared_apply_read_only()` runs at the *end* of the merge
  (`shared_conf.h:145`, applied at `:501`) and forces `allow_write = 0`.  The
  four gate sites are `handler_object_route.c:152,202,239` and `handler.c:171`.
- `brix_s3_token on` **is** the token gate this plane has (`auth_bearer.c`,
  routed by `s3_sigv4_bearer_intercept`, `auth_sigv4_verify.c:158`), and it
  coexists with SigV4 keys in the same location exactly as INVARIANT 6 requires:
  bearer OR signature, per request, each verified by its own tier.
- `brix_authdb_format xrdacc` **is** consulted (`s3_acc_check`,
  `handler.c:460`) — but only `u *` rules can ever match.

DEFECT CANDIDATE #36 (security, silent no-op) — four WebDAV security directives
parse inside an S3 location and enforce nothing, with no diagnostic at any
tier.  `brix_webdav_auth required` (with `brix_webdav_token_jwks` / `_issuer` /
`_audience`), `brix_webdav_macaroon_secret`, `brix_webdav_checksum_on_write`
and `brix_webdav_tpc` are all `NGX_HTTP_LOC_CONF`, so nginx accepts them in any
location; all four write into `ngx_http_brix_webdav_loc_conf_t`
(`module_commands.c:221/287/354/433`), and no S3 translation unit references
that type or that module at all.  The operator writes "auth required" on an S3
export, gets no warning, and the export is authenticated by the access key
alone.  Every arm is fail-CLOSED rather than fail-open — the SigV4 gate still
runs — so the cost is not a bypass; it is that a configuration which reads as
defence in depth provides none of the second layer, and `brix_s3_token on`,
which would, is silently not what was written.

DEFECT CANDIDATE #37 (security, unusable control) — the XrdAcc principal on the
S3 plane is always empty, so per-access-key rules can never match.
`s3_acc_check()` takes the subject name from `brix_identity_dn_cstr(id)`
(`handler.c:87`, whose comment claims "S3 access key (or subject)"), but the
SigV4 verifier stores the key id with `brix_identity_set_subject(identity,
r->pool, comp->akid, BRIX_AUTHN_S3KEY)` (`auth_sigv4_verify.c:313`), and
`brix_identity_set_subject()` writes `id->subject` only — `id->dn` stays unset
(`identity.c:249-263`).  XrdAcc therefore authorizes every signed request as an
anonymous principal: the audit line reads `@<host> deny read "<path>"` with
nothing before the `@`.  `u * ...` rules work; `u <access-key> ...` rules are
dead text.  Fail-closed, and unusable as written: an operator restricting one
key to one prefix gets a deny-all export.

DEFECT CANDIDATE #38 (dead branch) — the INVARIANT 6 "both credentials present"
rejection cannot fire.  `s3_sigv4_bearer_intercept()` computes `has_bearer` and
`has_sigv4` from the *same* `get_header(r, "authorization")` value, so the
400 "both Bearer and SigV4 credentials present" needs one header string that
starts with both `Bearer ` and `AWS4` — no request can produce it.  The
reachable shape of that conflict is a presigned URL (whose credentials live in
the query string, `X-Amz-Signature` being the presence test,
`auth_sigv4_parse.c:301`) carrying a Bearer header: the bearer path wins and
the signature material is never looked at, so a request bearing two credentials
is served on one of them without comment.

NOT DEFECTS, PINNED AS FACTS.  The macaroon-mint POST and the TPC `COPY` are
refused on this plane (403 from the S3 auth gate, 405 from the S3 dispatcher) —
they are unreachable, not permissive.  And the dashboard's route table is
URI-absolute (`module_dispatch.c:76-85`), so its co-residency with S3 is
prefix-sensitive: at `/brix` it answers beside the S3 exports without inheriting
their signature gate; anywhere else it 404s.
"""

import os
import re
from pathlib import Path

import datetime as dt
import hashlib
import hmac
from urllib.parse import quote

import pytest
import requests

from server_registry import NginxInstanceSpec
from settings import HOST, NGINX_BIN
from utils.make_token import TokenIssuer

def _check_test_no_s3_translation_unit_can_reach_a_webdav_loc_conf_1(hits):
    assert hits == [], f"{DEFECT36} S3 now references the WebDAV conf at {hits}"


pytestmark = [pytest.mark.timeout(180),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15k-s3cores")]

ROOT = Path(__file__).resolve().parents[1]
S3_SRC = ROOT / "src" / "protocols" / "s3"

_needs_nginx = pytest.mark.skipif(
    not os.access(NGINX_BIN, os.X_OK), reason=f"nginx not executable: {NGINX_BIN}")

ACCESS_KEY = "AKIAAUDIT15K"
SECRET_KEY = "audit15k-secret-key"
REGION = "us-east-1"
ISSUER = "https://test.example.com"
AUDIENCE = "audit15k-s3"

# One bucket per location, and the two names are the same string on purpose:
# s3_parse_uri() reads the bucket out of the first URI segment.
ARMS = ("plain", "ro", "ro2", "wrong", "stok", "acc")
SEED = b"audit15k s3 co-residency seed\n"

# `keyed` exists only so the per-access-key rule below has something to point
# at; `pub` is the `u *` rule's prefix and `priv` is covered by no rule at all.
SUBDIRS = ("pub", "priv", "keyed")
AUTHDB = f"u {ACCESS_KEY} /acc/keyed rl\nu * /acc/pub rl\n"

DEFECT36 = (
    "DEFECT CANDIDATE #36 has been FIXED: a brix_webdav_* security directive "
    "now does something inside an S3 location (or is refused there). Flip this "
    "expectation and test the enforcement, not the silence.")
DEFECT37 = (
    "DEFECT CANDIDATE #37 has been FIXED: the XrdAcc tier now sees the SigV4 "
    "access key as its principal. Flip this expectation — a per-key `u <key>` "
    "rule should grant, and the audit line should name the key.")
DEFECT38 = (
    "DEFECT CANDIDATE #38 has been FIXED: presenting a bearer and presigned "
    "SigV4 credentials on one request is now rejected. Flip this expectation "
    "to the 400 'both Bearer and SigV4 credentials present'.")


# --------------------------------------------------------------------------- #
# The block.                                                                   #
# --------------------------------------------------------------------------- #

@pytest.fixture()
def s3cores(lifecycle, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    for arm in ARMS:
        for sub in SUBDIRS:
            (data / arm / sub).mkdir(parents=True)
            (data / arm / sub / "seed.txt").write_bytes(SEED)
    tmp = tmp_path / "ngxtmp"
    tmp.mkdir()

    authdb = tmp_path / "authdb"
    authdb.write_text(AUTHDB, encoding="utf-8")

    issuer = TokenIssuer(str(tmp_path / "tokens"), issuer=ISSUER,
                         audience=AUDIENCE)
    issuer.init_keys()

    endpoint = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15k-s3cores",
        template="nginx_audit15k_s3cores.conf",
        protocol="s3",
        data_root=str(data),
        template_values={"ACCESS_KEY": ACCESS_KEY,
                         "SECRET_KEY": SECRET_KEY,
                         "REGION": REGION,
                         "JWKS": issuer.jwks_path,
                         "ISSUER": ISSUER,
                         "AUDIENCE": AUDIENCE,
                         "AUTHDB": str(authdb),
                         "TMP_DIR": str(tmp)},
        reason="audit-15k: the S3 security options in one server block"))
    return endpoint, issuer, data


# --------------------------------------------------------------------------- #
# Client-side SigV4, byte-identical to the server's canonicalization.          #
# (auth_sigv4_verify_crypto.c: SignedHeaders=host;x-amz-date and the literal    #
# UNSIGNED-PAYLOAD as the hashed-payload line.)                                 #
# --------------------------------------------------------------------------- #

def _signing_key(secret, date):
    k = hmac.new(f"AWS4{secret}".encode(), date.encode(), hashlib.sha256).digest()
    for part in (REGION.encode(), b"s3", b"aws4_request"):
        k = hmac.new(k, part, hashlib.sha256).digest()
    return k


def _sign(endpoint, method, path, *, access_key=ACCESS_KEY,
          secret_key=SECRET_KEY):
    now = dt.datetime.now(dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    canonical = (f"{method}\n"
                 f"{quote(path, safe='/-_.~')}\n"
                 "\n"
                 f"host:{HOST}:{endpoint.port}\n"
                 f"x-amz-date:{amz_date}\n"
                 "\n"
                 "host;x-amz-date\n"
                 "UNSIGNED-PAYLOAD")
    sts = ("AWS4-HMAC-SHA256\n"
           f"{amz_date}\n"
           f"{date}/{REGION}/s3/aws4_request\n"
           f"{hashlib.sha256(canonical.encode()).hexdigest()}")
    sig = hmac.new(_signing_key(secret_key, date), sts.encode(),
                   hashlib.sha256).hexdigest()
    return {"x-amz-date": amz_date,
            "Authorization": (
                "AWS4-HMAC-SHA256 "
                f"Credential={access_key}/{date}/{REGION}/s3/aws4_request, "
                "SignedHeaders=host;x-amz-date, "
                f"Signature={sig}")}


def _url(endpoint, path):
    return f"http://{HOST}:{endpoint.port}{path}"


def _signed(endpoint, method, path, **kwargs):
    return requests.request(method, _url(endpoint, path),
                            headers=_sign(endpoint, method, path),
                            timeout=30, **kwargs)


def _bearer(endpoint, method, path, token, **kwargs):
    return requests.request(method, _url(endpoint, path),
                            headers={"Authorization": f"Bearer {token}"},
                            timeout=30, **kwargs)


def _code(resp):
    """The <Code> of an S3 XML error, or None when the body is not S3 XML."""
    m = re.search(r"<Code>([^<]+)</Code>", resp.text)
    return m.group(1) if m else None


def _errlog(endpoint):
    """Instance logs are wiped at teardown, so failures quote them inline."""
    try:
        with open(os.path.join(endpoint.prefix, "logs", "error.log")) as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


def _authz_lines(endpoint):
    return [ln for ln in _errlog(endpoint).splitlines() if "xrootd authz:" in ln]


# --------------------------------------------------------------------------- #
# The control arm.  Every refusal below is measured against these four.        #
# --------------------------------------------------------------------------- #

class TestTheControlArm:

    def test_a_signed_get_is_served(self, s3cores):
        endpoint = s3cores[0]
        resp = _signed(endpoint, "GET", "/plain/pub/seed.txt")
        assert resp.status_code == 200, resp.text[:300]
        assert resp.content == SEED

    def test_an_unsigned_get_is_refused(self, s3cores):
        """The gate that is always on: no credentials, no object."""
        endpoint = s3cores[0]
        resp = requests.get(_url(endpoint, "/plain/pub/seed.txt"), timeout=30)
        assert resp.status_code == 403, resp.text[:300]
        assert _code(resp) == "InvalidRequest", resp.text[:300]

    def test_a_wlcg_bearer_is_not_an_s3_credential(self, s3cores):
        """INVARIANT 6, the direction that matters on an export with no token
        tier configured: a perfectly valid WLCG token is not a signature."""
        endpoint, issuer, _ = s3cores
        resp = _bearer(endpoint, "GET", "/plain/pub/seed.txt",
                       issuer.generate(scope="storage.read:/"))
        assert resp.status_code == 403, resp.text[:300]

    def test_signed_writes_succeed_where_writing_is_allowed(self, s3cores):
        endpoint = s3cores[0]
        put = _signed(endpoint, "PUT", "/plain/pub/new.txt", data=b"written\n")
        assert put.status_code == 200, put.text[:300]
        delete = _signed(endpoint, "DELETE", "/plain/pub/seed.txt")
        assert delete.status_code == 204, delete.text[:300]


# --------------------------------------------------------------------------- #
# sec:readonly × proto:s3 and auth:s3sigv4 × sec:readonly — 1 file, 0 blocks.  #
# --------------------------------------------------------------------------- #

class TestReadOnlyOnTheS3Plane:

    @pytest.mark.parametrize("arm", ["ro", "ro2"])
    def test_read_only_refuses_a_signed_put(self, s3cores, arm):
        endpoint = s3cores[0]
        resp = _signed(endpoint, "PUT", f"/{arm}/pub/new.txt", data=b"x")
        assert resp.status_code == 403, resp.text[:300]
        assert _code(resp) == "AccessDenied", resp.text[:300]
        assert "Write access is disabled" in resp.text, resp.text[:300]

    @pytest.mark.parametrize("arm", ["ro", "ro2"])
    def test_read_only_refuses_a_signed_delete(self, s3cores, arm):
        endpoint = s3cores[0]
        resp = _signed(endpoint, "DELETE", f"/{arm}/pub/seed.txt")
        assert resp.status_code == 403, resp.text[:300]
        assert _code(resp) == "AccessDenied", resp.text[:300]
        assert (s3cores[2] / arm / "pub" / "seed.txt").exists(), \
            "the refused DELETE removed the object anyway"

    @pytest.mark.parametrize("arm", ["ro", "ro2"])
    def test_read_only_still_serves_reads(self, s3cores, arm):
        endpoint = s3cores[0]
        resp = _signed(endpoint, "GET", f"/{arm}/pub/seed.txt")
        assert resp.status_code == 200 and resp.content == SEED, resp.text[:300]

    def test_the_verdict_does_not_depend_on_directive_order(self, s3cores):
        """/ro/ writes brix_read_only AFTER brix_allow_write, /ro2/ before it.
        A merge-order dependency here would be a security bug that reads as a
        typo, so the two arms are compared directly rather than separately."""
        endpoint = s3cores[0]
        first = _signed(endpoint, "PUT", "/ro/pub/new.txt", data=b"x")
        second = _signed(endpoint, "PUT", "/ro2/pub/new.txt", data=b"x")
        assert (first.status_code, _code(first)) == \
               (second.status_code, _code(second)), \
            f"{first.status_code}/{_code(first)} vs " \
            f"{second.status_code}/{_code(second)}"

    def test_read_only_is_applied_after_the_whole_merge(self):
        """The source reason order cannot matter: the flag is forced down at
        the end of the shared merge, not where the directive was parsed."""
        hdr = (ROOT / "src" / "core" / "config" / "shared_conf.h").read_text(
            encoding="utf-8")
        m = re.search(r"brix_shared_apply_read_only\(\s*ngx_http.*?\n\}", hdr,
                      re.S)
        assert m, "brix_shared_apply_read_only is no longer defined here"
        assert "allow_write = 0" in m.group(0), \
            f"it no longer clears allow_write: {m.group(0)}"

    def test_every_s3_write_path_consults_allow_write(self):
        """The four gate sites the arms above are actually exercising."""
        sites = []
        for name in ("handler_object_route.c", "handler.c"):
            text = (S3_SRC / name).read_text(encoding="utf-8")
            sites += [f"{name}:{i}" for i, line in
                      enumerate(text.splitlines(), 1)
                      if "common.allow_write" in line]
        assert len(sites) >= 4, \
            f"the S3 write gate lost a site — found only {sites}"


# --------------------------------------------------------------------------- #
# DEFECT #36 — auth:token × proto:s3 (11 files, 0 blocks), auth:macaroon ×     #
# proto:s3 (3), auth:macaroon × auth:s3sigv4 (1), proto:s3 × store:cksum_w     #
# (1), auth:s3sigv4 × store:cksum_w (1).                                       #
# --------------------------------------------------------------------------- #

class TestWebdavDirectivesAreInertInAnS3Location:

    def test_token_required_does_not_require_a_token(self, s3cores):
        """`brix_webdav_auth required` + a JWKS + an issuer + an audience, and
        a request carrying none of it is served."""
        endpoint = s3cores[0]
        resp = _signed(endpoint, "GET", "/wrong/pub/seed.txt")
        assert resp.status_code == 200 and resp.content == SEED, \
            f"{DEFECT36} (GET -> {resp.status_code})"

    def test_token_required_does_not_gate_writes_either(self, s3cores):
        endpoint = s3cores[0]
        resp = _signed(endpoint, "PUT", "/wrong/pub/new.txt", data=b"written\n")
        assert resp.status_code == 200, f"{DEFECT36} (PUT -> {resp.status_code})"

    def test_the_arm_is_not_more_permissive_than_the_control(self, s3cores):
        """The inertness is fail-CLOSED: the S3 gate still runs, so a bearer
        alone is refused here exactly as on /plain/.  Without this the finding
        above would read as a bypass, which it is not."""
        endpoint, issuer, _ = s3cores
        resp = _bearer(endpoint, "GET", "/wrong/pub/seed.txt",
                       issuer.generate(scope="storage.read:/"))
        assert resp.status_code == 403, resp.text[:300]

    def test_macaroon_minting_is_unreachable_here(self, s3cores):
        """`brix_webdav_macaroon_secret` is configured; the mint POST never
        reaches a macaroon handler because the S3 auth gate answers first."""
        endpoint = s3cores[0]
        resp = requests.post(
            _url(endpoint, "/wrong/pub/seed.txt"),
            headers={"Content-Type": "application/macaroon-request"},
            data="{}", timeout=30)
        assert resp.status_code == 403, resp.text[:300]
        assert _code(resp) == "InvalidRequest", resp.text[:300]
        assert "macaroon" not in resp.text.lower(), resp.text[:300]

    def test_webdav_tpc_copy_is_not_dispatched(self, s3cores):
        """`brix_webdav_tpc on` + allow_local + allow_private, and a signed
        COPY is simply a method the S3 dispatcher does not implement."""
        endpoint = s3cores[0]
        resp = requests.request(
            "COPY", _url(endpoint, "/wrong/pub/copy.txt"),
            headers=dict(_sign(endpoint, "COPY", "/wrong/pub/copy.txt"),
                         Source=_url(endpoint, "/wrong/pub/seed.txt")),
            timeout=30)
        assert resp.status_code == 405, resp.text[:300]
        assert not (s3cores[2] / "wrong" / "pub" / "copy.txt").exists()

    def test_checksum_on_write_algorithm_is_ignored(self, s3cores):
        """`brix_webdav_checksum_on_write adler32` in the location, and the
        object lands with the S3 plane's own default digest instead
        (checksum.c:46/55, crc64nvme) — the same one /plain/ writes with no
        checksum directive at all."""
        endpoint, _, data = s3cores
        assert _signed(endpoint, "PUT", "/wrong/pub/ck.txt",
                       data=b"written\n").status_code == 200
        assert _signed(endpoint, "PUT", "/plain/pub/ck.txt",
                       data=b"written\n").status_code == 200
        configured = os.listxattr(str(data / "wrong" / "pub" / "ck.txt"))
        control = os.listxattr(str(data / "plain" / "pub" / "ck.txt"))
        assert not any("adler32" in x for x in configured), \
            f"{DEFECT36} (xattrs {configured})"
        assert configured == control, \
            f"{DEFECT36} (configured {configured} vs control {control})"

    def test_no_s3_translation_unit_can_reach_a_webdav_loc_conf(self):
        """The structural reason all four are inert, pinned so a future reader
        of `ngx_http_brix_webdav_loc_conf_t` inside src/protocols/s3/ has to
        come back here and re-measure the arms above."""
        hits = []
        for path in sorted(S3_SRC.rglob("*")):
            if path.suffix not in (".c", ".h") or not path.is_file():
                continue
            for i, line in enumerate(
                    path.read_text(encoding="utf-8").splitlines(), 1):
                if ("webdav_loc_conf_t" in line
                        or "ngx_http_brix_webdav_module" in line):
                    hits.append(f"{path.relative_to(ROOT)}:{i}")
        _check_test_no_s3_translation_unit_can_reach_a_webdav_loc_conf_1(hits)

    @pytest.mark.parametrize("directive,field", [
        ("brix_webdav_auth", "auth"),
        ("brix_webdav_tpc", "tpc"),
        ("brix_webdav_macaroon_secret", "token_macaroon_secret"),
        ("brix_webdav_checksum_on_write", "checksum_on_write"),
    ])
    def test_each_inert_directive_writes_only_the_webdav_conf(self, directive,
                                                              field):
        """Where the operator's value actually goes: a struct the S3 handler
        never obtains.  Anchored on the ngx_command_t initializer so a rename
        fails loudly instead of silently passing."""
        text = (ROOT / "src" / "protocols" / "webdav"
                / "module_commands.c").read_text(encoding="utf-8")
        m = re.search(r'\{\s*ngx_string\("' + re.escape(directive)
                      + r'"\)(.{0,400}?)\},', text, re.S)
        assert m, f"{directive} is no longer declared in module_commands.c"
        assert f"ngx_http_brix_webdav_loc_conf_t, {field}" in m.group(1), \
            f"{directive} no longer writes webdav_loc_conf.{field}: {m.group(1)}"


# --------------------------------------------------------------------------- #
# The gate this plane does have — auth:token × proto:s3, done with the right   #
# directive, in the same block as the SigV4 keys (INVARIANT 6).                #
# --------------------------------------------------------------------------- #

class TestTheS3TokenGate:

    def test_a_valid_bearer_is_accepted(self, s3cores):
        endpoint, issuer, _ = s3cores
        resp = _bearer(endpoint, "GET", "/stok/pub/seed.txt",
                       issuer.generate(scope="storage.read:/"))
        assert resp.status_code == 200 and resp.content == SEED, resp.text[:300]

    def test_a_wrong_audience_bearer_is_refused(self, s3cores):
        endpoint, issuer, _ = s3cores
        resp = _bearer(endpoint, "GET", "/stok/pub/seed.txt",
                       issuer.generate(scope="storage.read:/",
                                       audience="somewhere-else.example"))
        assert resp.status_code == 403, resp.text[:300]
        assert _code(resp) == "AccessDenied", resp.text[:300]
        assert "bearer token validation failed" in resp.text, resp.text[:300]

    def test_a_scope_narrower_than_the_key_is_refused(self, s3cores):
        """The scope is matched against the KEY, not the URI: the bucket
        segment is parsed off first (s3_check_token_scope builds "/<key>")."""
        endpoint, issuer, _ = s3cores
        token = issuer.generate(scope="storage.read:/pub")
        assert _bearer(endpoint, "GET", "/stok/pub/seed.txt",
                       token).status_code == 200
        resp = _bearer(endpoint, "GET", "/stok/priv/seed.txt", token)
        assert resp.status_code == 403, resp.text[:300]
        assert "token scope does not cover this object" in resp.text, \
            resp.text[:300]

    def test_a_read_scope_cannot_write(self, s3cores):
        endpoint, issuer, _ = s3cores
        resp = _bearer(endpoint, "PUT", "/stok/pub/new.txt",
                       issuer.generate(scope="storage.read:/"), data=b"x")
        assert resp.status_code == 403, resp.text[:300]
        assert "token scope does not cover this object" in resp.text, \
            resp.text[:300]

    def test_sigv4_still_works_beside_the_token_gate(self, s3cores):
        """INVARIANT 6 as co-residency rather than exclusion: one location, two
        credential types, each verified by its own tier."""
        endpoint = s3cores[0]
        resp = _signed(endpoint, "GET", "/stok/pub/seed.txt")
        assert resp.status_code == 200 and resp.content == SEED, resp.text[:300]

    def test_no_credentials_at_all_is_refused(self, s3cores):
        endpoint = s3cores[0]
        resp = requests.get(_url(endpoint, "/stok/pub/seed.txt"), timeout=30)
        assert resp.status_code == 403, resp.text[:300]
        assert "bearer token required" in resp.text, resp.text[:300]

    def test_presigned_credentials_are_ignored_when_a_bearer_is_present(
            self, s3cores):
        """DEFECT #38.  X-Amz-Signature is the presigned presence test, and
        this one is nonsense — yet the request is served on the bearer without
        the signature material being examined or the conflict reported."""
        endpoint, issuer, _ = s3cores
        token = issuer.generate(scope="storage.read:/")
        resp = requests.get(
            _url(endpoint, "/stok/pub/seed.txt"),
            params={"X-Amz-Algorithm": "AWS4-HMAC-SHA256",
                    "X-Amz-Credential":
                        f"{ACCESS_KEY}/20260816/{REGION}/s3/aws4_request",
                    "X-Amz-Date": "20260816T000000Z",
                    "X-Amz-SignedHeaders": "host",
                    "X-Amz-Signature": "00" * 32},
            headers={"Authorization": f"Bearer {token}"}, timeout=30)
        assert resp.status_code == 200, f"{DEFECT38} ({resp.status_code})"
        assert resp.content == SEED, f"{DEFECT38} ({resp.text[:200]})"

    def test_the_both_credentials_branch_reads_a_single_header(self):
        """DEFECT #38, structurally: both predicates come from one
        `get_header(r, "authorization")` value, so their conjunction is
        unsatisfiable and the 400 below it is unreachable."""
        text = (S3_SRC / "auth_sigv4_verify.c").read_text(encoding="utf-8")
        body = text.split("s3_sigv4_bearer_intercept(", 1)[1].split("\n}", 1)[0]
        assert 'get_header(r, "authorization")' in body, body[:400]
        assert "has_bearer && has_sigv4" in body, \
            f"{DEFECT38} the conjunction is gone from the intercept"
        assert body.count('get_header(r, "authorization")') == 1, \
            f"{DEFECT38} the intercept now reads more than one header source"
        bearer = (S3_SRC / "auth_bearer.c").read_text(encoding="utf-8")
        assert 'get_header(r, "authorization")' in bearer, \
            f"{DEFECT38} s3_bearer_present no longer reads the same header"


# --------------------------------------------------------------------------- #
# DEFECT #37 — auth:authdb × proto:s3.  Not one of the 24 once inheritance is  #
# modelled (a conf declares brix_authdb above an S3 server), which is exactly  #
# why the pair is worth a REQUEST and not a grep: co-resident in the merge and #
# never once exercised end to end.                                             #
# --------------------------------------------------------------------------- #

class TestXrdAccOverASigV4Principal:

    def test_a_star_rule_grants_read(self, s3cores):
        """`u * /acc/pub rl` — the rule shape that does work, and the control
        that keeps the per-key failure below from meaning "the tier is off"."""
        endpoint = s3cores[0]
        resp = _signed(endpoint, "GET", "/acc/pub/seed.txt")
        assert resp.status_code == 200 and resp.content == SEED, resp.text[:300]

    def test_a_path_no_rule_covers_is_denied(self, s3cores):
        endpoint = s3cores[0]
        resp = _signed(endpoint, "GET", "/acc/priv/seed.txt")
        assert resp.status_code == 403, resp.text[:300]

    def test_a_rule_without_w_denies_create(self, s3cores):
        """`rl` is read+lookup; the write privilege is a separate letter, and
        the S3 CREATE op is mapped through s3_method_aop()."""
        endpoint = s3cores[0]
        resp = _signed(endpoint, "PUT", "/acc/pub/new.txt", data=b"x")
        assert resp.status_code == 403, resp.text[:300]
        assert not (s3cores[2] / "acc" / "pub" / "new.txt").exists()

    def test_a_per_access_key_rule_never_matches(self, s3cores):
        """DEFECT #37.  The authdb grants `u AKIAAUDIT15K /acc/keyed rl`, the
        request is signed by exactly that key and verified — and the read is
        denied, because the name XrdAcc is given is the empty DN."""
        endpoint = s3cores[0]
        resp = _signed(endpoint, "GET", "/acc/keyed/seed.txt")
        assert resp.status_code == 403, f"{DEFECT37} ({resp.status_code})"

    def test_the_denial_is_attributed_to_an_empty_principal(self, s3cores):
        """The observable tell, and the thing an operator would file: the audit
        line names the host and nothing else where the access key should be."""
        endpoint = s3cores[0]
        _signed(endpoint, "GET", "/acc/keyed/seed.txt")
        lines = [ln for ln in _authz_lines(endpoint) if "/acc/keyed" in ln]
        def _assert_test_the_denial_is_attributed_to_an_empty_principal_1():
            assert lines, f"the xrdacc audit tier logged nothing: {_errlog(endpoint)[-2000:]}"
            assert all(ACCESS_KEY not in ln for ln in lines), \
                f"{DEFECT37} the audit line now names the key: {lines}"

        _assert_test_the_denial_is_attributed_to_an_empty_principal_1()
        assert any(re.search(r"xrootd authz: @\S+ deny ", ln) for ln in lines), \
            f"{DEFECT37} the principal is no longer empty: {lines}"

    def test_the_acc_tier_reads_the_dn_that_sigv4_never_writes(self):
        """DEFECT #37 at the seam: two files, two different identity slots."""
        handler = (S3_SRC / "handler.c").read_text(encoding="utf-8")
        acc = handler.split("s3_acc_check(ngx_http_request_t", 1)[1] \
                     .split("\n}", 1)[0]
        assert "brix_identity_dn_cstr(id)" in acc, \
            f"{DEFECT37} s3_acc_check no longer reads the DN"
        verify = (S3_SRC / "auth_sigv4_verify.c").read_text(encoding="utf-8")
        assert "brix_identity_set_subject(identity" in verify, \
            f"{DEFECT37} the SigV4 verifier no longer sets the subject"
        assert "brix_identity_set_dn" not in verify, \
            f"{DEFECT37} the SigV4 verifier now sets a DN too"
        identity = (ROOT / "src" / "core" / "types" / "identity.c").read_text(
            encoding="utf-8")
        setter = identity.split("brix_identity_set_subject(brix_identity_t", 1)[1] \
                         .split("\n}", 1)[0]
        assert "&id->subject" in setter and "id->dn" not in setter, \
            f"{DEFECT37} brix_identity_set_subject now touches the DN: {setter}"


# --------------------------------------------------------------------------- #
# proto:dashboard × xfer:tpc_webdav (3 files, 0 blocks) — and the dashboard    #
# beside six exports that all refuse unsigned requests, which is the half the  #
# matrix cannot score.                                                         #
# --------------------------------------------------------------------------- #

class TestDashboardCoresidentWithS3:

    def test_the_dashboard_answers_beside_the_s3_exports(self, s3cores):
        endpoint = s3cores[0]
        resp = requests.get(_url(endpoint, "/brix/api/v1/snapshot"), timeout=30)
        assert resp.status_code == 200, resp.text[:300]
        assert resp.json()["schema"] == "xrootd-dashboard.v1", resp.text[:300]

    def test_the_signature_gate_does_not_leak_into_the_dashboard(self, s3cores):
        """The pair's actual question: a server block whose other six locations
        all refuse unsigned requests must not make the dashboard refuse them —
        and must not make it accept a signature as a login either."""
        endpoint = s3cores[0]
        anon = requests.get(_url(endpoint, "/brix/api/v1/snapshot"), timeout=30)
        signed = _signed(endpoint, "GET", "/brix/api/v1/snapshot")
        assert anon.status_code == 200, anon.text[:300]
        assert signed.status_code == 200, signed.text[:300]
        assert "worker_pid" not in anon.json(), \
            "the anonymous snapshot is no longer PII-redacted"

    def test_s3_keeps_serving_after_a_dashboard_request(self, s3cores):
        endpoint = s3cores[0]
        assert requests.get(_url(endpoint, "/brix/api/v1/snapshot"),
                            timeout=30).status_code == 200
        resp = _signed(endpoint, "GET", "/plain/pub/seed.txt")
        assert resp.status_code == 200 and resp.content == SEED, resp.text[:300]

    def test_the_dashboard_route_table_is_uri_absolute(self):
        """Why the config mounts it at /brix and not next to the S3 prefixes:
        the routes are compared against the whole URI, so any other prefix
        yields a 404 that would look like a co-residency failure."""
        text = (ROOT / "src" / "observability" / "dashboard"
                / "module_dispatch.c").read_text(encoding="utf-8")
        routes = re.findall(r'DASH_MATCH_\w+,\s*"([^"]+)"', text)
        assert routes, "the dashboard route table moved"
        assert all(r.startswith("/brix") for r in routes), \
            f"a dashboard route is no longer /brix-absolute: {routes[:10]}"
