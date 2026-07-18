"""WLCG token conformance — EXT family (extended cross-protocol matrix,
WebDAV 8446 + S3 9002).

WHAT: Verifies 35 RFC/WLCG rules — six families HDR, NDT, CLM2, SCP2, ALG2,
      WLCG2 plus five extras — uniformly across the two enforcing HTTP token
      ports.  Each case is parametrized over proto in ["webdav","s3"] producing
      70 tests in total.

WHY:  Extends test_wlcg_token_conformance_parity.py (20 PAR cases) with the
      full RFC 7515/7518/7519/8725 surface that was left to the extended matrix:
      crit header sub-rules, typ variants, NumericDate edge values, CLM ordering
      constraints, scope boundary/hierarchy rules, algorithm-security cases, and
      WLCG-profile specifics.  All cases are NEW — no overlap with PAR-01..20.

HOW:  Same probe() dispatcher and _forge() factory as the PAR suite.  Data files
      (/test.txt, /atlas/ok.txt, /cms/ok.txt) provisioned idempotently by
      _ensure_parity_data().

Divergences vs RFC asserted as xfail(strict=True) with rule cites:
  CLM2-02  iat_after_exp: rule 155 — iat>exp ordering not enforced by
           validate.c; token passes temporal checks (exp within 30 s skew,
           nbf in past, iat future-ordering unchecked) → server accepts.

Note: ES256 and multi-key cases are NOT included (HTTP ports are RSA-only,
      jwks.json = one RSA entry, kid test-key-1).  EC accept is confirmed on
      root:// multikey port 11250.
"""

import os
import sys

import pytest
import urllib3

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from settings import (
    NGINX_WEBDAV_TOKEN_PORT,
    NGINX_S3_TOKEN_PORT,
    S3_BUCKET,
    TEST_ROOT,
    TOKENS_DIR,
)
from tokenforge import TokenForge
from lib.tokenconf import (
    ensure_conformance_data,
    webdav_bearer,
    s3_bearer,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Data provisioning (same roots as PAR suite)
# ---------------------------------------------------------------------------

_EXT_FIXTURE_FILES = {
    "test.txt":     b"hello from nginx-xrootd\n",
    "atlas/ok.txt": b"atlasfile\n",
    "cms/ok.txt":   b"cmsfile\n",
}

_EXT_DATA_ROOTS = [
    os.path.join(TEST_ROOT, "data-webdav-token"),
    os.path.join(TEST_ROOT, "data-s3-token"),
]


def _ensure_parity_data():
    """Provision fixture files in both HTTP token server data roots.

    WHAT: Creates test.txt, atlas/ok.txt, cms/ok.txt in data-webdav-token and
          data-s3-token if absent.
    WHY:  Accept-path and scope-boundary tests must land on real files so that
          a token-acceptance decision is not confused with a 404 not-found.
    HOW:  Idempotent; skips existing files; creates parent directories.
    """
    for root in _EXT_DATA_ROOTS:
        for rel, body in _EXT_FIXTURE_FILES.items():
            path = os.path.join(root, rel)
            if os.path.exists(path):
                continue
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(body)


@pytest.fixture(autouse=True)
def _provision():
    """Idempotently provision all fixture data before every test in this module."""
    ensure_conformance_data()
    _ensure_parity_data()


# ---------------------------------------------------------------------------
# Shared forge factory and probe dispatcher (mirrors PAR suite exactly)
# ---------------------------------------------------------------------------

def _forge():
    """Return a TokenForge loaded from the fleet token directory."""
    return TokenForge(TOKENS_DIR)


def probe(proto, token, path="/test.txt", write=False):
    """Dispatch to the enforcing token port for the given protocol.

    WHAT: Routes to webdav_bearer (8446, HTTPS) or s3_bearer (9002, HTTP) with
          the enforcing port so both checks share one call site.
    WHY:  Centralises port selection; every parametrized body calls probe() and
          asserts verdict without knowing which protocol is under test.
    HOW:  proto="webdav" → webdav_bearer with NGINX_WEBDAV_TOKEN_PORT;
          proto="s3"     → s3_bearer with NGINX_S3_TOKEN_PORT; S3 URL layout is
          /{bucket}/{key} so the key is prefixed with S3_BUCKET ("testbucket").
          write flag is forwarded unchanged.

    Args:
        proto: "webdav" or "s3".
        token: JWT string.
        path:  URL path (must start with /).
        write: If True, issue a write (PUT) probe instead of a read (GET).

    Returns:
        "accept", "reject", or "notfound".
    """
    if proto == "webdav":
        return webdav_bearer(token, path, write, port=NGINX_WEBDAV_TOKEN_PORT)
    key = f"{S3_BUCKET}/{path.lstrip('/')}"
    return s3_bearer(token, key, write, port=NGINX_S3_TOKEN_PORT)


# ===========================================================================
# HDR family — RFC 7515 header parameter rules
# ===========================================================================

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_hdr_01_crit_empty_reject(proto):
    """HDR-01: crit=[] empty array → reject (RFC 7515 §4.1.11 / rule 37).

    WHAT: Header carries a crit member whose value is an empty JSON array.
    WHY:  RFC 7515 §4.1.11 / rule 37 — the crit array MUST NOT be empty;
          an empty array is a structural error that MUST cause rejection.
    HOW:  forge.crit_empty() inserts crit=[] signed by the main key.
    """
    tok = _forge().crit_empty()
    assert probe(proto, tok) == "reject"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_hdr_02_crit_non_array_reject(proto):
    """HDR-02: crit="exp" scalar string → reject (RFC 7515 §4.1.11 / rule 37).

    WHAT: Header carries crit as a plain string value rather than a JSON array.
    WHY:  RFC 7515 §4.1.11 — crit MUST be a JSON array; a scalar type violates
          the structural constraint → reject.
    """
    tok = _forge().crit_non_array()
    assert probe(proto, tok) == "reject"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_hdr_03_crit_lists_alg_reject(proto):
    """HDR-03: crit=["alg"] lists a registered JWS parameter → reject (rule 38).

    WHAT: Header carries crit=["alg"]; the "alg" parameter is already defined
          by the JWS/JWA registrations and MUST NOT appear in crit.
    WHY:  RFC 7515 §4.1.11 / rule 38 — crit MUST NOT list parameters whose
          semantics are already specified in the JWS/JWA registrations.  Listing
          "alg" is a protocol violation → reject.
    """
    tok = _forge().crit_lists_alg()
    assert probe(proto, tok) == "reject"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_hdr_04_crit_missing_name_reject(proto):
    """HDR-04: crit=["kid"] but kid absent from header → reject (rule 37).

    WHAT: The crit array names "kid" as a critical extension, but the header
          carries no "kid" member — the named parameter is absent.
    WHY:  RFC 7515 §4.1.11 / rule 37 — every name in crit MUST also appear
          as a header member; an absent critical parameter MUST cause rejection.
    """
    tok = _forge().crit_missing_name()
    assert probe(proto, tok) == "reject"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_hdr_05_x5c_injection_reject(proto):
    """HDR-05: x5c header with self-signed attacker cert, signed by attacker key → reject (SEC).

    WHAT: Header carries x5c=[<attacker-cert-DER-base64>]; the token is signed
          by the matching attacker private key (absent from jwks.json).
    WHY:  RFC 7515 §4.1.6 / rules 32/150 — the server MUST NOT trust key
          material from the x5c header; it verifies against its configured JWKS.
          The attacker key kid is absent from jwks.json → MUST reject.
    """
    tok = _forge().header_x5c_injection()
    assert probe(proto, tok) == "reject"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_hdr_06_jku_accept(proto):
    """HDR-06: jku header present, signed by main key → accept (jku ignored, rule 28).

    WHAT: Header carries jku="https://attacker.example.com/jwks.json"; the
          token is still RS256-signed by the main key (kid test-key-1).
    WHY:  RFC 7515 §4.1.2 / rule 28 — a conformant server MUST NOT fetch the
          jku URL; it verifies against its statically configured JWKS.  If jku
          is ignored (correct behavior), the main-key signature verifies → accept.
    """
    tok = _forge().header_jku()
    assert probe(proto, tok) == "accept"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_hdr_07_typ_at_jwt_accept(proto):
    """HDR-07: typ=at+jwt access-token type designator → accept (RFC 9068 / rule 75).

    WHAT: Header carries typ="at+jwt", the IANA media type for OAuth 2.0 access
          tokens (RFC 9068).  All other claims are valid.
    WHY:  A conformant validator must accept this type value equivalently to
          "JWT"; characterises whether at+jwt is treated as valid.
    """
    tok = _forge().typ_at_jwt()
    assert probe(proto, tok) == "accept"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_hdr_08_typ_missing_accept(proto):
    """HDR-08: typ claim absent from header entirely → accept (rule 70 characterize).

    WHAT: Header contains only alg and kid — no typ member.
    WHY:  RFC 8725 §2.9 / rule 70 — WLCG tokens typically carry typ=JWT; its
          absence is advisory.  Our implementation does not enforce typ presence
          → accept (same-issuer-same-key signature still verifies).
    """
    tok = _forge().typ_missing()
    assert probe(proto, tok) == "accept"


# ===========================================================================
# NDT family — RFC 7519 §2 NumericDate edge values
# ===========================================================================

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_ndt_01_numericdate_negative_accept(proto):
    """NDT-01: nbf=-1 negative NumericDate (before Unix epoch) → accept (rule 3).

    WHAT: The nbf claim is -1 — a negative integer representing a time before
          the Unix epoch; nbf is in the past so the token is immediately valid.
    WHY:  RFC 7519 §2 / rule 3 — NumericDate may be negative; the implementation
          must not overflow or refuse negative values.  nbf=-1 in the past → accept.
    """
    tok = _forge().numericdate_negative()
    assert probe(proto, tok) == "accept"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_ndt_02_numericdate_huge_accept(proto):
    """NDT-02: exp=99999999999999999999 huge integer far future → accept (rule 3).

    WHAT: The exp claim is an astronomically large integer (year ~3170+).
    WHY:  RFC 7519 §2 / rule 3 — NumericDate may be very large; the
          implementation must not overflow (e.g. truncate to int32/int64) in
          a way that treats a far-future expiry as expired.  validate.c
          json_get_int64 saturates at INT64_MAX which is still far future → accept.
    """
    tok = _forge().numericdate_huge()
    assert probe(proto, tok) == "accept"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_ndt_03_exp_null_reject(proto):
    """NDT-03: exp=null non-number type → reject (RFC 7519 §4.1.4 / rule 1).

    WHAT: The exp claim is JSON null — not a NumericDate.
    WHY:  RFC 7519 §4.1.4 / rule 1 — exp MUST be a NumericDate (integer or
          float); null fails json_get_int64 → exp=0 → treated as expired → reject.
    """
    tok = _forge().exp_null()
    assert probe(proto, tok) == "reject"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_ndt_04_temporal_within_skew_accept(proto):
    """NDT-04: exp=now-20 s, within default 30 s clock-skew window → accept.

    WHAT: Token expired 20 seconds ago — still within the brix_token_clock_skew
          tolerance of 30 s (the default for ports 8446 and 9002).
    WHY:  RFC 7519 §4.1.4 / WLCG tunables.h — the skew window allows small
          clock differences between token issuer and verifier.  A token expired
          within the window MUST be accepted; only tokens outside it are rejected.
          Complements NDT PAR-05 (temporal(-3600) → reject outside window).
    """
    tok = _forge().temporal(-20)
    assert probe(proto, tok) == "accept"


# ===========================================================================
# CLM2 family — RFC 7519 claim type and logical-ordering constraints
# ===========================================================================

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_clm2_01_iss_non_string_reject(proto):
    """CLM2-01: iss=12345 numeric value → reject (RFC 7519 §4.1.1 / rule 4).

    WHAT: The iss claim is an integer rather than a StringOrURI.
    WHY:  RFC 7519 §4.1.1 / rule 4 — the iss claim MUST be a StringOrURI;
          a numeric value violates the type constraint → parse failure → reject.
    """
    tok = _forge().iss_non_string()
    assert probe(proto, tok) == "reject"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "RFC 7519 rule 155: iat>exp ordering not enforced — "
        "exp=now-10 passes 30 s clock-skew, nbf=now-20 in past, "
        "iat=now+10 future-ordering check absent in validate.c → server accepts"
    ),
)
@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_clm2_02_iat_after_exp_reject(proto):
    """CLM2-02: iat > exp (issued after expiry) → RFC mandates reject (rule 155).

    WHAT: exp=now-10 (within 30 s skew → passes), nbf=now-20 (in past → passes),
          iat=now+10 (10 s in the future — logically impossible ordering).
    WHY:  Rule 155 — a token whose iat is after exp is logically contradictory
          and SHOULD be rejected.  Our implementation does NOT enforce iat/exp
          ordering; the token passes all three temporal checks → accepts.
    XFAIL: validate.c does not check iat>exp ordering; token is accepted.
           Marked xfail(strict) to track the known RFC divergence.
    """
    tok = _forge().iat_after_exp()
    assert probe(proto, tok) == "reject"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_clm2_03_nbf_after_exp_reject(proto):
    """CLM2-03: nbf=now+3600 far future not-before, exp=now+10 → reject (rule 155).

    WHAT: The token's not-before time is 1 hour in the future; the token can
          never be valid (nbf > exp).  validate.c checks `now < nbf → reject`.
    WHY:  RFC 7519 §4.1.5 / rule 155 — nbf in the far future means the token
          is not yet valid; since nbf has no skew tolerance in validate.c the
          server rejects immediately.
    """
    tok = _forge().nbf_after_exp()
    assert probe(proto, tok) == "reject"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_clm2_04_dup_claim_names_reject(proto):
    """CLM2-04: duplicate aud keys in payload JSON → reject (RFC 7159 §4 / rule 21).

    WHAT: Raw payload JSON contains two "aud" members: first "nginx-xrootd"
          then "evil".  The jansson parser uses the last value ("evil") → aud
          mismatch → reject.
    WHY:  RFC 7159 §4 / rule 21 — duplicate member names SHOULD be rejected;
          the last-wins jansson behaviour here yields a wrong audience → reject.
    """
    tok = _forge().dup_claim_names()
    assert probe(proto, tok) == "reject"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_clm2_05_missing_exp_reject(proto):
    """CLM2-05: exp claim absent → reject (RFC 7519 §4.1.4).

    WHAT: A structurally valid RS256 JWT with all standard claims except exp.
    WHY:  RFC 7519 §4.1.4 — exp is effectively REQUIRED by validate.c; when the
          key is absent json_get_int64 returns 0, treating exp=0 as expired
          (epoch) → now > 0+30 → reject.
    """
    tok = _forge().missing_exp()
    assert probe(proto, tok) == "reject"


# ===========================================================================
# SCP2 family — WLCG scope boundary, hierarchy, and operator rules
# ===========================================================================

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_scp2_01_segment_boundary_reject(proto):
    """SCP2-01: scope=storage.read:/atl, path=/atlas/ok.txt → reject (rule 117).

    WHAT: Scope prefix /atl is a string-prefix of /atlas but does NOT coincide
          with a directory boundary — /atlas does not live under /atl/.
    WHY:  WLCG Token Profile §4 / rule 117 — prefix matching must respect
          segment boundaries; /atl covers /atl and /atl/... but NOT /atlas.
          The scope check must reject this request.
    """
    tok = _forge().scope("storage.read:/atl")
    assert probe(proto, tok, path="/atlas/ok.txt") == "reject"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_scp2_02_stage_implies_read_accept(proto):
    """SCP2-02: scope=storage.stage:/atlas, GET /atlas/ok.txt → accept.

    WHAT: The token carries storage.stage:/atlas; the request is a read (GET).
    WHY:  WLCG Token Profile §4 — storage.stage grants staging (recall) and
          implies read permission; the scope engine in scopes.c maps
          storage.stage to the read permission set → accept.
    """
    tok = _forge().scope("storage.stage:/atlas")
    assert probe(proto, tok, path="/atlas/ok.txt") == "accept"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_scp2_03_storage_no_path_reject(proto):
    """SCP2-03: scope="storage.read" (no colon, no path) → reject (rule 112).

    WHAT: The scope string is "storage.read" — a storage action with no
          ':PATH' component at all (no colon separator).
    WHY:  WLCG Token Profile §4 / rule 112 — a storage scope MUST include a
          path component; the path-less form is malformed → reject.
          Distinct from the empty-path case SCP2-08 ("storage.read:" with colon).
    """
    tok = _forge().scope_storage_no_path()
    assert probe(proto, tok) == "reject"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_scp2_04_compute_scope_no_storage_reject(proto):
    """SCP2-04: scope="compute.read:/queue", GET /test.txt → reject (rule 118).

    WHAT: The token's only scope token is compute.read:/queue — a compute
          namespace scope with no storage grant.
    WHY:  WLCG Token Profile §4 / rule 118 — compute scopes apply to compute
          resources, not storage paths; the storage check finds no matching
          storage.* scope token → reject.
    """
    tok = _forge().scope_compute("read")
    assert probe(proto, tok, path="/test.txt") == "reject"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_scp2_05_scope_reordered_accept(proto):
    """SCP2-05: scope="storage.read:/atlas storage.write:/cms", GET /atlas/ok.txt → accept.

    WHAT: The scope string lists two tokens in order: read:/atlas then write:/cms.
          The GET request targets /atlas/ok.txt, which is covered by the first.
    WHY:  WLCG Token Profile §4 / rule 98 — multiple scope tokens are space-
          separated; order MUST NOT affect whether any individual token grants
          access.  The read grant is present regardless of its position → accept.
    """
    tok = _forge().scope_reordered("storage.read:/atlas", "storage.write:/cms")
    assert probe(proto, tok, path="/atlas/ok.txt") == "accept"


# ===========================================================================
# ALG2 family — RFC 7518 / RFC 8725 algorithm security (new cases)
# ===========================================================================

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_alg2_01_none_with_sig_reject(proto):
    """ALG2-01: alg=none header with non-empty signature segment → reject (rule 55 / SEC).

    WHAT: A three-segment JWT where the header declares alg=none but the third
          segment contains a non-empty bogus value (32 bytes of 0xDEADBEEF).
    WHY:  RFC 7518 §3.6 / rule 55 — alg=none tokens must have an empty signature
          segment; a non-empty segment is a protocol violation.  More broadly, any
          alg=none must be rejected by an asymmetric-only verifier.
    """
    tok = _forge().none_with_sig()
    assert probe(proto, tok) == "reject"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_alg2_02_alg_lowercase_reject(proto):
    """ALG2-02: alg="rs256" lowercase variant → reject (RFC 7515 §4.1.1 / rule 54).

    WHAT: A validly RS256-signed compact JWS whose header alg field is the
          lowercase string "rs256" instead of the canonical "RS256".
    WHY:  RFC 7515 §4.1.1 / rule 54 — alg comparison is case-sensitive and
          whitespace-exact; "rs256" MUST be treated as an unrecognised algorithm
          → reject.
    """
    tok = _forge().alg_variant("rs256")
    assert probe(proto, tok) == "reject"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_alg2_03_rs384_unsupported_reject(proto):
    """ALG2-03: alg=RS384, kid=test-key-1 → reject (RS384 not in {RS256, ES256}).

    WHAT: A valid RS384 token signed by the main RSA key; alg header = "RS384".
    WHY:  The enforcing ports only accept RS256 (and ES256 on the multikey port);
          RS384 is not in the allowed set → reject even though the key is present.
    """
    tok = _forge().rs384()
    assert probe(proto, tok) == "reject"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_alg2_04_ps256_unsupported_reject(proto):
    """ALG2-04: alg=PS256 (RSA-PSS SHA-256) → reject (PS256 not accepted).

    WHAT: A valid PS256 token signed by the main RSA key using PSS padding.
    WHY:  Our verifier uses PKCS#1v15 only; PSS-padded signatures are not
          accepted by the RS256 verification path → reject.
    """
    tok = _forge().ps256()
    assert probe(proto, tok) == "reject"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_alg2_05_weak_rsa_signed_reject(proto):
    """ALG2-05: RS256 signed with 1024-bit RSA key (kid=weak-rsa) → reject (rule 50 / SEC).

    WHAT: A syntactically valid RS256 JWT signed by a 1024-bit RSA key whose
          kid is "weak-rsa" — absent from jwks.json (which only contains
          test-key-1, a 2048-bit key).
    WHY:  RFC 8725 §2.2 / rule 50 — the minimum acceptable RSA key size is
          2048 bits.  More directly, "weak-rsa" is not in the server's JWKS →
          JWKS lookup fails → reject (key-not-found path, not key-size path).
    """
    tok = _forge().weak_rsa_signed()
    assert probe(proto, tok) == "reject"


# ===========================================================================
# WLCG2 family — WLCG Token Profile specific rules
# ===========================================================================

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_wlcg2_01_valid_root_scope_accept(proto):
    """WLCG2-01: valid RS256 token with storage.read:/ → accept (positive baseline).

    WHAT: A fully-formed RS256 JWT with storage.read:/ scope covering all paths.
    WHY:  Positive baseline for the EXT suite, mirroring PAR-01 but generated
          via generate() rather than forge._base_claims() directly.  If this
          fails the fleet is not up or the enforcing port is misconfigured.
    """
    tok = _forge().generate(scope="storage.read:/")
    assert probe(proto, tok) == "accept"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_wlcg2_02_wlcg_groups_accept(proto):
    """WLCG2-02: token with wlcg.groups=["/wlcg"] extra claim → accept (rule 119).

    WHAT: The token carries a wlcg.groups claim in addition to storage.read:/.
    WHY:  WLCG Token Profile §4 / rule 119 — wlcg.groups carries VO group
          membership; the claim is informational for capability-strategy issuers
          and MUST NOT cause rejection if present.  Storage scope is still
          granted by storage.read:/ → accept.
    """
    tok = _forge().wlcg_groups(["/wlcg"])
    assert probe(proto, tok) == "accept"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_wlcg2_03_modify_scope_read_denied_reject(proto):
    """WLCG2-03: scope=storage.modify:/atlas, GET /atlas/ok.txt → reject.

    WHAT: The token's only scope is storage.modify:/atlas; the request is a
          read (GET).
    WHY:  WLCG Token Profile §4 — storage.modify grants permission to modify
          (overwrite data within) an existing object; it does NOT grant read
          permission.  The scope engine must not conflate modify with read →
          no storage.read grant → reject.
    """
    tok = _forge().generate(scope="storage.modify:/atlas")
    assert probe(proto, tok, path="/atlas/ok.txt") == "reject"


# ===========================================================================
# Extra cases — genuine distinct rule checks to reach ~70 tests
# ===========================================================================

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_extra_01_wlcg_missing_ver_accept(proto):
    """EXTRA-01: wlcg.ver claim absent → accept (WLCG rule 101, advisory).

    WHAT: A fully-valid RS256 JWT from which the wlcg.ver claim has been removed.
    WHY:  WLCG Token Profile §2.1 / rule 101 — wlcg.ver is advisory; validate.c
          does not read or enforce the wlcg.ver claim → absence must not cause
          rejection → accept.
    """
    tok = _forge().wlcg_missing_ver()
    assert probe(proto, tok) == "accept"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_extra_02_aud_empty_array_reject(proto):
    """EXTRA-02: aud=[] empty JSON array → reject (RFC 7519 §4.1.3).

    WHAT: The aud claim is an empty JSON array — no audience entries at all.
    WHY:  RFC 7519 §4.1.3 — json_string_or_array_contains finds no element
          matching "nginx-xrootd" (the array is empty) → audience check fails
          → reject.  Distinct from PAR-07 (array with valid element → accept).
    """
    tok = _forge().aud_value([])
    assert probe(proto, tok) == "reject"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_extra_03_scope_empty_path_accept(proto):
    """EXTRA-03: scope="storage.read:" (colon, empty path) → accept (root scope).

    WHAT: The scope string is "storage.read:" — a storage.read action followed
          by a colon and an empty path component.
    WHY:  WLCG Token Profile §4 / scopes.c — an empty path after the colon
          defaults to the root scope "/" and therefore covers all paths including
          /test.txt → accept.  Distinct from EXTRA scope_storage_no_path
          ("storage.read" with NO colon, rule 112 → reject).
    """
    tok = _forge().scope("storage.read:")
    assert probe(proto, tok) == "accept"


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_extra_04_scope_unnormalized_reject(proto):
    """EXTRA-04: scope path contains /../ traversal → reject (rules 113/141).

    WHAT: scope="storage.read:/foo/../bar" — a scope path with an embedded
          dot-dot traversal.
    WHY:  WLCG Token Profile §4 / rules 113/141 — scope paths must be
          normalized; a path containing '..' components is either malformed
          or a traversal attempt → reject.
    """
    tok = _forge().scope_unnormalized()
    assert probe(proto, tok) == "reject"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "RFC 7519 §4.1.2 rules 4/6: sub type not enforced — "
        "validate.c reads sub via json_string (returns NULL for array) but does "
        "not reject on NULL sub; remaining claims pass → server accepts"
    ),
)
@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_extra_05_sub_non_string_reject(proto):
    """EXTRA-05: sub=["a","b"] array value → RFC mandates reject (rules 4/6).

    WHAT: The sub claim is a JSON array rather than a StringOrURI scalar.
    WHY:  RFC 7519 §4.1.2 / rules 4/6 — the sub claim MUST be a StringOrURI;
          an array value violates the type constraint.  Our implementation reads
          sub via json_string() (which returns NULL for a non-string) but does not
          enforce a non-NULL sub → remaining claims all pass → server accepts.
    XFAIL: sub type not enforced; uniform across webdav and s3.
    """
    tok = _forge().sub_non_string()
    assert probe(proto, tok) == "reject"
