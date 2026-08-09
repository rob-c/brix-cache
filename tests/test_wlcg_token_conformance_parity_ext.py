from split_continuation import reexport as _reexport
_reexport(globals(), "_test_wlcg_token_conformance_parity_ext_helpers")

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
