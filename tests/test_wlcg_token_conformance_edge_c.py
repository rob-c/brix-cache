from split_continuation import reexport as _reexport
_reexport(globals(), "_test_wlcg_token_conformance_edge_helpers")

@pytest.mark.tokenconf
def test_d08_wlcg_ver_integer_type_accept():
    """wlcg.ver=1 (integer, not string) → accept.

    WHY:  Rule 101 specifies wlcg.ver as a string "1.0".  An integer 1 is a
          type mismatch.  Our implementation ignores wlcg.ver (unknown claim)
          so the type mismatch is also ignored → accept.
    CHARACTERISE: confirms that wlcg.ver type enforcement is absent.
    """
    tok = _f().wlcg_ver(1)
    assert root_ztn(tok, "/test.txt", port=PORT) == "accept"


# ---------------------------------------------------------------------------
# Group E — KID-EDGE: Key-selection edge cases across ports
#
# Existing SIG-multikey family (test_wlcg_token_conformance_signature_multikey)
# covers on 11250: kid=test-key-2 accept, kid=does-not-exist reject,
# no-kid key2 accept, ES256 accept, ES256 bad-sig reject.
# These cases fill: main key on multikey port, RSA-kid names EC-key (mismatch),
# key2-signed token on main RSA-only port, no-kid-key2 on main port,
# ES256 on RSA-only ports (main and strict), key2 on strict port.
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
def test_e01_main_key_on_multikey_port_accept():
    """generate() kid=test-key-1 on multikey port (11250) → accept.

    WHY:  The multikey JWKS contains test-key-1 as its first entry.  A token
          signed by the main key (DEFAULT_KID=test-key-1) must still be accepted
          on the multikey port — adding extra keys must not break existing tokens.
    """
    tok = _f().generate()
    assert root_ztn(tok, "/test.txt", port=MK) == "accept"


@pytest.mark.tokenconf
def test_e02_kid_names_ec_key_rsa_sig_reject():
    """kid=ec-key-1 but RSA-signed (wrong_kid_multikey("ec-key-1")) → reject.

    WHY:  The multikey JWKS resolves kid=ec-key-1 to a P-256 EC public key.
          The token is RS256-signed by the main RSA private key.  Verifying an
          RSA signature against an EC public key must fail → reject.
          Confirms that the verifier uses the key matched by kid, not any key.
    """
    tok = _f().wrong_kid_multikey("ec-key-1")
    assert root_ztn(tok, "/test.txt", port=MK) == "reject"


@pytest.mark.tokenconf
def test_e03_key2_signed_on_rsa_only_port_reject():
    """signed_by_key2() on main RSA-only port (11097) → reject.

    WHY:  Port 11097 uses jwks.json which contains only test-key-1.  A token
          signed by test-key-2 (absent from this JWKS) must be rejected.
          kid=test-key-2 → JWKS lookup fails → no key to verify against → reject.
    """
    tok = _f().signed_by_key2()
    assert root_ztn(tok, "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_e04_no_kid_key2_on_rsa_only_port_reject():
    """no_kid_key2() on main RSA-only port (11097) → reject.

    WHY:  no_kid_key2() is signed by test-key-2 with no kid in the header.
          The verifier tries all keys in the JWKS (rotation fallback); jwks.json
          has only test-key-1.  test-key-1 cannot verify a signature made with
          test-key-2 → all keys tried → verification fails → reject.
    """
    tok = _f().no_kid_key2()
    assert root_ztn(tok, "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_e05_es256_on_rsa_only_main_port_reject():
    """es256() (kid=ec-key-1) on main RSA-only port (11097) → reject.

    WHY:  Port 11097 uses jwks.json which contains only test-key-1 (RSA).
          kid=ec-key-1 is absent from this JWKS → key lookup fails → reject.
          Complements PAR-19 (ES256 rejected on WebDAV/S3 HTTP ports); this
          confirms the same behaviour on the root:// main token port.
    """
    tok = _f().es256()
    assert root_ztn(tok, "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_e06_es256_on_strict_port_reject():
    """es256() (kid=ec-key-1) on strict port (11119) → reject.

    WHY:  Port 11119 also uses an RSA-only JWKS (same as 11097 with skew=0).
          kid=ec-key-1 is absent → reject.  Confirms that the strict port's
          key-lookup behaviour is identical to the main port.
    """
    tok = _f().es256()
    assert root_ztn(tok, "/test.txt", port=STRICT) == "reject"


@pytest.mark.tokenconf
def test_e07_key2_signed_on_strict_port_reject():
    """signed_by_key2() on strict port (11119) → reject.

    WHY:  Port 11119 uses the same RSA-only JWKS as 11097.  test-key-2 is
          absent; the token must be rejected for the same reason as E03.
          Confirms strict port JWKS is not accidentally extended.
    """
    tok = _f().signed_by_key2()
    assert root_ztn(tok, "/test.txt", port=STRICT) == "reject"


# ---------------------------------------------------------------------------
# D-5 — asserted kid is authoritative even with a single loaded key.
#
# The former single-key leniency (unmatched kid → use the sole JWKS key anyway)
# meant an asserted kid that named no loaded key still authenticated as long as
# the signature happened to verify under the one key.  Port 11097's JWKS holds
# exactly test-key-1, which is also the forge's default signing key, so the same
# valid signature reaches the verifier in all three cases below — only the kid
# header differs.  The exact-match kid must accept; any other asserted kid must
# now reject.  (The kid-*absent* multi-key trial — rotation grace — is unchanged
# and is exercised by E04/no_kid_key2.)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
def test_e08_matching_kid_single_key_accept():
    """kid=test-key-1 (the sole loaded key), RSA-signed, on 11097 → accept.

    WHY:  An asserted kid that exactly names the one configured JWKS key is the
          spec-correct path (RFC 7515 §4.1.4); hardening the single-key case
          must not disturb it.  wrong_kid() signs with the default key and lets
          us set the kid explicitly, so asserting the real kid is a pure
          exact-match accept — the success anchor for the D-5 change.
    """
    tok = _f().wrong_kid("test-key-1")
    assert root_ztn(tok, "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_e09_unmatched_kid_single_key_reject():
    """kid=does-not-exist, RSA-signed by the sole key, on 11097 → reject.

    WHY:  This is the D-5 behaviour change.  Before, the single-key fallback
          used test-key-1 despite the asserted kid matching nothing, so this
          validly-signed token was accepted; the asserted kid was therefore not
          authoritative.  Now an asserted kid that names no loaded key is a hard
          reject even though the signature would verify under the only key.
    """
    tok = _f().wrong_kid("does-not-exist")
    assert root_ztn(tok, "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_e10_traversal_shaped_kid_single_key_reject():
    """kid="../../../../etc/passwd", RSA-signed, on 11097 → reject.

    WHY:  Security-negative for D-5: an attacker who asserts a bogus, path-like
          kid must not slip through on the single-key fallback.  The kid is
          in-memory JWKS array lookup only (never a filesystem path — see
          test_malicious_credentials.test_kid_path_traversal_not_used_as_path);
          here we additionally require that it is rejected, not silently
          accepted under the retired leniency.
    """
    tok = _f().wrong_kid("../../../../etc/passwd")
    assert root_ztn(tok, "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_e08_valid_token_multikey_port_root_scope_accept():
    """Valid RS256 token, scope=storage.read:/, GET /test.txt on 11250 → accept.

    WHY:  Sanity regression for the multikey port with the standard root scope.
          Confirms that the multikey JWKS setup (extra keys added) does not
          interfere with normal token acceptance for the main key.
          Uses /test.txt which is provisioned in all port data roots.
    """
    tok = _f().generate()
    assert root_ztn(tok, "/test.txt", port=MK) == "accept"


@pytest.mark.tokenconf
def test_e09_key2_signed_root_scope_multikey_accept():
    """signed_by_key2() with default scope=storage.read:/, GET /test.txt on 11250 → accept.

    WHY:  Confirms that key2's acceptance on the multikey port extends to
          a full auth+authz round-trip: a token signed by test-key-2 with
          storage.read:/ scope must grant read access to /test.txt.
          Tests auth (kid=test-key-2 in multikey JWKS) AND authz (scope covers
          path) together.  Uses /test.txt which is in all port data roots.
    """
    tok = _f().signed_by_key2()
    assert root_ztn(tok, "/test.txt", port=MK) == "accept"


# ---------------------------------------------------------------------------
# Group F — REG-EDGE: Issuer-registry base_path × scope interactions
#
# Existing ISS family covers: atlas in-base (ISS-01), atlas out-of-base (ISS-02),
# cms in-base (ISS-03), cms out-of-base (ISS-04), unknown issuer (ISS-05),
# atlas at root /test.txt (ISS-06).
# These cases fill: traversal rejection, trailing-slash issuer mismatch,
# base-OK-but-scope-fails interactions, exact-file scope within base,
# cms exact-file scope, cross-issuer scope attempt.
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
def test_f01_traversal_rejected_before_base_path():
    """atlas token, path=/atlas/../cms/ok.txt → reject (traversal defense).

    WHY:  §3.5 traversal defense — brix_reject_dotdot_path() rejects any path
          containing ".." components before the base_path or scope check.
          This confirms the registry port also applies the traversal guard.
    """
    tok = _f().for_issuer("https://atlas.example.com")
    assert root_ztn(tok, "/atlas/../cms/ok.txt", port=REG) == "reject"


@pytest.mark.tokenconf
def test_f02_trailing_slash_issuer_registry_reject():
    """iss="https://atlas.example.com/" (trailing slash) on registry port → reject.

    WHY:  Rule 130 — issuer comparison in the registry is an exact string match.
          The scitokens.cfg entry is "https://atlas.example.com" (no slash).
          "https://atlas.example.com/" does not match → no issuer entry found
          → reject.  Tests the same rule as D04 but on the registry port.
    """
    forge = _f()
    claims = forge._base_claims(iss="https://atlas.example.com/")
    tok = forge._sign_with_header({"alg": "RS256", "typ": "JWT"}, claims)
    assert root_ztn(tok, "/atlas/ok.txt", port=REG) == "reject"


@pytest.mark.tokenconf
def test_f03_base_ok_scope_wrong_direction_reject():
    """atlas issuer, scope=storage.read:/cms, path=/atlas/ok.txt → reject.

    WHY:  base_path check: /atlas/ok.txt is under /atlas (base_path=atlas) →
          PASS.  Scope check: storage.read:/cms does not cover /atlas/ok.txt
          → FAIL → reject.  Confirms that satisfying base_path is necessary
          but not sufficient — scope must also cover the request path.
    """
    forge = _f()
    claims = forge._base_claims(iss="https://atlas.example.com",
                                scope="storage.read:/cms")
    tok = forge._sign_with_header({"alg": "RS256", "typ": "JWT"}, claims)
    assert root_ztn(tok, "/atlas/ok.txt", port=REG) == "reject"


@pytest.mark.tokenconf
def test_f04_exact_file_scope_within_registry_base_accept():
    """atlas issuer, scope=storage.read:/atlas/ok.txt, path=/atlas/ok.txt → accept.

    WHY:  base_path check: /atlas/ok.txt under /atlas → PASS.  Scope check:
          storage.read:/atlas/ok.txt exactly covers /atlas/ok.txt → PASS.
          Confirms that exact-file scope (B01) also works correctly when
          combined with the registry base_path constraint.
    """
    forge = _f()
    claims = forge._base_claims(iss="https://atlas.example.com",
                                scope="storage.read:/atlas/ok.txt")
    tok = forge._sign_with_header({"alg": "RS256", "typ": "JWT"}, claims)
    assert root_ztn(tok, "/atlas/ok.txt", port=REG) == "accept"


@pytest.mark.tokenconf
def test_f05_cms_exact_file_scope_accept():
    """cms issuer, scope=storage.read:/cms/ok.txt, path=/cms/ok.txt → accept.

    WHY:  Symmetric to F04 for the cms issuer entry.  base_path: /cms/ok.txt
          under /cms (cms base_path) → PASS.  Scope: storage.read:/cms/ok.txt
          exactly covers /cms/ok.txt → PASS → accept.  Confirms exact-file
          scope works under both registry entries (not atlas-specific).
    """
    forge = _f()
    claims = forge._base_claims(iss="https://cms.example.com",
                                scope="storage.read:/cms/ok.txt")
    tok = forge._sign_with_header({"alg": "RS256", "typ": "JWT"}, claims)
    assert root_ztn(tok, "/cms/ok.txt", port=REG) == "accept"


@pytest.mark.tokenconf
def test_f06_cms_issuer_scope_atlas_path_cms_reject():
    """cms issuer, scope=storage.read:/atlas, path=/cms/ok.txt → reject.

    WHY:  base_path: /cms/ok.txt is under /cms (cms base_path) → PASS.
          Scope: storage.read:/atlas does not cover /cms/ok.txt → FAIL.
          Symmetric to F03: base_path passes but scope in the wrong direction
          prevents access.  Confirms the check is issuer-independent.
    """
    forge = _f()
    claims = forge._base_claims(iss="https://cms.example.com",
                                scope="storage.read:/atlas")
    tok = forge._sign_with_header({"alg": "RS256", "typ": "JWT"}, claims)
    assert root_ztn(tok, "/cms/ok.txt", port=REG) == "reject"


@pytest.mark.tokenconf
def test_f07_atlas_issuer_database_path_reject():
    """atlas issuer (base_path=/atlas), path=/database/ok.txt → reject.

    WHY:  base_path: /database/ok.txt is NOT under /atlas → base_path check
          fails → reject before reaching the scope check.  Tests a path that
          is neither under /atlas nor /cms — a third data area entirely outside
          both registry entries.
    """
    tok = _f().for_issuer("https://atlas.example.com")
    assert root_ztn(tok, "/database/ok.txt", port=REG) == "reject"


@pytest.mark.tokenconf
def test_f08_unknown_issuer_root_scope_reject():
    """Unknown issuer "https://unknown.example.com" → reject (rule 103).

    WHY:  Rule 103 — the registry must reject tokens from issuers not listed
          in the configuration.  No JWKS entry exists for unknown.example.com
          → registry lookup fails → reject.  Complements ISS-05 with a
          distinct issuer URL (not "evil") to confirm it's a general rule.
    """
    tok = _f().for_issuer("https://unknown.example.com")
    assert root_ztn(tok, "/atlas/ok.txt", port=REG) == "reject"


# ---------------------------------------------------------------------------
# Group G — SKW-EDGE: Clock-skew precision cases
#
# Existing SKEW family covers: temporal(-20) on default(accept)/strict(reject),
# temporal(-5) on strict(reject), temporal(3600) on strict(accept).
# These cases cover: tighter boundaries on the 30s window, nbf skew
# interactions, strict-port nbf confirmation, and short-lifetime tokens.
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
def test_g01_exp_minus_1s_default_port_accept():
    """exp=now-1 (1s expired) on default port (30s skew) → accept.

    WHY:  The 30s window trivially covers 1s of expiry.  Confirms the grace
          window starts from below (any exp within 30s of now is accepted).
    """
    assert root_ztn(_f().temporal(-1), "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_g02_exp_minus_29s_default_port_accept():
    """exp=now-29 (29s expired) on default port → accept.

    WHY:  1s inside the 30s grace window.  Paired with A03 (exp=now-31 →
          reject), this bracket confirms the window is exactly [0, 30] seconds.
    """
    assert root_ztn(_f().temporal(-29), "/test.txt", port=PORT) == "accept"
