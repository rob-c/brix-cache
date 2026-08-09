from split_continuation import reexport as _reexport
_reexport(globals(), "_test_wlcg_token_conformance_parity_ext_helpers")

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


@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_ext_extra_05_sub_non_string_reject(proto):
    """EXTRA-05: sub=["a","b"] array value → RFC mandates reject (rules 4/6).

    WHAT: The sub claim is a JSON array rather than a StringOrURI scalar.
    WHY:  RFC 7519 §4.1.2 / rules 4/6 — the sub claim MUST be a StringOrURI;
          an array value violates the type constraint.  token_extract_claims()
          now rejects a present-but-non-string "sub" (json_get_string fails on
          an array while json_has_member confirms presence) → reject, uniform
          across webdav and s3. (phase-92: was XFAIL; hardening landed.)
    """
    tok = _forge().sub_non_string()
    assert probe(proto, tok) == "reject"
