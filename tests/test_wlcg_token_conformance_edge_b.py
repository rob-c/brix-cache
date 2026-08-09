from split_continuation import reexport as _reexport
_reexport(globals(), "_test_wlcg_token_conformance_edge_helpers")

@pytest.mark.tokenconf
def test_b16_stage_atlas_write_cms_read_write_path_reject():
    """scope="storage.stage:/atlas storage.write:/cms", GET /cms/ok.txt → reject.

    WHY:  write:/cms grants write only (scope->write=1, not ->read=1);
          stage:/atlas grants read only for /atlas.  Requesting /cms/ok.txt
          for read finds no read scope that covers /cms → reject.
    """
    tok = _f().scope("storage.stage:/atlas storage.write:/cms")
    assert root_ztn(tok, "/cms/ok.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_b17_exact_root_file_scope_accept():
    """scope=storage.read:/test.txt, GET /test.txt → accept.

    WHY:  Exact-file scope at the root level (no subdirectory).  Verifies
          that the prefix match works for paths of the form "/<filename>"
          as well as "/<dir>/<filename>" (B01).
    """
    tok = _f().scope("storage.read:/test.txt")
    assert root_ztn(tok, "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_b18_file_scope_shorter_request_reject():
    """scope=storage.read:/test.txt, GET /test → reject.

    WHY:  The scope path "/test.txt" (9 chars) is longer than the request
          path "/test" (5 chars).  A longer scope cannot prefix a shorter path
          → reject.  Confirms the prefix direction check.
    """
    tok = _f().scope("storage.read:/test.txt")
    assert root_ztn(tok, "/test", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_b19_rule117_scope_atlas_sibling_dir_reject():
    """scope=storage.read:/atlas, GET /atlasmore/ok.txt → reject (rule 117).

    WHY:  Rule 117 — scope path prefix match must respect directory-segment
          boundaries.  "/atlas" ends at the boundary before "/atlasmore"
          diverges (at the 'm' character, no '/' separator) — /atlasmore is a
          sibling, not a child of /atlas.  Reject whether by scope mismatch or
          path-not-found (both produce reject; the scope is the relevant guard).
    NOTE: /atlasmore/ok.txt does not exist; rejection is guaranteed regardless.
    """
    tok = _f().scope("storage.read:/atlas")
    assert root_ztn(tok, "/atlasmore/ok.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_b20_rule117_file_prefix_no_segment_boundary_reject():
    """scope=storage.read:/atlas/ok, GET /atlas/ok.txt → reject (rule 117).

    WHY:  Rule 117 — "/atlas/ok" is a string prefix of "/atlas/ok.txt" but the
          next character in the request path is '.' (not '/'), so no segment
          boundary is present.  The scope /atlas/ok MUST NOT cover /atlas/ok.txt.
          Complements SCP2-04b which tests /atl→/atlas (directory level);
          this tests the same rule at the file level within a directory.
    """
    tok = _f().scope("storage.read:/atlas/ok")
    assert root_ztn(tok, "/atlas/ok.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_b21_narrow_database_scope_accept():
    """scope=storage.read:/database, GET /database/ok.txt → accept.

    WHY:  Confirms the scope engine works correctly for a path outside the
          /atlas and /cms trees.  A narrow scope grants access to files under
          its prefix regardless of directory name.
    """
    tok = _f().scope("storage.read:/database")
    assert root_ztn(tok, "/database/ok.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_b22_unknown_scope_action_reject():
    """scope=storage.delete:/cms, GET /cms/ok.txt → reject.

    WHY:  "storage.delete" is not a recognised WLCG scope action.  The scope
          parser does not set any capability flag for unknown actions; zero
          flags means no read grant → fail-closed → reject.
    """
    tok = _f().scope("storage.delete:/cms")
    assert root_ztn(tok, "/cms/ok.txt", port=PORT) == "reject"


# ---------------------------------------------------------------------------
# Group C — AUD-EDGE: Audience claim type matrix
#
# Existing coverage: wrong scalar (PAR-06), array with our id (PAR-07),
# WLCG wildcard scalar on WebDAV/S3 (PAR-08), SciTokens ANY (SCITOK-03 xfail).
# Manifest AUD family covers additional root:// cases (load_manifest("AUD")).
# These cases fill: single-element array, wildcard as array element, no-match
# array, wrong case, empty string, id+extras in array, empty array, wildcard
# scalar on root://, numeric aud type.
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
def test_c01_aud_single_element_array_accept():
    """aud=["nginx-xrootd"] (single-element array) → accept.

    WHY:  RFC 7519 §4.1.3 — aud may be a JSON array; a single-element array
          containing the server's audience identifier is a valid match.
          Confirms array form is accepted at parity with scalar form.
    """
    tok = _f().aud_value(["nginx-xrootd"])
    assert root_ztn(tok, "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_c02_aud_array_wildcard_element_accept():
    """aud=["other","https://wlcg.cern.ch/jwt/v1/any"] → accept.

    WHY:  Rules 104/105 — the WLCG wildcard URI is valid even when it appears
          as one element among several in an array.  The server must match any
          element, including the wildcard URI, regardless of position.
    """
    tok = _f().aud_value(["other", "https://wlcg.cern.ch/jwt/v1/any"])
    assert root_ztn(tok, "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_c03_aud_array_no_match_no_wildcard_reject():
    """aud=["a","b","c"] (array, no server id, no wildcard) → reject.

    WHY:  RFC 7519 §4.1.3 — every element in the array is checked; none
          equals "nginx-xrootd" and none is the WLCG wildcard → reject.
    """
    tok = _f().aud_value(["a", "b", "c"])
    assert root_ztn(tok, "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_c04_aud_wrong_case_reject():
    """aud="Nginx-Xrootd" (capital N and X) → reject.

    WHY:  Rule 9 — audience comparison is case-sensitive.  "Nginx-Xrootd"
          ≠ "nginx-xrootd" → mismatch → reject.
    """
    tok = _f().aud_value("Nginx-Xrootd")
    assert root_ztn(tok, "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_c05_aud_empty_string_reject():
    """aud="" (empty string) → reject.

    WHY:  An empty string does not match the server's configured audience
          ("nginx-xrootd") and is not the WLCG wildcard URI → reject.
    """
    tok = _f().aud_value("")
    assert root_ztn(tok, "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_c06_aud_server_id_plus_extras_accept():
    """aud=["nginx-xrootd","x","y","z"] → accept.

    WHY:  RFC 7519 §4.1.3 — any element in the aud array matching the server's
          audience is sufficient for acceptance, regardless of other elements.
          This tests that our id in position 0 among multiple values accepts.
    """
    tok = _f().aud_value(["nginx-xrootd", "x", "y", "z"])
    assert root_ztn(tok, "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_c07_aud_empty_array_reject():
    """aud=[] (empty JSON array) → reject.

    WHY:  RFC 7519 §4.1.3 — an empty audience array contains no identifiers.
          json_string_or_array_contains() iterates zero elements; no match →
          reject.  Distinct from the "missing aud" case (which we don't test
          here since aud is always set by the forge).
    """
    tok = _f().aud_value([])
    assert root_ztn(tok, "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_c08_aud_wildcard_scalar_root_accept():
    """aud="https://wlcg.cern.ch/jwt/v1/any" (scalar wildcard) on root:// → accept.

    WHY:  Rules 104/105 — the WLCG wildcard is valid for root:// (port 11097)
          as well as WebDAV/S3 (PAR-08).  This is an explicit root:// check
          since PAR-08 only covers HTTP paths.
    """
    tok = _f().aud_wildcard()
    assert root_ztn(tok, "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_c09_aud_wildcard_sole_array_element_accept():
    """aud=["https://wlcg.cern.ch/jwt/v1/any"] (wildcard as sole array element) → accept.

    WHY:  Rules 104/105 — the wildcard URI must be accepted in array form as
          well as scalar form.  C08 tests scalar; this tests single-element
          array to confirm the array path is also checked for the wildcard.
    """
    tok = _f().aud_value(["https://wlcg.cern.ch/jwt/v1/any"])
    assert root_ztn(tok, "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_c10_aud_numeric_type_reject():
    """aud=42 (JSON integer, wrong type) → reject.

    WHY:  RFC 7519 §4.1.3 — aud MUST be a string or array of strings.  A
          numeric value does not match the configured audience string and is
          not the wildcard URI.  Confirms that type confusion via numeric aud
          does not accidentally match the audience check.
    """
    forge = _f()
    tok = forge._sign_with_header(
        {"alg": "RS256", "typ": "JWT", "kid": forge.DEFAULT_KID},
        forge._base_claims(aud=42))
    assert root_ztn(tok, "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_c11_aud_our_id_last_in_long_array_accept():
    """aud=["a","b","c","d","nginx-xrootd"] (our id last in multi-element array) → accept.

    WHY:  RFC 7519 §4.1.3 — audience match is position-independent.  The
          json_string_or_array_contains() function iterates ALL elements;
          finding our id at the last position must still accept.
    """
    tok = _f().aud_value(["a", "b", "c", "d", "nginx-xrootd"])
    assert root_ztn(tok, "/test.txt", port=PORT) == "accept"


# ---------------------------------------------------------------------------
# Group D — CLM-EDGE: Claim type/version/lifetime interactions
#
# Existing CLM2 family covers: dup_claim_names, iss_non_string, sub_non_string
# (xfail), iat_after_exp, nbf_after_exp, unknown_claims_ok.
# These cases fill: empty sub, groups claim with read scope, >6h lifetime
# (rule 108 divergence), trailing-slash issuer, wlcg.ver variants.
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
def test_d01_empty_sub_accept():
    """generate(sub="") empty subject claim → accept.

    WHY:  The sub claim is used for logging/mapping only; its format is not
          strictly validated.  An empty string is structurally valid (still a
          string per RFC 7519 §4.1.2).  The validator does not enforce
          non-empty sub → accept.
    """
    assert root_ztn(_f().generate(sub=""), "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_d02_wlcg_groups_with_read_scope_accept():
    """Token with wlcg.groups=["/wlcg","/atlas"] + storage.read:/ → accept.

    WHY:  Rule 119 — wlcg.groups is an optional claim carrying VO membership.
          Its presence must not interfere with scope-based authorization.
          The read scope still covers /test.txt regardless of groups.
    """
    tok = _f().generate(groups=["/wlcg", "/atlas"])
    assert root_ztn(tok, "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
@pytest.mark.xfail(
    strict=True,
    reason=(
        "DIVERGENCE rule 108: WLCG Token Profile SHOULD reject tokens with "
        "lifetime > 6 hours (25200s).  generate(lifetime=7*3600) produces a "
        "25200s token.  Our implementation does not enforce this SHOULD rule; "
        "actual=accept.  Documented as a known conformance gap — rule 108 is "
        "advisory (SHOULD, not MUST)."
    ),
)
def test_d03_7h_lifetime_rule108_divergence():
    """generate(lifetime=7*3600) 7-hour token → RFC SHOULD reject (rule 108).

    WHY:  WLCG Token Profile §3 / rule 108 — tokens SHOULD NOT have a lifetime
          exceeding 6 hours (21600s).  A 7-hour (25200s) token exceeds this
          advisory limit.  RFC-correct verdict is reject; our implementation
          does not enforce the SHOULD → actual=accept → xfail(strict).
    """
    tok = _f().generate(lifetime=7 * 3600)
    assert root_ztn(tok, "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_d04_trailing_slash_issuer_reject():
    """generate(issuer="https://test.example.com/") trailing-slash iss → reject.

    WHY:  Rule 130 — iss comparison is exact string match.  The configured
          issuer is "https://test.example.com" (no trailing slash); the token
          carries "https://test.example.com/" → no match → reject.
          Confirms that URL normalisation is not silently applied to iss.
    """
    tok = _f().generate(issuer="https://test.example.com/")
    assert root_ztn(tok, "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_d05_wlcg_ver_missing_accept():
    """Token with no wlcg.ver claim → accept (lenient; rule 101 advisory).

    WHY:  Rule 101 — WLCG profile REQUIRES wlcg.ver="1.0".  Our implementation
          treats the absence of wlcg.ver as a non-fatal advisory; scope-based
          authorization proceeds normally → accept.
    CHARACTERISE: confirms that wlcg.ver enforcement is advisory not mandatory.
    """
    tok = _f().wlcg_missing_ver()
    assert root_ztn(tok, "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_d06_wlcg_ver_future_version_accept():
    """wlcg.ver="2.0" (future/unknown version string) → accept.

    WHY:  Rule 101 specifies version "1.0"; a higher version is unknown.  Our
          implementation ignores wlcg.ver entirely (treated as an unknown claim
          per rule 16) → accept.  A strict implementation might reject.
    CHARACTERISE: confirms forward-compatibility tolerance for future WLCG versions.
    """
    tok = _f().wlcg_ver("2.0")
    assert root_ztn(tok, "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_d07_wlcg_ver_old_version_accept():
    """wlcg.ver="0.9" (pre-1.0 version string) → accept.

    WHY:  A pre-1.0 version value is also unknown.  Same reasoning as D06:
          wlcg.ver is not enforced → accept.
    CHARACTERISE: confirms backward-compatibility tolerance.
    """
    tok = _f().wlcg_ver("0.9")
    assert root_ztn(tok, "/test.txt", port=PORT) == "accept"
