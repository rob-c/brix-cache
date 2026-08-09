from split_continuation import reexport as _reexport
_reexport(globals(), "_test_wlcg_token_conformance_edge_helpers")

@pytest.mark.tokenconf
def test_a01_exp_exactly_now_default_accept():
    """exp=now (exp_delta=0) on 30s-skew port → accept.

    WHY:  now > exp+30 is false when exp=now (exp+30=now+30 > now) → valid.
          Boundary check: the skew window makes an exactly-at-epoch exp valid.
    """
    assert root_ztn(_f().temporal(0), "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_a02_exp_at_30s_boundary_accept():
    """exp=now-30 (exactly at 30s skew boundary) → accept.

    WHY:  With skew=30, the test is now > exp+30.  exp=now-30 ⇒ exp+30=now
          ⇒ now > now is false ⇒ still valid.  Exact-boundary case.
    """
    assert root_ztn(_f().temporal(-30), "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_a03_exp_1s_beyond_skew_reject():
    """exp=now-31 (1s past the 30s boundary) → reject.

    WHY:  exp=now-31 ⇒ exp+30=now-1 ⇒ now > now-1 is true ⇒ expired.
          Confirms the skew window is exactly [0, 30] seconds.
    """
    assert root_ztn(_f().temporal(-31), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_a04_strict_exp_minus_1s_reject():
    """exp=now-1 on strict port (skew=0) → reject.

    WHY:  Strict port: now > exp+0 ⇒ now > now-1 is true ⇒ rejected immediately.
          Even 1s past expiry triggers rejection when there is no grace window.
    """
    assert root_ztn(_f().temporal(-1), "/test.txt", port=STRICT) == "reject"


@pytest.mark.tokenconf
def test_a05_strict_exp_plus_1s_accept():
    """exp=now+1 on strict port (skew=0) → accept.

    WHY:  Strict port: now > now+1 is false ⇒ still valid.  Confirms that
          skew=0 is strict-expiry enforcement only — barely-future tokens pass.
    """
    assert root_ztn(_f().temporal(1), "/test.txt", port=STRICT) == "accept"


@pytest.mark.tokenconf
def test_a06_nbf_exactly_now_accept():
    """nbf=now (nbf_delta=0) → accept.

    WHY:  RFC 7519 §4.1.5 — nbf: the token is NOT valid before this time.
          nbf=now means valid exactly starting now; now >= nbf → accept.
          No grace window is applied to nbf; this is the boundary from below.
    """
    assert root_ztn(_f().temporal(3600, 0), "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_a07_nbf_1s_future_reject():
    """nbf=now+1 (1s in the future, nbf_delta=+1) → reject.

    WHY:  nbf is enforced strictly (no skew).  now < now+1 ⇒ not-yet-valid.
          Confirms the strict nbf boundary at +1s.
    """
    assert root_ztn(_f().temporal(3600, 1), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_a08_nbf_1h_past_accept():
    """nbf=now-3600 (1h in the past, nbf_delta=-3600) → accept.

    WHY:  Old nbf is valid; no upper bound on how far in the past nbf may be.
          Confirms that a token issued an hour ago (with still-valid exp) passes.
    """
    assert root_ztn(_f().temporal(3600, -3600), "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_a09_iat_future_accept():
    """iat=now+3600 (1h in the future, iat_delta=+3600) → accept.

    WHY:  RFC 7519 §4.1.6 — iat is informational; the server MUST NOT reject
          based on iat alone (rule 13).  A future iat is logically surprising
          but must not cause rejection.
    """
    assert root_ztn(_f().temporal(3600, 0, 3600), "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_a10_missing_nbf_accept():
    """Token with no nbf claim → accept.

    WHY:  RFC 7519 §4.1.5 — nbf is optional; its absence means no not-before
          constraint.  The server must not reject a token solely because nbf
          is missing.
    """
    forge = _f()
    claims = forge._base_claims()
    claims.pop("nbf")
    tok = forge._sign_with_header(
        {"alg": "RS256", "typ": "JWT", "kid": forge.DEFAULT_KID}, claims)
    assert root_ztn(tok, "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_a11_missing_iat_accept():
    """Token with no iat claim → accept.

    WHY:  RFC 7519 §4.1.6 — iat is optional; the server must not reject a
          token solely because iat is absent.
    """
    forge = _f()
    claims = forge._base_claims()
    claims.pop("iat")
    tok = forge._sign_with_header(
        {"alg": "RS256", "typ": "JWT", "kid": forge.DEFAULT_KID}, claims)
    assert root_ztn(tok, "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_a12_exp_24h_future_accept():
    """exp=now+86400 (24h future) → accept.

    WHY:  A 24-hour token is well within normal operational parameters.
          Confirms no artificial upper bound on exp is enforced here.
    """
    assert root_ztn(_f().temporal(86400), "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_a13_iat_epoch_accept():
    """iat=0 (Unix epoch, 1970-01-01) with valid exp → accept.

    WHY:  iat is not validated against any lower-bound; epoch-zero iat is a
          legitimate value for a long-lived token and must not be rejected.
    """
    forge = _f()
    claims = forge._base_claims()
    claims["iat"] = 0
    tok = forge._sign_with_header(
        {"alg": "RS256", "typ": "JWT", "kid": forge.DEFAULT_KID}, claims)
    assert root_ztn(tok, "/test.txt", port=PORT) == "accept"


# ---------------------------------------------------------------------------
# Group B — SCP-EDGE: Scope combination / action / path edge cases
#
# Existing SCP2 family covers: reordered read+write, no-path, sibling-prefix
# (/atl→/atlas), unnormalized, compute, create-read, forbidden chars.
# These cases fill: exact-file, root-scope, trailing-slash, stage/modify/write
# read-access, overlapping reads, empty scope, case-sensitivity,
# file-scope-vs-parent, unknown action, and additional combination cases.
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
def test_b01_exact_file_scope_accept():
    """scope=storage.read:/atlas/ok.txt, GET /atlas/ok.txt → accept.

    WHY:  A scope whose path exactly matches the requested file's path MUST
          grant access (rule 111 — scope path is a prefix ≤ request path at
          segment boundary; equal paths satisfy prefix match).
    """
    tok = _f().scope("storage.read:/atlas/ok.txt")
    assert root_ztn(tok, "/atlas/ok.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_b02_exact_file_scope_different_file_reject():
    """scope=storage.read:/atlas/ok.txt, GET /atlas/other.txt → reject.

    WHY:  The scope grants access only to /atlas/ok.txt specifically; another
          file in the same directory is outside the scope prefix → reject.
          Confirms exact-file scopes are not directory-covering.
    """
    tok = _f().scope("storage.read:/atlas/ok.txt")
    assert root_ztn(tok, "/atlas/other.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_b03_root_scope_deep_path_accept():
    """scope=storage.read:/, GET /database/ok.txt → accept.

    WHY:  Root scope covers all paths; /database/ok.txt is reachable even
          though it is not under /atlas or /cms.  Validates broad-scope coverage.
    """
    tok = _f().scope("storage.read:/")
    assert root_ztn(tok, "/database/ok.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_b04_trailing_slash_scope_accept():
    """scope=storage.read:/atlas/, GET /atlas/ok.txt → accept.

    WHY:  A scope path with a trailing slash explicitly ends at a directory
          boundary; /atlas/ covers all children.  The scope path "/atlas/"
          matches "/atlas/ok.txt" because the scope ends with '/', fulfilling
          the boundary constraint from the start (rule 117).
    """
    tok = _f().scope("storage.read:/atlas/")
    assert root_ztn(tok, "/atlas/ok.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_b05_stage_scope_grants_read_accept():
    """scope=storage.stage:/atlas, GET /atlas/ok.txt → accept.

    WHY:  WLCG Token Profile — storage.stage maps to read permission in the
          scope engine (src/auth/token/scopes.c sets scope->read=1 for stage).
          Stage is a read-like operation; a token with only stage scope CAN
          read files from the staged area.
    """
    tok = _f().scope("storage.stage:/atlas")
    assert root_ztn(tok, "/atlas/ok.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_b06_create_scope_no_read_reject():
    """scope=storage.create:/atlas, GET /atlas/ok.txt → reject.

    WHY:  storage.create sets only scope->create=1; brix_token_check_read
          checks only scope->read.  create does NOT imply read.  The path
          /atlas/ok.txt IS within the scope's prefix (/atlas) but the
          capability is wrong → reject.  Isolates the "create≠read" rule
          from the path check (unlike SCP2-07 where path was also outside scope).
    """
    tok = _f().scope("storage.create:/atlas")
    assert root_ztn(tok, "/atlas/ok.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_b07_modify_scope_no_read_reject():
    """scope=storage.modify:/atlas, GET /atlas/ok.txt → reject.

    WHY:  storage.modify sets only scope->modify=1.  brix_token_check_read
          checks only scope->read; modify is NOT a read capability.
          A token with only modify scope is a write-side token — it cannot read.
    """
    tok = _f().scope("storage.modify:/atlas")
    assert root_ztn(tok, "/atlas/ok.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_b08_write_scope_no_read_reject():
    """scope=storage.write:/atlas, GET /atlas/ok.txt → reject.

    WHY:  storage.write sets scope->write=1 only.  brix_token_check_read
          checks scope->read; write does NOT grant read access.
          Confirms write-only tokens cannot stat/read files even within scope.
    """
    tok = _f().scope("storage.write:/atlas")
    assert root_ztn(tok, "/atlas/ok.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_b09_overlapping_read_scopes_broader_covers_accept():
    """scope="storage.read:/ storage.read:/atlas", GET /database/ok.txt → accept.

    WHY:  Two overlapping read scopes; the broader (storage.read:/) covers
          /database/ok.txt even though the narrower (storage.read:/atlas)
          does not.  The scope engine must evaluate ALL scope entries and
          accept if ANY one grants access (rules 98, 111).
    """
    tok = _f().scope("storage.read:/ storage.read:/atlas")
    assert root_ztn(tok, "/database/ok.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_b10_empty_scope_string_reject():
    """scope="" (empty string), GET /test.txt → reject.

    WHY:  An empty scope string carries no grants.  brix_token_scope_parse
          produces zero parsed entries; brix_token_check_read finds nothing →
          reject.  Confirms that an empty scope is not equivalent to a wildcard.
    """
    tok = _f().scope("")
    assert root_ztn(tok, "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_b11_scope_case_sensitive_reject():
    """scope=storage.read:/Atlas (capital A), GET /atlas/ok.txt → reject.

    WHY:  Scope path comparison uses memcmp (byte-for-byte comparison in
          scope_path_matches).  '/Atlas' ≠ '/atlas' on case-sensitive systems
          → scope mismatch → reject.  Rule 117: path comparison is exact.
    """
    tok = _f().scope("storage.read:/Atlas")
    assert root_ztn(tok, "/atlas/ok.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_b12_file_scope_parent_dir_reject():
    """scope=storage.read:/atlas/ok.txt, GET /atlas → reject.

    WHY:  The scope path "/atlas/ok.txt" (13 chars) is LONGER than the request
          path "/atlas" (6 chars).  A longer scope path cannot be a prefix of a
          shorter request path → no scope match → reject.  File scope does not
          cover parent directories.
    """
    tok = _f().scope("storage.read:/atlas/ok.txt")
    assert root_ztn(tok, "/atlas", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_b13_two_disjoint_read_scopes_second_covers_accept():
    """scope="storage.read:/atlas storage.read:/database", GET /database/ok.txt → accept.

    WHY:  Two disjoint read scopes; the second (storage.read:/database) covers
          /database/ok.txt.  Validates that the engine evaluates all scope
          entries (not just the first) and accepts on any match.
    """
    tok = _f().scope("storage.read:/atlas storage.read:/database")
    assert root_ztn(tok, "/database/ok.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_b14_write_atlas_read_cms_request_atlas_reject():
    """scope="storage.write:/atlas storage.read:/cms", GET /atlas/ok.txt → reject.

    WHY:  The token has write:/atlas (no read for /atlas) and read:/cms.
          Requesting /atlas/ok.txt requires read access to /atlas; the only
          read scope (/cms) does not cover /atlas → reject.
    """
    tok = _f().scope("storage.write:/atlas storage.read:/cms")
    assert root_ztn(tok, "/atlas/ok.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_b15_stage_atlas_write_cms_read_stage_path_accept():
    """scope="storage.stage:/atlas storage.write:/cms", GET /atlas/ok.txt → accept.

    WHY:  stage:/atlas grants read on /atlas (stage maps to scope->read=1);
          write:/cms is irrelevant to this request.  The stage scope covers
          /atlas/ok.txt → accept.
    """
    tok = _f().scope("storage.stage:/atlas storage.write:/cms")
    assert root_ztn(tok, "/atlas/ok.txt", port=PORT) == "accept"
