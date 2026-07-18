"""WLCG token conformance — deep edge matrix.

WHAT: ~80 distinct RFC-boundary cases not already covered by the existing
      NDT, CLM2, SCP2, SIG-multikey, AUD, ISS, and SCITOK families.
WHY:  Locks down subtle conformance corners — exact skew boundaries, scope
      action semantics, audience type variants, claim interactions, key-lookup
      failures across ports, and registry base_path vs scope interplay.
HOW:  Seven groups, each isolating a distinct rule cluster:

  Group A — NDT-EDGE: NumericDate precision boundaries (RFC 7519 §4.1.4-4.1.5)
  Group B — SCP-EDGE: Scope combination / action / path edge cases (WLCG rules 111-117)
  Group C — AUD-EDGE: Audience claim type matrix (RFC 7519 §4.1.3, rules 7-9)
  Group D — CLM-EDGE: Claim type/version/lifetime interactions (rules 15-16, 101, 108, 130)
  Group E — KID-EDGE: Key-selection edge cases across ports (RFC 7515 §4.1.4)
  Group F — REG-EDGE: Issuer-registry base_path × scope interactions (rules 103-105)
  Group G — SKW-EDGE: Clock-skew precision on exp/nbf (30s-grace vs strict-0)

Ports used:
  NGINX_TOKEN_PORT        11097  (default 30s exp skew)
  NGINX_TOKEN_STRICT_PORT 11119  (skew=0 — exp strict)
  NGINX_TOKEN_MULTIKEY_PORT 11250 (jwks_multi: test-key-1 RSA, test-key-2 RSA, ec-key-1 P-256)
  NGINX_TOKEN_REGISTRY_PORT 11251 (scitokens.cfg: atlas base_path=/atlas, cms base_path=/cms)

Data files: /test.txt, /atlas/ok.txt, /cms/ok.txt, /database/ok.txt
  provisioned by ensure_conformance_data() + _ensure_registry_data().
"""

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from tokenforge import TokenForge
from lib.tokenconf import root_ztn, ensure_conformance_data, _CONFORMANCE_FILES
from settings import (
    NGINX_TOKEN_PORT as PORT,
    NGINX_TOKEN_STRICT_PORT as STRICT,
    NGINX_TOKEN_MULTIKEY_PORT as MK,
    NGINX_TOKEN_REGISTRY_PORT as REG,
    TOKENS_DIR,
    DATA_ROOT,
    TEST_ROOT,
)

# ---------------------------------------------------------------------------
# Data provisioning helpers
# ---------------------------------------------------------------------------

_REGISTRY_DATA_ROOT = os.path.join(TEST_ROOT, "data-token-registry")


def _ensure_registry_data():
    """Idempotently create fixture files in the registry server's data root.

    WHAT: Mirrors ensure_conformance_data() but targets data-token-registry
          rather than the shared fleet data root.
    WHY:  The dedicated token-registry nginx instance uses a separate
          brix_storage_backend root; stat requests from ISS tests land there.
    HOW:  Skips existing files; creates parent directories.
    """
    for rel, body in _CONFORMANCE_FILES.items():
        path = os.path.join(_REGISTRY_DATA_ROOT, rel)
        if os.path.exists(path):
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(body)


@pytest.fixture(autouse=True)
def _data():
    """Provision all fixture data before each test in this module."""
    ensure_conformance_data()
    _ensure_registry_data()


def _f():
    """Return a TokenForge loaded from the fleet TOKENS_DIR."""
    return TokenForge(TOKENS_DIR)


# ---------------------------------------------------------------------------
# Group A — NDT-EDGE: NumericDate precision boundaries
#
# Existing NDT family covers: fractional(accept), negative(accept),
# huge(accept), exp_null(reject).
# Existing SKEW family covers: temporal(-20) on default(accept)/strict(reject),
# temporal(-5) on strict(reject), temporal(3600) on strict(accept).
# These cases fill the exact-boundary gaps.
# ---------------------------------------------------------------------------

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


@pytest.mark.tokenconf
def test_g03_nbf_30s_future_default_port_reject():
    """nbf=now+30 (30s in future) on default port → reject.

    WHY:  nbf is enforced strictly (no skew window).  nbf=now+30 means the
          token is not yet valid; now < nbf → reject.  Confirms the skew
          window is applied ONLY to exp, not to nbf.
    """
    assert root_ztn(_f().temporal(3600, 30), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_g04_nbf_31s_future_default_port_reject():
    """nbf=now+31 (31s in future) on default port → reject.

    WHY:  Confirms nbf enforcement holds even 1s beyond the exp skew window.
          Paired with G03 to show consistent strict nbf behaviour.
    """
    assert root_ztn(_f().temporal(3600, 31), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_g05_exp_ok_nbf_future_reject():
    """exp=now+3600 (valid), nbf=now+1 (1s future) → reject.

    WHY:  Both exp and nbf are checked independently.  A valid exp does not
          compensate for a future nbf; the token is still not-yet-valid.
          Confirms that nbf enforcement is not bypassed by a good exp value.
    """
    assert root_ztn(_f().temporal(3600, 1), "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_g06_iat_1d_old_valid_exp_accept():
    """iat=now-86400 (1 day old iat) with normal exp and nbf → accept.

    WHY:  iat is informational only.  A very old iat with still-valid exp/nbf
          must be accepted.  Confirms no upper-bound on iat age is enforced.
    """
    assert root_ztn(_f().temporal(3600, 0, -86400), "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_g07_exp_minus_29s_strict_port_reject():
    """exp=now-29 (29s expired) on strict port (skew=0) → reject.

    WHY:  Strict port: any past expiry is rejected.  exp=now-29 is fine on
          11097 (within 30s grace) but must be rejected on 11119 (skew=0).
          Provides a clear cross-port contrast: the SAME token rejects on 11119
          but would accept on 11097.
    """
    assert root_ztn(_f().temporal(-29), "/test.txt", port=STRICT) == "reject"


@pytest.mark.tokenconf
def test_g08_exp_exactly_now_strict_port_accept():
    """exp=now (exp_delta=0) on strict port (skew=0) → accept.

    WHY:  Both mint and validate use int(time.time()); within the same integer
          second, exp == now, so now > exp is false → token is still valid.
          With skew=0, "not yet expired" means now <= exp (not now < exp+30).
          This shows strict=0 means strict-expiry, not sub-second pessimism.
          Contrast: exp=now-1 on strict port → reject (A04) because now > exp-1+0.
    """
    assert root_ztn(_f().temporal(0), "/test.txt", port=STRICT) == "accept"


@pytest.mark.tokenconf
def test_g09_nbf_5s_future_strict_port_reject():
    """nbf=now+5 (5s future) on strict port → reject.

    WHY:  Confirms that the strict port also enforces nbf (not just exp).
          nbf=now+5 is in the future on any port; skew=0 does not change nbf
          handling (which has always been strict).  This is a belt-and-braces
          check that the strict port's tighter exp-skew did not accidentally
          relax nbf enforcement.
    """
    assert root_ztn(_f().temporal(3600, 5), "/test.txt", port=STRICT) == "reject"
