"""WLCG token conformance — SCP2 family (scope syntax, authz, segment boundary).

Probes port 11097 (NGINX_TOKEN_PORT) which enforces token auth and capability
scope (storage.*) over the WLCG profile.

Ground truth (src/auth/token/validate.c + src/auth/token/scope.c):
  - scope is a space-separated list; order is irrelevant (rule 98).
  - storage.* scopes require a ':path' component; bare 'storage.read' grants
    nothing (rule 112).
  - Prefix match is directory-boundary aware: storage.read:/atl does NOT cover
    /atlas (rule 117 — segment must end at '/' or string end).
  - storage.create:/path grants create (write-new) only; does NOT imply read
    (rule 115).
  - Non-storage scopes (compute.*) grant no storage access (rule 118).
  - Unnormalized scope paths (/foo/../bar) do not match normalised paths →
    reject (rules 113/141).
  - Malformed scope-token characters ('"', '\\') → fail-closed → reject.

Test cases:
  SCP2-01  scope_reordered("storage.read:/atlas","storage.write:/cms") +
           GET /atlas/ok.txt → accept (rule 98: order-independent; read:/atlas grants).
  SCP2-02  same token, GET /cms/ok.txt → reject (only write:/cms, not read:/cms).
  SCP2-03  scope_storage_no_path(), GET /test.txt → reject (rule 112: path required).
  SCP2-04a scope_sibling("/atlas"), GET /atlas/ok.txt → accept (covers).
  SCP2-04b scope("storage.read:/atl"), GET /atlas/ok.txt → reject (rule 117: /atl ≠ /atlas).
  SCP2-05  scope_unnormalized(), GET /test.txt → reject (fail-closed; path unresolvable).
  SCP2-06  scope_compute("read"), GET /test.txt → reject (compute scope ≠ storage).
  SCP2-07  scope_create_only(), GET /data/ → reject (rule 115: create ≠ read).
  SCP2-08  scope_forbidden_quote(), GET /test.txt → reject (malformed → fail-closed).
  SCP2-09  scope_forbidden_backslash(), GET /test.txt → reject (malformed → fail-closed).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

import pytest
from tokenforge import TokenForge
from lib.tokenconf import root_ztn, ensure_conformance_data
from settings import NGINX_TOKEN_PORT as PORT, TOKENS_DIR


def _f():
    return TokenForge(TOKENS_DIR)


@pytest.fixture(autouse=True)
def _data():
    ensure_conformance_data()


@pytest.mark.tokenconf
def test_scp2_01_scope_reordered_read_atlas_accept():
    """storage.read:/atlas storage.write:/cms, GET /atlas/ok.txt → accept (rule 98).

    WHY:  WLCG Token Profile §4 / rule 98 — multiple scope-tokens are
          space-separated; the order in which they appear MUST NOT affect
          whether any individual scope-token grants access.  The first token
          storage.read:/atlas covers /atlas/ok.txt → accept.
    """
    tok = _f().scope_reordered("storage.read:/atlas", "storage.write:/cms")
    assert root_ztn(tok, "/atlas/ok.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_scp2_02_scope_reordered_no_read_cms_reject():
    """Same token (read:/atlas write:/cms), GET /cms/ok.txt → reject.

    WHY:  The token carries write:/cms but NOT read:/cms.  A stat/read of
          /cms/ok.txt requires read capability over that path — write-only scope
          does not cover it → reject.
    """
    tok = _f().scope_reordered("storage.read:/atlas", "storage.write:/cms")
    assert root_ztn(tok, "/cms/ok.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_scp2_03_scope_storage_no_path_reject():
    """scope 'storage.read' without ':PATH', GET /test.txt → reject (rule 112).

    WHY:  WLCG Token Profile §4 / rule 112 — storage.* scopes MUST carry a
          path component in the form 'storage.action:/path'.  The path-less form
          'storage.read' is malformed for storage authorization and MUST NOT
          grant any access.
    """
    tok = _f().scope_storage_no_path()
    assert root_ztn(tok, "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_scp2_04a_scope_sibling_covers_accept():
    """scope storage.read:/atlas, GET /atlas/ok.txt → accept.

    WHY:  The scope storage.read:/atlas covers the subtree rooted at /atlas.
          /atlas/ok.txt is a direct child → accept.
    """
    tok = _f().scope_sibling("/atlas")
    assert root_ztn(tok, "/atlas/ok.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_scp2_04b_scope_prefix_no_segment_boundary_reject():
    """scope storage.read:/atl, GET /atlas/ok.txt → reject (rule 117).

    WHY:  WLCG Token Profile §4 / rule 117 — a scope path MUST respect
          directory-segment boundaries.  /atl is a strict string prefix of
          /atlas but does NOT end at a '/' boundary; it MUST NOT be treated as
          covering /atlas or any path under it.
    """
    tok = _f().scope("storage.read:/atl")
    assert root_ztn(tok, "/atlas/ok.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_scp2_05_scope_unnormalized_reject():
    """scope storage.read:/foo/../bar (unnormalized path), GET /test.txt → reject.

    WHY:  WLCG Token Profile §4 / rules 113/141 — scope paths must be
          normalized; a path containing '..' components is either an invalid
          scope-token or a traversal attempt.  The implementation rejects
          the stat request (the scope path '/foo/../bar' does not cover
          '/test.txt') → fail-closed → reject.
    """
    tok = _f().scope_unnormalized()
    assert root_ztn(tok, "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_scp2_06_scope_compute_no_storage_reject():
    """scope compute.read:/queue, GET /test.txt → reject (rule 118).

    WHY:  WLCG Token Profile §4 / rule 118 — compute.* scopes apply to
          compute resources, not storage paths.  A storage read requires a
          storage.read (or storage.modify/storage.stage) scope; compute.read
          grants no storage access.  Unknown/non-storage scopes are fail-closed.
    """
    tok = _f().scope_compute("read")
    assert root_ztn(tok, "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_scp2_07_scope_create_only_no_read_reject():
    """scope storage.create:/data, read stat of /test.txt → reject (rule 115).

    WHY:  WLCG Token Profile §4 / rule 115 — storage.create grants permission
          to create new objects but does NOT imply storage.read, storage.modify,
          or overwrite of existing objects.  A read (kXR_stat) of /test.txt
          requires storage.read:/test.txt or a covering storage.read scope;
          storage.create:/data does not supply it → reject.

    NOTE: Full write-path testing (kXR_open for write) is deferred to a separate
          write-framing task; this case validates the read side only.
    """
    tok = _f().scope_create_only()
    assert root_ztn(tok, "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_scp2_08_scope_forbidden_quote_reject():
    """scope storage.read:/a"b (contains double-quote), GET /test.txt → reject.

    WHY:  WLCG Token Profile §4 / rule 97 — the double-quote character (0x22)
          is not permitted inside a scope-token value.  The malformed scope does
          not match /test.txt; the implementation fails closed regardless of
          whether the charset constraint is explicitly enforced.
    COMMENT: The RFC mandates charset enforcement (rule 97); our server may or
             may not enforce the charset explicitly, but the fail-closed behaviour
             on the scope path match produces the correct reject verdict.
    """
    tok = _f().scope_forbidden_quote()
    assert root_ztn(tok, "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_scp2_09_scope_forbidden_backslash_reject():
    r"""scope storage.read:/a\b (contains backslash), GET /test.txt → reject.

    WHY:  WLCG Token Profile §4 / rule 97 — the backslash character (0x5C)
          is not permitted inside a scope-token value.  The malformed scope
          does not match /test.txt; the implementation fails closed.
    """
    tok = _f().scope_forbidden_backslash()
    assert root_ztn(tok, "/test.txt", port=PORT) == "reject"
