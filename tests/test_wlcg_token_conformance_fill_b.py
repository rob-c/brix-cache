from split_continuation import reexport as _reexport
_reexport(globals(), "_test_wlcg_token_conformance_fill_helpers")

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_17_read_root_get_atlas_accept():
    """FIL-WG-17: storage.read:/ GET /atlas/ok.txt → accept (rule 114: root covers any sub).

    WHAT: A root-scoped read token grants access to every path under /.
    WHY:  Rule 114 — storage.read:/ covers all sub-paths including /atlas/ok.txt.
          Root-scope tokens are issued by WLCG VOs for broad data-access roles.
    """
    tok = _forge().scope("storage.read:/")
    assert webdav_bearer(tok, "/atlas/ok.txt", write=False,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "accept"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_18_write_root_put_accept():
    """FIL-WG-18: storage.write:/ PUT /atlas/wg_fill_18.txt → accept (root write scope).

    WHAT: A root-scoped write token grants PUT access to every path under /.
    WHY:  Confirms that root-scope write is honoured on WebDAV 8446 independently
          of the per-path scope tests.
    """
    tok = _forge().scope("storage.write:/")
    assert webdav_bearer(tok, "/atlas/wg_fill_18.txt", write=True,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "accept"


# --- Cross-grant: read on /cms, write on /atlas ---

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_19_read_cms_write_atlas_get_atlas_reject():
    """FIL-WG-19: read:/cms write:/atlas GET /atlas/ok.txt → reject (no read on /atlas).

    WHAT: The token has read on /cms and write on /atlas — GET /atlas/ok.txt
          requires read on /atlas, which is absent.
    WHY:  Cross-VO scope combinations must not accidentally grant read via the
          write grant; each permission type is independent.
    """
    tok = _forge().scope("storage.read:/cms storage.write:/atlas")
    assert webdav_bearer(tok, "/atlas/ok.txt", write=False,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "reject"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_20_read_cms_write_atlas_get_cms_accept():
    """FIL-WG-20: read:/cms write:/atlas GET /cms/ok.txt → accept (read on /cms present).

    WHAT: The same cross-grant token has read on /cms; GET /cms/ok.txt must
          be accepted since the read component covers /cms.
    WHY:  Positive complement to FIL-WG-19 — confirms the read-on-/cms grant
          in the same token is independently honoured.
    """
    tok = _forge().scope("storage.read:/cms storage.write:/atlas")
    assert webdav_bearer(tok, "/cms/ok.txt", write=False,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "accept"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_21_read_cms_write_atlas_put_atlas_accept():
    """FIL-WG-21: read:/cms write:/atlas PUT /atlas/wg_fill_21.txt → accept.

    WHAT: The write-on-/atlas grant in the cross-grant token must accept PUT.
    WHY:  Confirms the write component of the cross-grant is independently active
          even when the same token also carries a read grant on a different path.
    """
    tok = _forge().scope("storage.read:/cms storage.write:/atlas")
    assert webdav_bearer(tok, "/atlas/wg_fill_21.txt", write=True,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "accept"


# --- Multi-scope read on two paths (FIL-WG-22 through FIL-WG-23) ---

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_22_read_atlas_read_cms_get_atlas_accept():
    """FIL-WG-22: read:/atlas read:/cms GET /atlas/ok.txt → accept.

    WHAT: A token with two read scopes covering different paths; GET on the
          first covered path must be accepted.
    WHY:  Rules 98/110 — scope order is irrelevant; the union of grants applies.
    """
    tok = _forge().scope("storage.read:/atlas storage.read:/cms")
    assert webdav_bearer(tok, "/atlas/ok.txt", write=False,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "accept"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_23_read_atlas_read_cms_get_cms_accept():
    """FIL-WG-23: read:/atlas read:/cms GET /cms/ok.txt → accept (second path in union).

    WHAT: GET on the second covered path in a multi-scope read token must also
          be accepted.
    WHY:  Both paths are independently granted by the scope union; neither takes
          precedence over the other.
    """
    tok = _forge().scope("storage.read:/atlas storage.read:/cms")
    assert webdav_bearer(tok, "/cms/ok.txt", write=False,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "accept"


# --- Sub-scope narrower than request ---

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_24_read_atlas_sub_get_atlas_root_reject():
    """FIL-WG-24: read:/atlas/sub GET /atlas/ok.txt → reject (scope narrower than request).

    WHAT: The scope covers /atlas/sub only; /atlas/ok.txt is at the parent level
          and is NOT covered by the sub-path scope.
    WHY:  Rule 114 — scope prefix grants access to the named path and its
          sub-paths, but NOT to the parent directory.
    """
    tok = _forge().scope("storage.read:/atlas/sub")
    assert webdav_bearer(tok, "/atlas/ok.txt", write=False,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "reject"


# --- Write scope narrower than request (cross-read-scope PUT) ---

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_25_write_atlas_read_cms_put_cms_reject():
    """FIL-WG-25: write:/atlas read:/cms PUT /cms/wg_fill_25.txt → reject (no write on /cms).

    WHAT: The token has read on /cms but only write on /atlas; PUT /cms/ requires
          write on /cms, which is absent.
    WHY:  The read grant on /cms must NOT be confused with a write grant; scope
          types are orthogonal.
    """
    tok = _forge().scope("storage.write:/atlas storage.read:/cms")
    assert webdav_bearer(tok, "/cms/wg_fill_25.txt", write=True,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "reject"


# --- Sibling-path rejection (rule 117) ---

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_26_read_atlas_write_cms_put_atlas_reject():
    """FIL-WG-26: read:/atlas write:/cms GET /cms/ok.txt → reject (only read on /atlas not /cms).

    WHAT: The token carries read on /atlas and write on /cms; GET /cms/ok.txt
          needs read on /cms, which is not in the token.
    WHY:  The write grant on /cms is not a superset of the read grant; rule 116
          states each permission type is independent.
    """
    tok = _forge().scope("storage.read:/atlas storage.write:/cms")
    assert webdav_bearer(tok, "/cms/ok.txt", write=False,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "reject"


# ===========================================================================
# Group 3 — Audience and scope variants (root:// 11097)
# ===========================================================================

@pytest.mark.tokenconf
def test_fil_aq_01_aud_five_element_array_accept():
    """FIL-AQ-01: aud=["a","b","c","d","nginx-xrootd"] (5-elem array, match last) → accept.

    WHAT: The aud claim is a 5-element JSON array; "nginx-xrootd" is the last
          element.  The server must accept because its identifier is present.
    WHY:  RFC 7519 §4.1.3 / rule 7 — aud MAY be a JSON array; membership is
          position-independent.  A 5-element array stresses the iteration path.
    """
    tok = _forge().aud_value(["a", "b", "c", "d", "nginx-xrootd"])
    assert root_ztn(tok, "/test.txt", port=NGINX_TOKEN_PORT) == "accept"


@pytest.mark.tokenconf
def test_fil_aq_02_aud_duplicate_elements_accept():
    """FIL-AQ-02: aud=["nginx-xrootd","nginx-xrootd"] (duplicate) → accept.

    WHAT: An aud array with the server's identifier listed twice.
    WHY:  Rule 7 — the server must accept as long as its identifier appears at
          least once; duplicate elements must not cause rejection.
    """
    tok = _forge().aud_value(["nginx-xrootd", "nginx-xrootd"])
    assert root_ztn(tok, "/test.txt", port=NGINX_TOKEN_PORT) == "accept"


@pytest.mark.tokenconf
def test_fil_aq_03_aud_trailing_space_reject():
    """FIL-AQ-03: aud="nginx-xrootd " (trailing space) → reject (rule 9 exact match).

    WHAT: The audience string includes a trailing space; the comparison must be
          exact — "nginx-xrootd " ≠ "nginx-xrootd".
    WHY:  RFC 7519 §4.1.3 / rule 9 — aud comparison MUST be case-sensitive
          equality; a trailing space is a distinct character that must not match.
    """
    tok = _forge().generate(audience="nginx-xrootd ")
    assert root_ztn(tok, "/test.txt", port=NGINX_TOKEN_PORT) == "reject"


@pytest.mark.tokenconf
def test_fil_aq_04_aud_empty_array_reject():
    """FIL-AQ-04: aud=[] (empty array) → reject (server's id absent, rule 8).

    WHAT: The aud claim is an empty JSON array; the server's identifier is
          absent → must reject.
    WHY:  RFC 7519 §4.1.3 / rule 8 — if aud is present and the server's
          identifier is not among the values, reject; an empty array trivially
          fails the membership check.
    """
    tok = _forge().aud_value([])
    assert root_ztn(tok, "/test.txt", port=NGINX_TOKEN_PORT) == "reject"


@pytest.mark.tokenconf
def test_fil_aq_05_scope_narrower_than_request_reject():
    """FIL-AQ-05: scope=storage.read:/atlas/deep/nested/path GET /atlas/ok.txt → reject.

    WHAT: The scope covers a deep sub-path; /atlas/ok.txt is at the parent
          level and is NOT within the scope's coverage.
    WHY:  Rule 114 — the scope covers only the named path and its sub-paths;
          the requested path at the parent level is not covered.
    """
    tok = _forge().scope("storage.read:/atlas/deep/nested/path")
    assert root_ztn(tok, "/atlas/ok.txt", port=NGINX_TOKEN_PORT) == "reject"


@pytest.mark.tokenconf
def test_fil_aq_06_scope_prefix_boundary_at_vs_atlas_reject():
    """FIL-AQ-06: scope=storage.read:/at GET /atlas/ok.txt → reject (rule 117 segment boundary).

    WHAT: /atlas starts with /at but /at is not a directory-boundary ancestor of
          /atlas — the path-segment boundary rule prevents /at from covering /atlas.
    WHY:  Rule 117 — path authz is on segment boundaries: /at ≠ /atlas because
          the next character after the prefix /at is not '/' or end-of-string.
          This is the sibling-path CVE class (scitokens advisories).
    """
    tok = _forge().scope("storage.read:/at")
    assert root_ztn(tok, "/atlas/ok.txt", port=NGINX_TOKEN_PORT) == "reject"


@pytest.mark.tokenconf
def test_fil_aq_07_repeated_scope_tokens_accept():
    """FIL-AQ-07: scope="storage.read:/ storage.read:/ storage.read:/" (3× repeated) → accept.

    WHAT: The same scope token appears three times in the space-delimited scope
          claim; the union of grants is storage.read:/ regardless of duplicates.
    WHY:  Rule 98 — scope order is irrelevant (set equivalence); duplicate scope
          tokens must not cause rejection or grant escalation.
    """
    tok = _forge().generate(
        scope="storage.read:/ storage.read:/ storage.read:/")
    assert root_ztn(tok, "/test.txt", port=NGINX_TOKEN_PORT) == "accept"


@pytest.mark.tokenconf
def test_fil_aq_08_no_scope_claim_reject():
    """FIL-AQ-08: no scope claim → reject (rule 112).

    WHAT: A cryptographically valid token with no scope claim at all.
    WHY:  Rule 112 — storage access requires an explicit storage.* scope; absence
          of scope means no storage permission on any path.
    """
    tok = _forge().no_scope()
    assert root_ztn(tok, "/test.txt", port=NGINX_TOKEN_PORT) == "reject"


@pytest.mark.tokenconf
def test_fil_aq_09_three_path_scope_get_atlas_accept():
    """FIL-AQ-09: read:/atlas + read:/cms + read:/database GET /atlas/ok.txt → accept.

    WHAT: A token granting read access to three distinct VO paths; GET on the
          first path must be accepted.
    WHY:  Multi-path scope tokens are common in federated environments; each path
          grant must be independently honoured (rules 98/110/114).
    """
    tok = _forge().scope(
        "storage.read:/atlas storage.read:/cms storage.read:/database")
    assert root_ztn(tok, "/atlas/ok.txt", port=NGINX_TOKEN_PORT) == "accept"


@pytest.mark.tokenconf
def test_fil_aq_10_three_path_scope_get_cms_accept():
    """FIL-AQ-10: read:/atlas + read:/cms + read:/database GET /cms/ok.txt → accept.

    WHAT: Same three-path token; GET on the second path must also be accepted.
    WHY:  The second path grant is independently honoured.
    """
    tok = _forge().scope(
        "storage.read:/atlas storage.read:/cms storage.read:/database")
    assert root_ztn(tok, "/cms/ok.txt", port=NGINX_TOKEN_PORT) == "accept"


@pytest.mark.tokenconf
def test_fil_aq_11_three_path_scope_get_database_accept():
    """FIL-AQ-11: read:/atlas + read:/cms + read:/database GET /database/ok.txt → accept.

    WHAT: Same three-path token; GET on the third path must be accepted.
    WHY:  Confirms the third grant in the scope set is not lost during parsing.
    """
    tok = _forge().scope(
        "storage.read:/atlas storage.read:/cms storage.read:/database")
    assert root_ztn(tok, "/database/ok.txt", port=NGINX_TOKEN_PORT) == "accept"


@pytest.mark.tokenconf
@pytest.mark.registry_server("token-strict")
def test_fil_aq_12_strict_port_accept():
    """FIL-AQ-12: read:/ GET /test.txt on strict port 11119 → accept.

    WHAT: A valid, unexpired token probed against the strict-skew port (clock
          skew = 0); token is freshly minted so it is within the zero-skew window.
    WHY:  Confirms that scope enforcement on the strict port operates normally
          for a valid token; the strict port must still accept valid tokens even
          though it rejects tokens outside the tighter skew window.
    HOW:  Probes /test.txt (the strict port serves its own data root, seeded
          with /test.txt) with a root-scoped token.
    """
    tok = _forge().scope("storage.read:/")
    assert root_ztn(tok, "/test.txt",
                    port=NGINX_TOKEN_STRICT_PORT) == "accept"


@pytest.mark.tokenconf
def test_fil_aq_13_scope_segment_boundary_test_vs_test_txt_reject():
    """FIL-AQ-13: scope=storage.read:/test GET /test.txt → reject (segment boundary rule 117).

    WHAT: /test.txt does NOT start with /test/ nor equal /test; the path
          segment after "/" is "test.txt", not "test".  The scope /test therefore
          does NOT cover /test.txt.
    WHY:  Rule 117 — the segment-boundary CVE class: /foobar must not be covered
          by a scope for /foo.  This mirrors the scitokens-cpp path-traversal
          advisories.
    """
    tok = _forge().scope("storage.read:/test")
    assert root_ztn(tok, "/test.txt", port=NGINX_TOKEN_PORT) == "reject"
