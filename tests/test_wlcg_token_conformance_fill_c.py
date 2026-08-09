from split_continuation import reexport as _reexport
_reexport(globals(), "_test_wlcg_token_conformance_fill_helpers")

@pytest.mark.tokenconf
def test_fil_aq_14_root_scope_read_any_path_accept():
    """FIL-AQ-14: scope=storage.read:/ GET /atlas/ok.txt → accept (rule 114 root coverage).

    WHAT: A root-scoped read token covers any sub-path, including /atlas/ok.txt.
    WHY:  Rule 114 — storage.read:/ is the broadest possible read grant; every
          sub-path is covered.
    """
    tok = _forge().scope("storage.read:/")
    assert root_ztn(tok, "/atlas/ok.txt", port=NGINX_TOKEN_PORT) == "accept"


@pytest.mark.tokenconf
def test_fil_aq_15_groups_plus_read_scope_accept():
    """FIL-AQ-15: wlcg.groups + storage.read:/ → accept (groups don't block storage).

    WHAT: A token carrying both a wlcg.groups claim and a storage.read:/ scope.
    WHY:  Rule 109 — capability (scope) and attribute (wlcg.groups) models are
          handled distinctly; the presence of wlcg.groups MUST NOT interfere with
          scope-based storage access decisions (rule 120).
    """
    tok = _forge().groups(["/atlas/production", "/atlas/admin"])
    assert root_ztn(tok, "/test.txt", port=NGINX_TOKEN_PORT) == "accept"


# ===========================================================================
# Group 4 — Per-port no-credential / bad-credential negatives
# ===========================================================================

@pytest.mark.tokenconf
def test_fil_nc_01_root_random_string_reject():
    """FIL-NC-01: root:// 11097 with non-JWT random string → reject.

    WHAT: Sending "not-a-jwt-at-all" (no dots, no base64url segments) as the
          ztn credential must be rejected immediately.
    WHY:  RFC 7515 §7.1 / rule 24 — a JWS compact serialization MUST have
          exactly three base64url segments separated by two dots.
    """
    assert root_ztn("not-a-jwt-at-all", "/test.txt",
                    port=NGINX_TOKEN_PORT) == "reject"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_nc_02_webdav_no_auth_header_reject():
    """FIL-NC-02: WebDAV 8446 GET /test.txt with no Authorization header → reject.

    WHAT: A GET request to the enforcing WebDAV port with no Authorization
          header at all; the server must require authentication.
    WHY:  RFC 6750 §2 / rule 86 — no credential on a protected resource → 401
          + WWW-Authenticate: Bearer.  brix_webdav_auth=required enforces this.
    """
    url = f"https://{SERVER_HOST}:{NGINX_WEBDAV_TOKEN_PORT}/test.txt"
    resp = requests.get(url, verify=False, timeout=5)
    assert resp.status_code in (401, 403), (
        f"Expected 401/403 for no-credential, got {resp.status_code}")


@pytest.mark.tokenconf
@pytest.mark.registry_server("s3-token")
def test_fil_nc_03_s3_no_auth_header_reject():
    """FIL-NC-03: S3 9002 GET /test.txt with no Authorization header → reject.

    WHAT: A GET request to the enforcing S3 bearer-token port with no
          Authorization header; the server must deny without a valid token.
    WHY:  brix_s3_token=on enforces token auth on port 9002; unauthenticated
          access must be rejected.
    """
    url = f"http://{SERVER_HOST}:{NGINX_S3_TOKEN_PORT}/{S3_BUCKET}/test.txt"
    resp = requests.get(url, timeout=5)
    assert resp.status_code in (400, 401, 403), (
        f"Expected 400/401/403 for no-credential on S3 enforcing port, "
        f"got {resp.status_code}")


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_nc_04_webdav_bearer_empty_token_reject():
    """FIL-NC-04: WebDAV 8446 Authorization: Bearer (empty string after scheme) → reject.

    WHAT: The Authorization header carries "Bearer " with no token following,
          making the token value an empty string.
    WHY:  RFC 6750 §2.1 / rule 82 — the b64token charset requires at least one
          character; an empty token is malformed and must be rejected.
    """
    url = f"https://{SERVER_HOST}:{NGINX_WEBDAV_TOKEN_PORT}/test.txt"
    resp = requests.get(url, headers={"Authorization": "Bearer "},
                        verify=False, timeout=5)
    assert resp.status_code not in (200, 206), (
        f"Expected non-200 for empty Bearer token, got {resp.status_code}")


@pytest.mark.tokenconf
def test_fil_nc_05_root_empty_string_token_reject():
    """FIL-NC-05: root:// 11097 empty-string "" as ztn credential → reject.

    WHAT: Sending an empty byte sequence as the ztn auth credential must be
          rejected cleanly without a crash or hang.
    WHY:  Defensive robustness: an empty credential is not a valid JWT and must
          not be accepted.
    """
    assert root_ztn("", "/test.txt", port=NGINX_TOKEN_PORT) == "reject"


@pytest.mark.tokenconf
@pytest.mark.registry_server("token-strict")
def test_fil_nc_06_strict_port_no_credential_reject():
    """FIL-NC-06: strict port 11119 empty-string token → reject.

    WHAT: The strict zero-skew port must also reject an empty credential;
          clock-skew settings do not affect the credential-presence check.
    WHY:  Confirms that the strict port applies the same baseline token
          validation as the standard token port.
    """
    assert root_ztn("", "/test.txt", port=NGINX_TOKEN_STRICT_PORT) == "reject"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_nc_07_webdav_wrong_auth_scheme_reject():
    """FIL-NC-07: WebDAV 8446 Authorization: Basic dXNlcjpwYXNz → reject (wrong scheme).

    WHAT: The request carries a Basic auth header rather than a Bearer token.
    WHY:  RFC 6750 / rule 80 — the server is a Bearer-only endpoint; a Basic
          credential is not a valid JWT and must be rejected.
    """
    url = f"https://{SERVER_HOST}:{NGINX_WEBDAV_TOKEN_PORT}/test.txt"
    resp = requests.get(
        url,
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
        verify=False, timeout=5)
    assert resp.status_code not in (200, 206), (
        f"Expected non-200 for Basic auth on Bearer endpoint, got {resp.status_code}")


@pytest.mark.tokenconf
@pytest.mark.registry_server("s3-token")
def test_fil_nc_08_s3_bearer_garbage_token_reject():
    """FIL-NC-08: S3 9002 Authorization: Bearer garbage.not.jwt → reject.

    WHAT: The S3 bearer-token port receives three dot-separated segments that
          are not valid base64url JWT; signature verification must fail.
    WHY:  The token has the structural shape of a JWT (three segments) but the
          payload and signature are not valid; the verifier must reject.
    """
    result = s3_bearer("garbage.not.jwt", f"{S3_BUCKET}/test.txt",
                       write=False, port=NGINX_S3_TOKEN_PORT)
    assert result == "reject"


@pytest.mark.tokenconf
def test_fil_nc_09_root_three_junk_segments_reject():
    """FIL-NC-09: root:// 11097 "a.b.c" (three segments, junk content) → reject.

    WHAT: Three dot-separated segments that look like a compact JWS but contain
          non-base64url content; base64 decode or JSON parse must fail.
    WHY:  Rule 20 — header and payload MUST each be valid UTF-8 JSON objects;
          a single character segment fails this requirement.
    """
    assert root_ztn("a.b.c", "/test.txt", port=NGINX_TOKEN_PORT) == "reject"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_nc_10_webdav_bearer_literal_null_reject():
    """FIL-NC-10: WebDAV 8446 Authorization: Bearer null → reject.

    WHAT: The token value is the literal string "null" — three characters,
          one segment, no dots.
    WHY:  "null" is not a valid compact JWS (rule 24: requires two dots); the
          server must reject without crashing or treating it as an absent token.
    """
    url = f"https://{SERVER_HOST}:{NGINX_WEBDAV_TOKEN_PORT}/test.txt"
    resp = requests.get(url, headers={"Authorization": "Bearer null"},
                        verify=False, timeout=5)
    assert resp.status_code not in (200, 206)


@pytest.mark.tokenconf
def test_fil_nc_11_root_alg_none_token_reject():
    """FIL-NC-11: root:// 11097 alg=none token → reject (SEC, rule 19/rule 59).

    WHAT: A three-segment compact JWS with alg=none and an empty signature
          probed against the root:// enforcing port on 11097.
    WHY:  PAR-02 covers alg=none on WebDAV and S3; this case confirms the root://
          path also rejects unsigned tokens independently (rule 19 / RFC 8725 §3.2).
    """
    tok = _forge().alg_none()
    assert root_ztn(tok, "/test.txt", port=NGINX_TOKEN_PORT) == "reject"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_nc_12_webdav_truncated_sig_reject():
    """FIL-NC-12: WebDAV 8446 truncated-signature token → reject (rule 41).

    WHAT: A structurally valid JWT whose signature segment has been cut to 50%
          of its original length — the resulting partial RSA signature never
          verifies.
    WHY:  PAR-12 covers truncated sig on WebDAV and S3 via parity; this confirms
          the same rejection on the dedicated WebDAV enforcing port 8446 using
          the helper directly.
    """
    tok = _forge().truncated_sig()
    result = webdav_bearer(tok, "/test.txt", write=False,
                           port=NGINX_WEBDAV_TOKEN_PORT)
    assert result == "reject"


# ===========================================================================
# Group 5 — Query-token transport variants on WebDAV 8446 (RFC 6750 §2.3)
# ===========================================================================

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_qt_01_query_authz_bearer_prefix_accept():
    """FIL-QT-01: ?authz=Bearer%20<token> on WebDAV 8446 → accept.

    WHAT: Valid token delivered via the ?authz= query parameter with a "Bearer "
          prefix (URL-encoded as %20).
    WHY:  RFC 6750 §2.3 — query-string transport is supported by the server via
          brix_http_query_token; the server must accept a valid token regardless
          of whether it arrives in the Authorization header or a query param.
    """
    tok = _forge().generate(scope="storage.read:/")
    result = webdav_query_token(tok, path="/test.txt",
                                param="authz", prefix="Bearer ",
                                port=NGINX_WEBDAV_TOKEN_PORT)
    assert result == "accept"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_qt_02_query_authz_raw_token_accept():
    """FIL-QT-02: ?authz=<raw-token> (no Bearer prefix) on WebDAV 8446 → accept.

    WHAT: Valid token delivered via ?authz= without any "Bearer " prefix — just
          the raw JWT string.
    WHY:  The server's query-token extraction path should accept a bare JWT
          (no scheme prefix) as well as a "Bearer " prefixed value; this tests
          the prefix-stripping logic.
    """
    tok = _forge().generate(scope="storage.read:/")
    result = webdav_query_token(tok, path="/test.txt",
                                param="authz", prefix="",
                                port=NGINX_WEBDAV_TOKEN_PORT)
    assert result == "accept"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_qt_03_query_access_token_raw_accept():
    """FIL-QT-03: ?access_token=<raw-token> on WebDAV 8446 → accept.

    WHAT: Valid token delivered via the ?access_token= parameter (RFC 6750
          standard parameter name) without a "Bearer " prefix.
    WHY:  RFC 6750 §2.3 — the access_token form-parameter is the specified
          query-string delivery mechanism; the server must support it.
    """
    tok = _forge().generate(scope="storage.read:/")
    result = webdav_query_token(tok, path="/test.txt",
                                param="access_token", prefix="",
                                port=NGINX_WEBDAV_TOKEN_PORT)
    assert result == "accept"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_qt_04_query_alg_none_reject():
    """FIL-QT-04: ?authz=<alg-none token> on WebDAV 8446 → reject.

    WHAT: An unsigned alg=none token delivered via the query parameter.
    WHY:  Token validation applies the same rules regardless of the transport
          method; rule 19/59 — alg=none must be rejected whether it arrives in
          a header or a query param.
    """
    tok = _forge().alg_none()
    result = webdav_query_token(tok, path="/test.txt",
                                param="authz",
                                port=NGINX_WEBDAV_TOKEN_PORT)
    assert result == "reject"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_qt_05_query_expired_token_reject():
    """FIL-QT-05: ?authz=<expired token> on WebDAV 8446 → reject (rule 10).

    WHAT: A token that expired 3600 s ago, delivered via query parameter.
    WHY:  RFC 7519 §4.1.4 / rule 10 — expiry check applies identically to all
          transport methods; an expired query-delivered token must be rejected.
    """
    tok = _forge().temporal(-3600)
    result = webdav_query_token(tok, path="/test.txt",
                                param="authz",
                                port=NGINX_WEBDAV_TOKEN_PORT)
    assert result == "reject"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_qt_06_query_scope_enforced_on_path_reject():
    """FIL-QT-06: ?authz=<read:/atlas token> path=/cms/ok.txt → reject (scope on query).

    WHAT: A token scoped to read:/atlas, delivered via query param against
          /cms/ok.txt; the scope check applies to the URL path, not the
          token delivery mechanism.
    WHY:  Rule 114 — scope boundary is path-based and applies uniformly; an
          atlas-only token must be rejected for /cms/ok.txt via any transport.
    """
    tok = _forge().scope("storage.read:/atlas")
    result = webdav_query_token(tok, path="/cms/ok.txt",
                                param="authz",
                                port=NGINX_WEBDAV_TOKEN_PORT)
    assert result == "reject"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_qt_07_query_lowercase_bearer_prefix_accept():
    """FIL-QT-07: ?authz=bearer%20<token> (lowercase "bearer ") → accept (rule 81).

    WHAT: Token in query param with a lowercase "bearer " prefix; RFC 6750
          §2.1 / rule 81 specifies Bearer scheme name matching is case-insensitive.
    WHY:  The server's query-token extractor should strip a case-insensitive
          "Bearer " prefix; failing to do so would reject valid client requests.
    """
    tok = _forge().generate(scope="storage.read:/")
    result = webdav_query_token(tok, path="/test.txt",
                                param="authz", prefix="bearer ",
                                port=NGINX_WEBDAV_TOKEN_PORT)
    assert result in ("accept", "reject"), (
        "Expected accept (rule 81) or reject if lowercase stripping not "
        "implemented; mark xfail if consistently reject and deemed acceptable")
    # NOTE: RFC 6750 §2.1 says Bearer scheme is case-insensitive. A conformant
    # implementation must accept.  If this fails, it surfaces a known divergence
    # from rule 81 for the query-token path.
    assert result == "accept"
