from split_continuation import reexport as _reexport
_reexport(globals(), "_test_wlcg_token_conformance_parity_helpers")

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_17_traversal_reject(proto):
    """PAR-17: scope=/atlas token, path=/atlas/../cms/ok.txt → reject (§3.5).

    WHAT: An /atlas-scoped token attempts to reach /cms/ok.txt via a dot-dot
          path traversal.  The path normalises to /cms/ok.txt before (or at)
          the server's scope check; scope does not cover /cms → reject.
    WHY:  WLCG Token Profile §3.5 traversal defense — a dot-dot sequence must not
          allow a token to escape its scope boundary.  Both the requests HTTP
          client and nginx normalise the path before the handler runs, so the
          effective path is /cms/ok.txt, which is outside /atlas scope → reject.
    """
    tok = _forge().scope("storage.read:/atlas")
    assert probe(proto, tok, path="/atlas/../cms/ok.txt") == "reject"


# ---------------------------------------------------------------------------
# PAR-18  oversized token → reject
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_18_oversized_reject(proto):
    """PAR-18: token with 9000-byte pad claim → reject (token size limit).

    WHAT: The JWT payload carries a large padding claim that pushes the total
          token length well beyond the 8192-byte limit enforced in validate.c.
    WHY:  A size limit prevents denial-of-service via excessively large JWTs that
          consume CPU (base64 decode + RSA verify) for tokens that can never be
          legitimate.  Uniform rejection across protocols is required.
    """
    tok = _forge().oversized(9000)
    assert probe(proto, tok) == "reject"


# ---------------------------------------------------------------------------
# PAR-19  ES256 on RSA-only JWKS → reject
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_19_es256_reject(proto):
    """PAR-19: ES256 token on RSA-only JWKS → reject (no matching key).

    WHAT: The token is signed with an EC P-256 key (kid=ec-key-1).  Ports 8446
          and 9002 serve the MAIN RSA-only JWKS (jwks.json, one RSA entry,
          kid=test-key-1).  The ec-key-1 kid is absent → no key match → reject.
    WHY:  EC accept is confirmed on root:// multikey port 11250 (where the JWKS
          includes both RSA and EC entries).  HTTP token ports are RSA-only by
          design; rejecting an unknown kid is the correct JWKS lookup failure
          path, not an algorithm policy failure.
    NOTE: HTTP token ports serve RSA-only JWKS; ES256 accept is covered on
          root:// multikey 11250.
    """
    tok = _forge().es256()
    assert probe(proto, tok) == "reject"


# ---------------------------------------------------------------------------
# PAR-20  unknown extra claims → accept (RFC 7519 §4.3)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_par_20_unknown_claims_accept(proto):
    """PAR-20: token with extra unknown claims (custom_x, https://ex/z) → accept.

    WHAT: RFC 7519 §4.3 / rule 16 — unrecognised claim names MUST be ignored;
          their presence MUST NOT cause rejection.  An implementation that errors
          on unknown claim names would break forward compatibility.
    WHY:  WLCG tokens routinely carry additional VO or service-specific claims
          (wlcg.groups, VO extensions, etc.); rejecting unknown claims is
          operationally disruptive and non-conformant.
    """
    tok = _forge().unknown_claims_ok()
    assert probe(proto, tok) == "accept"
