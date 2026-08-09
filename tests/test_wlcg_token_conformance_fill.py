from split_continuation import reexport as _reexport
_reexport(globals(), "_test_wlcg_token_conformance_fill_helpers")

@pytest.mark.tokenconf
def test_fil_sz_01_clearly_under_accept():
    """FIL-SZ-01: oversized(2000) on root:// 11097 → accept.

    WHAT: A moderately padded token must be accepted by the root:// enforcing
          port.
    WHY:  Establishes the accept baseline for the size-boundary group; confirms
          that moderate-length tokens are not incorrectly rejected.
    HOW:  oversized(2000) → ~3.3 KB token, decoded payload well under the
          effective ~4096-byte payload buffer (pay_json[4096] in validate.c —
          the true payload ceiling, distinct from the 8192-byte raw-token guard).
    """
    forge = _forge()
    tok = forge.oversized(2000)
    assert root_ztn(tok, "/test.txt", port=NGINX_TOKEN_PORT) == "accept"


@pytest.mark.tokenconf
def test_fil_sz_02_near_under_accept():
    """FIL-SZ-02: oversized(3400) on root:// 11097 → accept (near payload limit).

    WHAT: A token whose decoded payload is just under the effective ~4096-byte
          payload buffer must still be accepted.
    WHY:  Tests the boundary from the accept side; legitimate large tokens (e.g.
          rich wlcg.groups payloads) must not be rejected prematurely.
    HOW:  oversized(3400) → ~5.2 KB token, decoded payload just under 4096.
          NOTE: the effective payload ceiling is the pay_json[4096] buffer in
          validate.c (~5.4 KB encoded token), NOT the 8192-byte raw-token guard —
          a documented implementation constraint (a token under 8192 total but
          with a >4 KB decoded payload is rejected).
    """
    forge = _forge()
    tok = forge.oversized(3400)
    assert root_ztn(tok, "/test.txt", port=NGINX_TOKEN_PORT) == "accept"


@pytest.mark.tokenconf
def test_fil_sz_03_near_over_reject():
    """FIL-SZ-03: oversized(5800) on root:// 11097 → reject (just over ~8380).

    WHAT: A token padded to ~8379 bytes — just over the 8192-byte limit — must
          be rejected, confirming the ceiling is enforced.
    WHY:  Demonstrates the limit is tight from the reject side; DoS-class tokens
          only slightly over the ceiling must be blocked on root://.
    HOW:  oversized(5800); estimate: ~8379 chars.
    """
    forge = _forge()
    tok = forge.oversized(5800)
    assert len(tok) > 8192, (
        f"Test setup: oversized(5800) gave len={len(tok)}, expected > 8192"
    )
    assert root_ztn(tok, "/test.txt", port=NGINX_TOKEN_PORT) == "reject"


@pytest.mark.tokenconf
def test_fil_sz_04_clearly_over_reject():
    """FIL-SZ-04: oversized(7000) on root:// 11097 → reject (clearly over ~9900).

    WHAT: A token padded to ~9900 bytes — far beyond the 8192-byte ceiling.
    WHY:  Defensive depth: even a grossly oversized token must be cleanly
          rejected without crash, hang, or partial processing on root://.
    HOW:  oversized(7000); estimate: ~9912 chars.
    """
    forge = _forge()
    tok = forge.oversized(7000)
    assert len(tok) > 8192
    assert root_ztn(tok, "/test.txt", port=NGINX_TOKEN_PORT) == "reject"


# ===========================================================================
# Group 2 — WebDAV permission-grant × operation matrix (port 8446)
#
# Six WLCG scope grants × two operations (GET = read, PUT = write):
#   storage.read    → read grant, no write
#   storage.write   → write grant, no read
#   storage.create  → write grant (new objects), no read
#   storage.modify  → write grant, no read
#   storage.stage   → read grant (bring-online semantics), no write
#   read + write    → both grants
# Plus out-of-path, root-scope, and cross-grant variants.
# ===========================================================================

# --- storage.read:/atlas (read accept, write reject) ---

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_01_read_atlas_get_accept():
    """FIL-WG-01: storage.read:/atlas GET /atlas/ok.txt → accept (rule 114).

    WHAT: A read-scoped token covering /atlas grants GET access to any path
          under that prefix.
    WHY:  Rule 114 — storage.read:<PATH> covers PATH and its sub-paths; a GET
          within the scope must be accepted.
    """
    tok = _forge().scope("storage.read:/atlas")
    assert webdav_bearer(tok, "/atlas/ok.txt", write=False,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "accept"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_02_read_atlas_put_reject():
    """FIL-WG-02: storage.read:/atlas PUT /atlas/wg_fill_02.txt → reject (rule 115).

    WHAT: A read-only token must NOT grant write access to any path.
    WHY:  Rule 115 — storage.read is strictly a read capability; granting write
          via a read token would be a critical authorization bypass.
    """
    tok = _forge().scope("storage.read:/atlas")
    assert webdav_bearer(tok, "/atlas/wg_fill_02.txt", write=True,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "reject"


# --- storage.write:/atlas (write accept, read reject) ---

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_03_write_atlas_get_reject():
    """FIL-WG-03: storage.write:/atlas GET /atlas/ok.txt → reject.

    WHAT: A write-only token (no read scope) must NOT grant GET access.
    WHY:  WLCG scopes are orthogonal; write does not imply read (rule 116).
    """
    tok = _forge().scope("storage.write:/atlas")
    assert webdav_bearer(tok, "/atlas/ok.txt", write=False,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "reject"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_04_write_atlas_put_accept():
    """FIL-WG-04: storage.write:/atlas PUT /atlas/wg_fill_04.txt → accept.

    WHAT: A write-scoped token covering /atlas grants PUT access within that prefix.
    WHY:  Positive write-scope case for storage.write (distinct from storage.create
          and storage.modify which are verified separately).
    """
    tok = _forge().scope("storage.write:/atlas")
    assert webdav_bearer(tok, "/atlas/wg_fill_04.txt", write=True,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "accept"


# --- storage.create:/atlas (create = write accept, read reject) ---

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_05_create_atlas_get_reject():
    """FIL-WG-05: storage.create:/atlas GET /atlas/ok.txt → reject (rule 115).

    WHAT: The create scope authorises creating new objects; it does NOT imply
          read access (rule 115: create ≠ read).
    WHY:  Ingest-only workflows receive create-scoped tokens; they must not
          accidentally gain read access to existing objects.
    """
    tok = _forge().scope("storage.create:/atlas")
    assert webdav_bearer(tok, "/atlas/ok.txt", write=False,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "reject"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_06_create_atlas_put_accept():
    """FIL-WG-06: storage.create:/atlas PUT /atlas/wg_fill_06.txt → accept.

    WHAT: The create scope grants write access for new object creation.
    WHY:  scopes.c maps storage.create to the write gate (brix_token_check_write
          checks write || create || modify); PUT with a create token must accept.
    """
    tok = _forge().scope("storage.create:/atlas")
    assert webdav_bearer(tok, "/atlas/wg_fill_06.txt", write=True,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "accept"


# --- storage.modify:/atlas (modify = write accept, read reject) ---

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_07_modify_atlas_get_reject():
    """FIL-WG-07: storage.modify:/atlas GET /atlas/ok.txt → reject (rule 116).

    WHAT: storage.modify authorises overwriting or modifying existing objects;
          it does NOT imply read access.
    WHY:  Rule 116 — modify and stage are distinct from read; modify tokens are
          issued by macaroon-to-JWT gateways for tape system writes.
    """
    tok = _forge().scope("storage.modify:/atlas")
    assert webdav_bearer(tok, "/atlas/ok.txt", write=False,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "reject"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_08_modify_atlas_put_accept():
    """FIL-WG-08: storage.modify:/atlas PUT /atlas/wg_fill_08.txt → accept.

    WHAT: storage.modify maps to the write gate alongside write/create
          (brix_token_check_write honours the modify flag — recently fixed from
          a bug where modify was parsed but never consulted).
    WHY:  Regression-guards the modify fix; a failing case here means the WLCG
          macaroon MANAGE capability is not honoured via JWT.
    """
    tok = _forge().scope("storage.modify:/atlas")
    assert webdav_bearer(tok, "/atlas/wg_fill_08.txt", write=True,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "accept"


# --- storage.stage:/atlas (stage = read accept per WLCG, write reject) ---

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_09_stage_atlas_get_accept():
    """FIL-WG-09: storage.stage:/atlas GET /atlas/ok.txt → accept (bring-online = read).

    WHAT: scopes.c maps storage.stage to read=1 (WLCG staging semantics: a
          staged file is read-accessible but not writable until committed).
          GET with a stage token must be accepted.
    WHY:  Rule 116 — storage.stage distinguishes the bring-online operation
          from pure storage.read while granting equivalent read-visibility.
    """
    tok = _forge().scope("storage.stage:/atlas")
    assert webdav_bearer(tok, "/atlas/ok.txt", write=False,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "accept"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_10_stage_atlas_put_reject():
    """FIL-WG-10: storage.stage:/atlas PUT /atlas/wg_fill_10.txt → reject.

    WHAT: stage grants read visibility only (mapped to read=1 in scopes.c);
          brix_token_check_write checks write || create || modify, and stage
          sets none of those flags.
    WHY:  A stage token must not grant write access; storage is brought online
          for reading only.
    """
    tok = _forge().scope("storage.stage:/atlas")
    assert webdav_bearer(tok, "/atlas/wg_fill_10.txt", write=True,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "reject"


# --- storage.read:/atlas storage.write:/atlas (both) ---

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_11_read_and_write_atlas_get_accept():
    """FIL-WG-11: read:/atlas + write:/atlas combined GET /atlas/ok.txt → accept.

    WHAT: A token bearing both read and write grants on /atlas must accept GET.
    WHY:  Combined-scope tokens are standard in interactive workflows where the
          client both reads and writes data; the read component must be active.
    """
    tok = _forge().scope("storage.read:/atlas storage.write:/atlas")
    assert webdav_bearer(tok, "/atlas/ok.txt", write=False,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "accept"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_12_read_and_write_atlas_put_accept():
    """FIL-WG-12: read:/atlas + write:/atlas combined PUT /atlas/wg_fill_12.txt → accept.

    WHAT: A combined read+write token must also accept PUT within its scope.
    WHY:  The write component of the combined scope must be honoured independently
          of the read component.
    """
    tok = _forge().scope("storage.read:/atlas storage.write:/atlas")
    assert webdav_bearer(tok, "/atlas/wg_fill_12.txt", write=True,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "accept"


# --- Out-of-path variants: grant on /atlas, operation on /cms or /test.txt ---

@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_13_read_atlas_get_cms_reject():
    """FIL-WG-13: storage.read:/atlas GET /cms/ok.txt → reject (scope boundary).

    WHAT: The token's read scope covers /atlas only; /cms is outside that
          prefix — the GET must be rejected.
    WHY:  Rule 114 — the scope prefix is a path-boundary guard, not a substring
          match; /atlas ≠ /cms.
    """
    tok = _forge().scope("storage.read:/atlas")
    assert webdav_bearer(tok, "/cms/ok.txt", write=False,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "reject"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_14_write_atlas_put_cms_reject():
    """FIL-WG-14: storage.write:/atlas PUT /cms/wg_fill_14.txt → reject (scope boundary).

    WHAT: Write scope on /atlas must not leak to /cms writes.
    WHY:  Cross-VO boundary write: a dataset owner with write access to /atlas
          must not accidentally write to /cms.
    """
    tok = _forge().scope("storage.write:/atlas")
    assert webdav_bearer(tok, "/cms/wg_fill_14.txt", write=True,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "reject"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_15_read_atlas_get_testfile_reject():
    """FIL-WG-15: storage.read:/atlas GET /test.txt → reject (different root namespace).

    WHAT: /test.txt is outside the /atlas scope prefix entirely.
    WHY:  Tests that scope enforcement applies even to paths in the server root
          that share no common prefix with the scope path.
    """
    tok = _forge().scope("storage.read:/atlas")
    assert webdav_bearer(tok, "/test.txt", write=False,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "reject"


@pytest.mark.tokenconf
@pytest.mark.registry_server("webdav-token")
def test_fil_wg_16_create_atlas_put_cms_reject():
    """FIL-WG-16: storage.create:/atlas PUT /cms/wg_fill_16.txt → reject.

    WHAT: A create-scoped token restricted to /atlas must not grant create
          access to /cms.
    WHY:  Orthogonal scope-path enforcement: the path component of the scope
          must be respected regardless of the permission type.
    """
    tok = _forge().scope("storage.create:/atlas")
    assert webdav_bearer(tok, "/cms/wg_fill_16.txt", write=True,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "reject"


# --- Root scope ---
