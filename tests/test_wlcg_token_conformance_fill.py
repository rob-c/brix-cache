"""WLCG token conformance — FILL matrix (size-boundary, perm×op, aud/scope, transport, negatives).

WHAT: ~65 RFC-conformance cases filling the remaining gaps across five groups:
  Group 1  FIL-SZ-*  Token-length boundary (root:// 11097, 4 cases).
           Brackets the 8192-byte limit with clear-under / just-under / just-over /
           clear-over pad values.  Runtime len() assertions guard the estimates.
  Group 2  FIL-WG-*  WebDAV permission-grant × operation matrix (port 8446, 26 cases).
           For each of six scope grants (read/write/create/modify/stage/read+write)
           probes both GET and PUT on /atlas paths plus out-of-path, root-scope, and
           cross-grant variants to confirm scope-enforced read/write isolation.
  Group 3  FIL-AQ-*  Audience and scope variants (root:// 11097, 15 cases).
           Multi-element aud arrays, duplicate elements, trailing-space rejection,
           prefix-boundary /at≠/atlas, deep-subpath narrowing, repeated scopes,
           3-path multi-grant, strict-port, segment-boundary, and groups coexistence.
  Group 4  FIL-NC-*  Per-port no-credential / bad-credential negatives (12 cases).
           Non-JWT strings, empty headers, wrong auth schemes, and malformed payloads
           across root:// 11097, strict 11119, WebDAV 8446, and S3 9002.
  Group 5  FIL-QT-*  Query-token transport variants on WebDAV 8446 (8 cases).
           RFC 6750 §2.3 query-parameter delivery via ?authz= and ?access_token=;
           raw vs. "Bearer " prefix; lowercase "bearer " case-insensitivity; and
           query-path scope enforcement.

WHY: Each case targets a distinct rule/boundary: §4.1.3 aud array membership,
     §3.3 scope space-delimited / segment-boundary, §2.3 Bearer transport, §3.1
     size limits, and the WLCG storage-scope grant table (read/write/create/modify/stage).
     The suite is additive — no case is a trivial duplicate of an existing PAR/WR/BEAR row.

HOW: Pure forge+assert; no JSON manifest required.  Data files are provisioned
     idempotently in both DATA_ROOT (root:// 11097) and data-webdav-token (WebDAV 8446)
     via _ensure_fill_data().  PUT write-test paths include a sequential index to avoid
     cross-test collisions; a yield fixture removes them after each test.
"""

import os
import sys

import pytest
import requests
import urllib3

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from settings import (
    DATA_ROOT,
    NGINX_TOKEN_PORT,
    NGINX_TOKEN_STRICT_PORT,
    NGINX_WEBDAV_TOKEN_PORT,
    NGINX_S3_TOKEN_PORT,
    S3_BUCKET,
    SERVER_HOST,
    TEST_ROOT,
    TOKENS_DIR,
)
from tokenforge import TokenForge
from lib.tokenconf import (
    ensure_conformance_data,
    root_ztn,
    webdav_bearer,
    s3_bearer,
    webdav_query_token,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Data provisioning
#
# The fill-matrix tests touch both the root:// data root (DATA_ROOT) and the
# dedicated WebDAV-token data root (data-webdav-token).  Provisioned once per
# test via the autouse fixture; idempotent.
# ---------------------------------------------------------------------------

_FILL_DATA_ROOT = os.path.join(TEST_ROOT, "data-webdav-token")

_FILL_FILES = {
    "test.txt":       b"hello from nginx-xrootd\n",
    "atlas/ok.txt":   b"atlasfile\n",
    "cms/ok.txt":     b"cmsfile\n",
    "database/ok.txt": b"dbfile\n",
}


def _ensure_fill_data():
    """Provision fixture files in both data roots.

    WHAT: Creates test.txt, atlas/ok.txt, cms/ok.txt, database/ok.txt in
          DATA_ROOT and data-webdav-token if absent.
    WHY:  Accept-path tests must land on real files so auth acceptance is not
          confused with a 404 not-found response.
    HOW:  Idempotent; skips existing files; creates parent directories.
    """
    for rel, body in _FILL_FILES.items():
        for root in (DATA_ROOT, _FILL_DATA_ROOT):
            path = os.path.join(root, rel)
            if os.path.exists(path):
                continue
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(body)


@pytest.fixture(autouse=True)
def _provision(request):
    """Idempotently provision fixtures before every test; clean up write targets after.

    Write-test targets follow the pattern /atlas/wg_fill_NN.txt in
    data-webdav-token.  The finalizer removes any that exist so reruns start
    clean without requiring a full fleet restart.
    """
    ensure_conformance_data()
    _ensure_fill_data()
    yield
    # Remove write-test artefacts from the WebDAV data root.
    atlas_dir = os.path.join(_FILL_DATA_ROOT, "atlas")
    cms_dir = os.path.join(_FILL_DATA_ROOT, "cms")
    for d in (atlas_dir, cms_dir, _FILL_DATA_ROOT):
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            if name.startswith("wg_fill_"):
                try:
                    os.unlink(os.path.join(d, name))
                except OSError:
                    pass


def _forge():
    """Return a TokenForge backed by the fleet token directory."""
    return TokenForge(TOKENS_DIR)


# ===========================================================================
# Group 1 — Token-length boundary (root:// 11097)
#
# Brackets the 8192-byte JWT size limit implemented in validate.c.
# Runtime len() assertions confirm the pad values land on the expected side.
# ===========================================================================

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
def test_fil_wg_03_write_atlas_get_reject():
    """FIL-WG-03: storage.write:/atlas GET /atlas/ok.txt → reject.

    WHAT: A write-only token (no read scope) must NOT grant GET access.
    WHY:  WLCG scopes are orthogonal; write does not imply read (rule 116).
    """
    tok = _forge().scope("storage.write:/atlas")
    assert webdav_bearer(tok, "/atlas/ok.txt", write=False,
                         port=NGINX_WEBDAV_TOKEN_PORT) == "reject"


@pytest.mark.tokenconf
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

@pytest.mark.tokenconf
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
def test_fil_nc_06_strict_port_no_credential_reject():
    """FIL-NC-06: strict port 11119 empty-string token → reject.

    WHAT: The strict zero-skew port must also reject an empty credential;
          clock-skew settings do not affect the credential-presence check.
    WHY:  Confirms that the strict port applies the same baseline token
          validation as the standard token port.
    """
    assert root_ztn("", "/test.txt", port=NGINX_TOKEN_STRICT_PORT) == "reject"


@pytest.mark.tokenconf
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


@pytest.mark.tokenconf
def test_fil_qt_08_query_no_scope_token_reject():
    """FIL-QT-08: ?authz=<no-scope token> on WebDAV 8446 → reject (rule 112).

    WHAT: A token with no scope claim delivered via query parameter.
    WHY:  Rule 112 — storage access requires an explicit storage.* scope; the
          absence of scope must cause rejection regardless of the transport method.
    """
    tok = _forge().no_scope()
    result = webdav_query_token(tok, path="/test.txt",
                                param="authz",
                                port=NGINX_WEBDAV_TOKEN_PORT)
    assert result == "reject"
