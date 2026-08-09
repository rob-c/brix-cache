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
