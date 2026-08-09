"""WLCG token conformance — EXT family (extended cross-protocol matrix,
WebDAV 8446 + S3 9002).

WHAT: Verifies 35 RFC/WLCG rules — six families HDR, NDT, CLM2, SCP2, ALG2,
      WLCG2 plus five extras — uniformly across the two enforcing HTTP token
      ports.  Each case is parametrized over proto in ["webdav","s3"] producing
      70 tests in total.

WHY:  Extends test_wlcg_token_conformance_parity.py (20 PAR cases) with the
      full RFC 7515/7518/7519/8725 surface that was left to the extended matrix:
      crit header sub-rules, typ variants, NumericDate edge values, CLM ordering
      constraints, scope boundary/hierarchy rules, algorithm-security cases, and
      WLCG-profile specifics.  All cases are NEW — no overlap with PAR-01..20.

HOW:  Same probe() dispatcher and _forge() factory as the PAR suite.  Data files
      (/test.txt, /atlas/ok.txt, /cms/ok.txt) provisioned idempotently by
      _ensure_parity_data().

Divergences vs RFC asserted as xfail(strict=True) with rule cites:
  CLM2-02  iat_after_exp: rule 155 — iat>exp ordering not enforced by
           validate.c; token passes temporal checks (exp within 30 s skew,
           nbf in past, iat future-ordering unchecked) → server accepts.

Note: ES256 and multi-key cases are NOT included (HTTP ports are RSA-only,
      jwks.json = one RSA entry, kid test-key-1).  EC accept is confirmed on
      root:// multikey port 11250.
"""

import os
import sys

import pytest
import urllib3

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from settings import (
    NGINX_WEBDAV_TOKEN_PORT,
    NGINX_S3_TOKEN_PORT,
    S3_BUCKET,
    TEST_ROOT,
    TOKENS_DIR,
)
from tokenforge import TokenForge
from lib.tokenconf import (
    ensure_conformance_data,
    webdav_bearer,
    s3_bearer,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Data provisioning (same roots as PAR suite)
# ---------------------------------------------------------------------------

_EXT_FIXTURE_FILES = {
    "test.txt":     b"hello from nginx-xrootd\n",
    "atlas/ok.txt": b"atlasfile\n",
    "cms/ok.txt":   b"cmsfile\n",
}

_EXT_DATA_ROOTS = [
    os.path.join(TEST_ROOT, "data-webdav-token"),
    os.path.join(TEST_ROOT, "data-s3-token"),
]


def _ensure_parity_data():
    """Provision fixture files in both HTTP token server data roots.

    WHAT: Creates test.txt, atlas/ok.txt, cms/ok.txt in data-webdav-token and
          data-s3-token if absent.
    WHY:  Accept-path and scope-boundary tests must land on real files so that
          a token-acceptance decision is not confused with a 404 not-found.
    HOW:  Idempotent; skips existing files; creates parent directories.
    """
    for root in _EXT_DATA_ROOTS:
        for rel, body in _EXT_FIXTURE_FILES.items():
            path = os.path.join(root, rel)
            if os.path.exists(path):
                continue
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(body)


@pytest.fixture(autouse=True)
def _provision():
    """Idempotently provision all fixture data before every test in this module."""
    ensure_conformance_data()
    _ensure_parity_data()


# ---------------------------------------------------------------------------
# Shared forge factory and probe dispatcher (mirrors PAR suite exactly)
# ---------------------------------------------------------------------------

def _forge():
    """Return a TokenForge loaded from the fleet token directory."""
    return TokenForge(TOKENS_DIR)


def probe(proto, token, path="/test.txt", write=False):
    """Dispatch to the enforcing token port for the given protocol.

    WHAT: Routes to webdav_bearer (8446, HTTPS) or s3_bearer (9002, HTTP) with
          the enforcing port so both checks share one call site.
    WHY:  Centralises port selection; every parametrized body calls probe() and
          asserts verdict without knowing which protocol is under test.
    HOW:  proto="webdav" → webdav_bearer with NGINX_WEBDAV_TOKEN_PORT;
          proto="s3"     → s3_bearer with NGINX_S3_TOKEN_PORT; S3 URL layout is
          /{bucket}/{key} so the key is prefixed with S3_BUCKET ("testbucket").
          write flag is forwarded unchanged.

    Args:
        proto: "webdav" or "s3".
        token: JWT string.
        path:  URL path (must start with /).
        write: If True, issue a write (PUT) probe instead of a read (GET).

    Returns:
        "accept", "reject", or "notfound".
    """
    if proto == "webdav":
        return webdav_bearer(token, path, write, port=NGINX_WEBDAV_TOKEN_PORT)
    key = f"{S3_BUCKET}/{path.lstrip('/')}"
    return s3_bearer(token, key, write, port=NGINX_S3_TOKEN_PORT)


# ===========================================================================
# HDR family — RFC 7515 header parameter rules
# ===========================================================================
