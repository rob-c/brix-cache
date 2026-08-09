"""WLCG token conformance — PAR family (cross-protocol parity, WebDAV + S3).

WHAT: Verifies 20 RFC/WLCG rules uniformly across the two HTTP enforcing token
      ports — WebDAV HTTPS 8446 (``NGINX_WEBDAV_TOKEN_PORT``) and S3 HTTP 9002
      (``NGINX_S3_TOKEN_PORT``).  Each test is parametrized over proto in
      ["webdav","s3"] so every rule runs twice and produces 40 tests in total.

WHY:  The same token validation pipeline (validate.c + scopes.c) backs all three
      protocol stacks.  Recently landed fixes — crit-header rejection, fractional
      NumericDate acceptance, WLCG aud wildcard acceptance — must hold uniformly
      across protocols.  This suite is the cross-protocol oracle.

HOW:  ``probe(proto, token, path, write)`` dispatches to webdav_bearer or
      s3_bearer with the enforcing port.  Cases are pure forge+assert; no JSON
      manifest is needed.  Data files (/test.txt, /atlas/ok.txt, /cms/ok.txt)
      are provisioned idempotently in both server data roots via
      ``_ensure_parity_data()``.

Fixed behaviours asserted as plain (non-xfail) PASSes:
  PAR-08  WLCG aud wildcard ``https://wlcg.cern.ch/jwt/v1/any`` → accept
  PAR-09  crit unknown extension → reject  (RFC 7515 §4.1.11)
  PAR-10  fractional NumericDate exp → accept  (RFC 7519 §2)
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
    SERVER_HOST,
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
# Data provisioning
#
# Both enforcing HTTP token servers expose dedicated data roots.  Provision the
# same small fixture set in each so accept-path tests land on real files.
# ---------------------------------------------------------------------------

_PAR_FIXTURE_FILES = {
    "test.txt":     b"hello from nginx-xrootd\n",
    "atlas/ok.txt": b"atlasfile\n",
    "cms/ok.txt":   b"cmsfile\n",
}

_PAR_DATA_ROOTS = [
    os.path.join(TEST_ROOT, "data-webdav-token"),
    os.path.join(TEST_ROOT, "data-s3-token"),
]


def _ensure_parity_data():
    """Provision fixture files in both HTTP token server data roots.

    WHAT: Creates test.txt, atlas/ok.txt, cms/ok.txt in data-webdav-token and
          data-s3-token if they are absent.
    WHY:  Accept-path and scope-boundary tests must land on real files so that a
          token-acceptance decision is not confused with a 404 not-found response.
    HOW:  Idempotent; skips existing files; creates parent directories.
    """
    for root in _PAR_DATA_ROOTS:
        for rel, body in _PAR_FIXTURE_FILES.items():
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
# Shared forge factory and probe dispatcher
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


# ---------------------------------------------------------------------------
# PAR-01  valid root-scoped token → accept (baseline)
# ---------------------------------------------------------------------------
