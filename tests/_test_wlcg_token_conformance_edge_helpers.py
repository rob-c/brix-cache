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
