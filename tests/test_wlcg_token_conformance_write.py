"""WLCG token conformance — WR family (write-scope enforcement, WebDAV + S3).

WHAT: Verifies that write-scope rules are enforced uniformly across the two
      HTTP enforcing token ports — WebDAV HTTPS 8446 (``NGINX_WEBDAV_TOKEN_PORT``)
      and S3 HTTP 9002 (``NGINX_S3_TOKEN_PORT``).  Each test is parametrized over
      proto in ["webdav","s3"], producing 16 tests in total (8 × 2).

WHY:  Write authorization is the critical security boundary for storage systems.
      A read-only token must never grant write access (WR-03 is the key security
      case).  storage.write, storage.create, and storage.modify all grant write
      access while storage.read does not.  Both protocols must enforce this
      identically via brix_identity_check_token_scope.

HOW:  ``probe(proto, token, path, write=True)`` issues a PUT via webdav_bearer or
      s3_bearer on the enforcing port.  Write targets use distinct per-case path
      suffixes to avoid cross-test state; both data roots have allow_write on so
      PUT with a valid write-scope token succeeds.  Cleanup is best-effort via an
      autouse finalizer.

Key security case: WR-03 — storage.read:/ token PUT → reject.  A passing
read token MUST NOT be accepted for writes.
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
# Data provisioning
# ---------------------------------------------------------------------------

_WR_DATA_ROOTS = [
    os.path.join(TEST_ROOT, "data-webdav-token"),
    os.path.join(TEST_ROOT, "data-s3-token"),
]


def _ensure_write_data():
    """Ensure the target data roots exist for write tests.

    WHAT: Creates the top-level data root directories if absent.  The write test
          targets (e.g. wtest_wr01.txt) are created dynamically by the PUT
          requests themselves; only the containing directory must pre-exist.
    WHY:  PUT to a non-existent root would fail with 500 rather than 201/403,
          masking the real auth verdict.
    HOW:  os.makedirs(exist_ok=True) is safe on existing paths.
    """
    for root in _WR_DATA_ROOTS:
        os.makedirs(root, exist_ok=True)


@pytest.fixture(autouse=True)
def _provision():
    """Idempotently provision write-test infrastructure before every test.

    Yields to the test body then performs best-effort cleanup of any files
    written to the data roots during this test run (paths matching wtest_wr*.txt
    under each root).
    """
    ensure_conformance_data()
    _ensure_write_data()
    yield
    # Best-effort cleanup: remove wtest_wr* files left by write tests.
    for root in _WR_DATA_ROOTS:
        for sub in ("", "cms/", "atlas/"):
            for name in (
                "wtest_wr01.txt", "wtest_wr02.txt", "wtest_wr03.txt",
                "wtest_wr04.txt", "wtest_wr05.txt", "wtest_wr06.txt",
                "wtest_wr07.txt", "wtest_wr08.txt",
            ):
                p = os.path.join(root, sub, name)
                try:
                    os.unlink(p)
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# Shared forge factory and probe dispatcher
# ---------------------------------------------------------------------------

def _forge():
    """Return a TokenForge loaded from the fleet token directory."""
    return TokenForge(TOKENS_DIR)


def probe(proto, token, path="/wtest_wr.txt", write=True):
    """Dispatch to the enforcing token port for write probes.

    WHAT: Routes a PUT request to webdav_bearer (8446, HTTPS) or s3_bearer
          (9002, HTTP) with the enforcing port and write=True.
    WHY:  Single call site for write probes; keeps test bodies one-liners.
    HOW:  proto="webdav" → webdav_bearer with NGINX_WEBDAV_TOKEN_PORT;
          proto="s3"     → s3_bearer with NGINX_S3_TOKEN_PORT; S3 URL layout is
          /{bucket}/{key} so the key is prefixed with S3_BUCKET ("testbucket").
          write defaults to True since this module is write-scope focused.

    Args:
        proto: "webdav" or "s3".
        token: JWT string.
        path:  URL path (must start with /).
        write: If True (default), issue PUT; False issues GET.

    Returns:
        "accept", "reject", or "notfound".
    """
    if proto == "webdav":
        return webdav_bearer(token, path, write, port=NGINX_WEBDAV_TOKEN_PORT)
    key = f"{S3_BUCKET}/{path.lstrip('/')}"
    return s3_bearer(token, key, write, port=NGINX_S3_TOKEN_PORT)


# ---------------------------------------------------------------------------
# WR-01  storage.write:/ PUT → accept
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_wr_01_write_scope_accept(proto):
    """WR-01: storage.write:/ token, PUT /wtest_wr01.txt → accept.

    WHAT: A token with storage.write:/ scope grants write access to any path
          under the export root.  The PUT must be accepted.
    WHY:  Positive write baseline — confirms that write-scope tokens reach
          actual storage on both protocols.  If this fails the allow_write
          directive is misconfigured or the scope parser is broken.
    """
    tok = _forge().scope("storage.write:/")
    assert probe(proto, tok, path="/wtest_wr01.txt") == "accept"


# ---------------------------------------------------------------------------
# WR-02  storage.create:/ PUT → accept
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_wr_02_create_scope_accept(proto):
    """WR-02: storage.create:/ token, PUT /wtest_wr02.txt → accept.

    WHAT: WLCG Token Profile §4 — storage.create authorises creating new objects.
          The scope check in scopes.c (brix_token_check_write) treats create
          equivalently to write; the PUT must be accepted.
    WHY:  Create-only tokens are common for data-ingest workflows that must write
          new objects but must not overwrite existing ones.  Both protocols must
          accept the create grant for new object creation.
    """
    tok = _forge().scope("storage.create:/")
    assert probe(proto, tok, path="/wtest_wr02.txt") == "accept"


# ---------------------------------------------------------------------------
# WR-03  storage.read:/ PUT → reject  (KEY security case)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_wr_03_read_scope_denies_write(proto):
    """WR-03: storage.read:/ token, PUT /wtest_wr03.txt → reject (key security case).

    WHAT: A token carrying ONLY storage.read:/ scope must NOT be accepted for a
          write (PUT) operation.  Read does not imply write.
    WHY:  WLCG Token Profile §4 — each scope action is distinct; storage.read
          grants GET access only.  Accepting a read token for PUT would be a
          critical authorization bug allowing read-only clients to modify or
          inject data on both HTTP storage protocols.
    HOW:  brix_identity_check_token_scope(identity, path, need_write=1) must
          return an error when the token's only active scope is storage.read.
    """
    tok = _forge().scope("storage.read:/")
    assert probe(proto, tok, path="/wtest_wr03.txt") == "reject"


# ---------------------------------------------------------------------------
# WR-04  storage.modify:/ PUT → accept
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_wr_04_modify_scope_accept(proto):
    """WR-04: storage.modify:/ token, PUT /wtest_wr04.txt → accept.

    WHAT: WLCG Token Profile §4 — storage.modify authorises overwriting or
          modifying existing objects.  The brix_token_check_write path treats
          modify equivalently to write and create; the PUT must be accepted.
    WHY:  storage.modify is issued by macaroon-to-JWT translation layers and by
          SciTokens-compatible issuers; it must be honoured alongside write/create
          on all storage protocols.
    """
    tok = _forge().scope("storage.modify:/")
    assert probe(proto, tok, path="/wtest_wr04.txt") == "accept"


# ---------------------------------------------------------------------------
# WR-05  write out-of-scope path → reject
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_wr_05_write_out_of_scope_reject(proto):
    """WR-05: scope="storage.write:/atlas", PUT /cms/wtest_wr05.txt → reject.

    WHAT: The token's write scope is restricted to /atlas; /cms/ is outside
          that prefix.  The write must be rejected.
    WHY:  Scope boundary enforcement applies to write operations exactly as it
          does to reads.  A write-scoped token must not leak outside its path
          prefix on any protocol.
    HOW:  brix_identity_check_token_scope checks the path against scope prefixes
          with boundary enforcement.  /cms/wtest_wr05.txt is not under /atlas →
          reject.
    """
    tok = _forge().scope("storage.write:/atlas")
    assert probe(proto, tok, path="/cms/wtest_wr05.txt") == "reject"


# ---------------------------------------------------------------------------
# WR-06  no-scope PUT → reject
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_wr_06_no_scope_reject(proto):
    """WR-06: no scope claim, PUT /wtest_wr06.txt → reject.

    WHAT: A token with no scope claim carries no storage grant; any write must
          be rejected on both protocols.
    WHY:  WLCG Token Profile §4 — storage access (read or write) requires an
          explicit storage.* scope.  A no-scope token is authenticated but
          carries no authorization for any storage path.
    """
    tok = _forge().no_scope()
    assert probe(proto, tok, path="/wtest_wr06.txt") == "reject"


# ---------------------------------------------------------------------------
# WR-07  expired token with write scope → reject
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_wr_07_expired_write_reject(proto):
    """WR-07: expired token (exp = now - 3600) with storage.write:/ → reject.

    WHAT: A token that would otherwise authorise a write must be rejected if
          it has expired.  Expiry is checked before scope on both protocols.
    WHY:  Temporal validity is the first gate in the validation pipeline
          (validate.c); a write-scoped but expired token must never reach the
          scope check successfully.
    """
    tok = _forge().temporal(-3600)
    assert probe(proto, tok, path="/wtest_wr07.txt") == "reject"


# ---------------------------------------------------------------------------
# WR-08  alg=none with write scope → reject (SEC)
# ---------------------------------------------------------------------------

@pytest.mark.tokenconf
@pytest.mark.parametrize("proto", ["webdav", "s3"])
@pytest.mark.registry_servers("s3-token", "webdav-token")
def test_wr_08_alg_none_write_reject(proto):
    """WR-08: alg=none unsigned token, PUT /wtest_wr08.txt → reject (SEC).

    WHAT: An unsigned JWT (alg=none) presented for a write operation must be
          rejected.  Accepting it would allow an unauthenticated attacker to
          inject arbitrary data into the storage endpoint.
    WHY:  Algorithm validation is the first cryptographic gate; a missing
          signature cannot grant any capability — read or write.  The SEC
          criticality is higher for writes because injecting data is more
          impactful than reading it.
    """
    tok = _forge().alg_none()
    assert probe(proto, tok, path="/wtest_wr08.txt") == "reject"
