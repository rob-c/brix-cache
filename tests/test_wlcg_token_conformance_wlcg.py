"""WLCG token conformance — WLCG family (profile-level claims and semantics).

Probes port 11097 (NGINX_TOKEN_PORT) which enforces token auth against the
main RSA JWKS (jwks.json, kid test-key-1) with WLCG profile validation.

Ground truth (src/auth/token/validate.c):
  - aud check: exact string match against the configured audience
    ('nginx-xrootd'). The WLCG wildcard 'https://wlcg.cern.ch/jwt/v1/any'
    SHOULD be accepted (rules 104/105) but our impl uses exact-match →
    DIVERGENCE (xfail strict).
  - wlcg.ver: treated as advisory by this implementation — absent ver does NOT
    cause rejection (rule 101 says REQUIRED; documented implementation choice).
  - wlcg.groups: parsed into the request context for authz; capability scope
    still authorises the read (rule 119; characterize).
  - storage.stage:/path grants read capability (the stage action includes
    read-access to initiate staging — same as POSIX O_RDONLY for tape).
  - storage.create:/path does NOT grant read (rule 115 parity check).

Test cases:
  WLCG-01  aud_wildcard(), GET /test.txt → RFC-correct accept (rules 104/105);
           ACTUAL=reject (exact-match audience) → xfail(strict) — aud-wildcard
           fix candidate.
  WLCG-02  wlcg_missing_ver(), GET /test.txt → RFC-correct reject (rule 101);
           ACTUAL=accept (wlcg.ver advisory) → xfail(strict) — documented choice.
  WLCG-03  generate() (wlcg.ver=1.0 baseline), GET /test.txt → accept.
  WLCG-04  wlcg_groups(["/wlcg","/wlcg/xfers"]) default scope, GET /test.txt →
           accept (groups do not block; capability scope authorises).
  WLCG-05  scope("storage.create:/data"), GET /test.txt → reject (rule 115:
           create ≠ read; WLCG family parity check for SCP2-07).
  WLCG-06  generate(scope="storage.stage:/atlas"), GET /atlas/ok.txt → accept
           (stage grants read capability over the staged path).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

import pytest
from tokenforge import TokenForge
from lib.tokenconf import root_ztn, ensure_conformance_data
from settings import NGINX_TOKEN_PORT as PORT, TOKENS_DIR


def _f():
    return TokenForge(TOKENS_DIR)


@pytest.fixture(autouse=True)
def _data():
    ensure_conformance_data()


@pytest.mark.tokenconf
def test_wlcg_01_aud_wildcard_accept():
    """aud = WLCG wildcard URI — MUST accept (rules 104/105).

    WHY:  WLCG Token Profile §3 / rules 104/105 — the audience value
          'https://wlcg.cern.ch/jwt/v1/any' is a WLCG-wide wildcard; every
          conformant WLCG endpoint MUST accept it regardless of locally
          configured audience.  The audience check now OR-ins a wildcard check
          against the WLCG wildcard URI after the configured-audience check.
    FIXED: wildcard-aud branch added to validate.c audience check.
    """
    tok = _f().aud_wildcard()
    assert root_ztn(tok, "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
@pytest.mark.xfail(
    strict=True,
    reason=(
        "DIVERGENCE rule 101: WLCG Token Profile §2.1 requires wlcg.ver to be "
        "present; our implementation treats it as advisory and accepts tokens "
        "with the claim absent. This is a documented implementation choice — "
        "wlcg.ver absence does not indicate a malformed token in practice; "
        "actual=accept; RFC-correct=reject."
    ),
)
def test_wlcg_02_missing_ver_reject():
    """wlcg.ver absent — RFC-correct reject (rule 101); ACTUAL=accept (advisory).

    WHY:  WLCG Token Profile §2.1 / rule 101 — the wlcg.ver claim is REQUIRED
          in a WLCG token; its absence signals a non-profile-conformant token.
          Our implementation treats wlcg.ver as advisory and does not reject on
          its absence.  Documented choice: ver-less tokens from compliant issuers
          are accepted to allow graceful forward compatibility.
    DIVERGENCE: actual=accept; RFC-correct=reject.
    """
    tok = _f().wlcg_missing_ver()
    assert root_ztn(tok, "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_wlcg_03_baseline_accept():
    """Well-formed WLCG token (wlcg.ver=1.0, storage.read:/), GET /test.txt → accept.

    WHY:  Baseline: a correctly-formed WLCG token with the default storage.read:/
          scope MUST be accepted.  Confirms the fleet is live and the conformance
          fixture files are present before the divergence cases run.
    """
    tok = _f().generate()
    assert root_ztn(tok, "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_wlcg_04_groups_claim_accept():
    """Token carrying wlcg.groups, default storage.read:/ scope, GET /test.txt → accept.

    WHY:  WLCG Token Profile §4 / rule 119 — wlcg.groups carries VO group
          membership and is parsed for authz context, but the capability scope
          (storage.read:/) still authorises the read independently.  Groups do
          not block access → accept.
    CHARACTERIZE: confirms the implementation does not erroneously fail on an
          unexpected wlcg.groups array.
    """
    tok = _f().wlcg_groups(["/wlcg", "/wlcg/xfers"])
    assert root_ztn(tok, "/test.txt", port=PORT) == "accept"


@pytest.mark.tokenconf
def test_wlcg_05_create_scope_no_read_reject():
    """scope storage.create:/data, GET /test.txt → reject (rule 115).

    WHY:  WLCG Token Profile §4 / rule 115 — storage.create grants permission
          to create new objects only; it does NOT imply read access.  A read
          (kXR_stat) of /test.txt requires storage.read or a read-implying scope
          over that path; storage.create:/data does not supply it → reject.
    NOTE: This is the WLCG-family mirror of SCP2-07, validating consistency
          across the two test families.
    """
    tok = _f().scope("storage.create:/data")
    assert root_ztn(tok, "/test.txt", port=PORT) == "reject"


@pytest.mark.tokenconf
def test_wlcg_06_storage_stage_grants_read_accept():
    """scope storage.stage:/atlas, GET /atlas/ok.txt → accept.

    WHY:  The WLCG storage.stage action semantics include read capability over
          the staged path (a client must be able to read data back after staging
          it to tape).  The implementation recognises storage.stage as equivalent
          to storage.read for the purpose of a read/stat access check →
          /atlas/ok.txt is covered → accept.
    CHARACTERIZE: documents the stage-implies-read policy.
    """
    tok = _f().generate(scope="storage.stage:/atlas")
    assert root_ztn(tok, "/atlas/ok.txt", port=PORT) == "accept"
