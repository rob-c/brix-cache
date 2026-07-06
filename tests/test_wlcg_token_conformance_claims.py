"""WLCG token conformance — CLM family (temporal / structural / size checks).

Runs manifest rows whose case_id starts with "CLM" against the live root://
fleet on port 11097 (enforcing token auth).  Every case in this family uses
protocol="root"; WebDAV (8443) is optional-auth and cannot enforce reject.

Ground truth from src/auth/token/validate.c:
  - token_len > 8192                      → reject (line 220)
  - now > exp + BRIX_TOKEN_CLOCK_SKEW_SECS (30s) → reject (line 389)
  - now < nbf (no skew tolerance on nbf)  → reject (line 398)
  - missing/string exp: json_get_int64 leaves exp=0 → treated as expired → reject
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

import pytest
from lib.tokenconf import load_manifest, assert_verdict


@pytest.mark.tokenconf
@pytest.mark.parametrize("row", load_manifest("CLM"), ids=lambda r: r["case_id"])
def test_clm(row):
    assert_verdict(row, row["protocol"])
