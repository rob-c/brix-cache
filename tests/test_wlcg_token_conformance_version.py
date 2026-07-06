"""WLCG token conformance — VER family (wlcg.ver claim handling).

Runs manifest rows whose case_id starts with "VER" against the live root://
fleet on port 11097.  All rows use protocol="root".

Ground truth from src/auth/token/validate.c:
  wlcg.ver is NOT read or validated anywhere in the validator.  The claim is
  only emitted by src/fs/cache/origin/pelican_register.c when minting outbound
  tokens.  Absent or unknown wlcg.ver values are therefore advisory — not fatal.

Design note: if any VER case unexpectedly REJECTs, that indicates enforcement
was added (a design change, not necessarily a bug).  The expected values in
this manifest reflect the current advisory-only implementation.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

import pytest
from lib.tokenconf import load_manifest, assert_verdict


@pytest.mark.tokenconf
@pytest.mark.parametrize("row", load_manifest("VER"), ids=lambda r: r["case_id"])
def test_ver(row):
    assert_verdict(row, row["protocol"])
