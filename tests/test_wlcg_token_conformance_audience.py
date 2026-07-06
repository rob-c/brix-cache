"""WLCG token conformance — AUD family (audience claim: scalar vs array).

Runs manifest rows whose case_id starts with "AUD" against the live root://
fleet on port 11097.  All rows use protocol="root".

Ground truth from src/auth/token/json.c:
  json_string_or_array_contains() iterates ALL array elements — membership is
  position-independent.  Called by validate.c line 372 for the audience check.

Key findings this suite validates:
  - AUD array membership previously only tested on WebDAV; this confirms parity
    on root:// (port 11097, enforcing).
  - Empty-array aud and all-wrong-aud arrays are both rejected.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

import pytest
from lib.tokenconf import load_manifest, assert_verdict


@pytest.mark.tokenconf
@pytest.mark.parametrize("row", load_manifest("AUD"), ids=lambda r: r["case_id"])
def test_aud(row):
    assert_verdict(row, row["protocol"])
