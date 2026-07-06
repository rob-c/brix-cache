"""WLCG token conformance — SIG family (signature / algorithm checks).

Runs the manifest rows whose case_id starts with "SIG" against the live root://
fleet on port 11097, which enforces token auth.  WebDAV (8443) is optional-auth
and S3 (9001) has no token path, so all current SIG rows target root:// only.

When multi-key-JWKS ports are added, SIG-10..14 (ES256, kid-selection, no_kid
multi-key fallback) will be added to the manifest and this module will handle
them automatically via row["protocol"].
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

import pytest
from lib.tokenconf import load_manifest, assert_verdict


@pytest.mark.tokenconf
@pytest.mark.parametrize(
    "row",
    load_manifest("SIG"),
    ids=lambda r: r["case_id"],
)
def test_sig(row):
    assert_verdict(row, row["protocol"])
