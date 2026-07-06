"""WLCG token conformance — SCP family (scope enforcement + traversal defense).

Runs the manifest rows whose case_id starts with "SCP" against the live root://
fleet on port 11097, which enforces token auth AND scope (brix_check_token_scope).

Each row carries a "path" key that names the XRootD path to probe via kXR_stat
after authentication; assert_verdict() reads that key and passes it through to
root_ztn().

Key security case:
  SCP-W04 — path "/atlas/../cms/ok.txt" MUST be rejected.  The stat handler
  calls brix_reject_dotdot_path() BEFORE the scope check, returning kXR_ArgInvalid
  for any path containing a ".." component (§3.5 traversal defense).  A pass here
  would be a real traversal bug — the dot-dot would have escaped the scope boundary
  and reached /cms/ok.txt.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

import pytest
from lib.tokenconf import load_manifest, assert_verdict


@pytest.mark.tokenconf
@pytest.mark.parametrize(
    "row",
    load_manifest("SCP"),
    ids=lambda r: r["case_id"],
)
def test_scp(row):
    assert_verdict(row, row["protocol"])
