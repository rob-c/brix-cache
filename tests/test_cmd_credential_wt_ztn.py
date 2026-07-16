import os

import pytest

from cmdscripts.credential_wt_ztn import XRDCP, run_checks
from settings import NGINX_BIN


def test_credential_wt_ztn_flow(tmp_path):
    for tool in (NGINX_BIN, str(XRDCP)):
        if not os.access(tool, os.X_OK):
            pytest.skip(f"required executable not found: {tool}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)
    if results and results[0][1].startswith("SKIP"):
        pytest.skip(results[0][1])

    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )
    messages = [message for _, message in results]
    assert "flushed byte-exact to token origin (ztn write-back)" in messages
    assert "multi-chunk ztn write-back byte-exact" in messages
    assert "unauthenticated write-back correctly failed to reach the token origin" in messages
