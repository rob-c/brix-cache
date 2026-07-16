import os

import pytest

from cmdscripts.credential_xroot_gsi_writeback import XRDCP, run_checks
from settings import NGINX_BIN


def test_credential_xroot_gsi_writeback_flow(tmp_path):
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
    assert "flush authenticated + wrote through to the GSI origin byte-exact" in messages
    assert "anonymous flush correctly rejected by the GSI origin" in messages
