import os

import pytest

from cmdscripts.credential_xroot_gsi import XRDFS, run_checks
from settings import NGINX_BIN


def test_credential_xroot_gsi_flow(tmp_path):
    for tool in (NGINX_BIN, str(XRDFS)):
        if not os.access(tool, os.X_OK):
            pytest.skip(f"required executable not found: {tool}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)
    if results and results[0][1].startswith("SKIP"):
        pytest.skip(results[0][1])

    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )
    messages = [message for _, message in results]
    assert "byte-exact serve (GSI-authenticated fill)" in messages
    assert "multi-chunk GSI-authenticated fill byte-exact" in messages
    assert "cert+key credential authenticated the GSI fill" in messages
    assert "unauthenticated fill correctly failed (origin required GSI)" in messages
    assert "fill correctly refused (origin cert not verifiable against the wrong CA)" in messages
