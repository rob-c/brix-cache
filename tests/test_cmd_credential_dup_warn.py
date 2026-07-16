import os

import pytest

from cmdscripts.credential_dup_warn import run_checks
from settings import NGINX_BIN


def test_credential_dup_warn_flow(tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)

    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )
    messages = [message for _, message in results]
    assert "duplicate same-name credential warned at config load" in messages
    assert "config with the duplicate still loads (warning, not error)" in messages
    assert "single credential block: no false warning" in messages
    assert "distinct credential names: no false warning" in messages
