import os

import pytest

from cmdscripts.s3_store_writable import run_checks
from settings import NGINX_BIN


def test_s3_store_writable_flow(tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)

    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )
    messages = [message for _, message in results]
    assert any(message.startswith("direct PUT to A") for message in messages)
    assert any(message.startswith("WebDAV PUT status=") for message in messages)
    assert "object reached the posix backend byte-exact (flushed FROM the s3 stage)" in messages
    assert "GET byte-exact" in messages
