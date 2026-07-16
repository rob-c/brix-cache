import os

import pytest

from cmdscripts.s3_usermeta import run_checks
from settings import NGINX_BIN


def test_s3_usermeta_flow(tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)

    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )
    messages = [message for _, message in results]
    assert "PUT 200" in messages
    assert "HEAD echoes x-amz-meta-foo=bar" in messages
    assert "HEAD echoes x-amz-meta-color=Blue (key lowercased)" in messages
    assert "GET echoes the metadata and body" in messages
    assert "COPY 200" in messages
    assert "copied object carries x-amz-meta-foo=bar" in messages
    assert "REPLACE copy-self 200" in messages
    assert "metadata replaced: foo=baz" in messages
    assert "old key dropped on REPLACE: color absent" in messages
    assert "bytes intact after metadata-only REPLACE" in messages
