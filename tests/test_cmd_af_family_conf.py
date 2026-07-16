import os

import pytest

from cmdscripts.af_family_conf import INVALID_TOKEN, VALID_TOKENS, run_checks
from settings import NGINX_BIN


def test_brix_cache_origin_family_config_tokens(tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    results = run_checks(NGINX_BIN, tmp_path)

    assert all(ok for ok, _ in results), "\n".join(message for _, message in results)
    messages = [message for _, message in results]
    for token in VALID_TOKENS:
        assert f"accepts brix_cache_origin_family {token}" in messages
    assert f"rejects brix_cache_origin_family {INVALID_TOKEN}" in messages
