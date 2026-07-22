import os

import pytest

from cmdscripts.cache_watermark_config import run_checks
from settings import NGINX_BIN

pytestmark = pytest.mark.xdist_group("cmd-cache_watermark_config")


def test_cache_watermark_config_flow(tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)

    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )
    messages = [message for _, message in results]
    assert "valid 90/80 pair accepted" in messages
    assert "inverted pair rejected with EMERG" in messages
    assert "back-compat eviction_threshold loads" in messages
    assert "decimal watermark form accepted" in messages
    assert "staging watermark without stage_root rejected" in messages
    assert "staging valid pair accepted" in messages
    assert "staging inverted pair rejected" in messages
    assert "evict_at/evict_to percent pair accepted" in messages
    assert "inverted evict pair rejected" in messages
    assert "evict_at 100 rejected (must stay below full)" in messages
    assert "evict pair coexists with explicit watermarks" in messages
