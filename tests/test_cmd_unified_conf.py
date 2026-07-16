from pathlib import Path
import os
import pytest

from cmdscripts.unified_conf import run


@pytest.mark.uses_lifecycle_harness
def test_unified_conf_port_importable():
    assert callable(run)


@pytest.mark.optin
def test_unified_conf_live_nginx_t():
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    assert run(nginx) == 0
