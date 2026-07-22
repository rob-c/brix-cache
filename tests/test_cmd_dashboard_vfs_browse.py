import os

import pytest

from cmdscripts.dashboard_vfs_browse import run_checks
from settings import NGINX_BIN

pytestmark = pytest.mark.xdist_group("cmd-dashboard_vfs_browse")


def test_dashboard_vfs_browse_flow(tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    results = run_checks(tmp_path, nginx_bin=NGINX_BIN)

    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results
    )
    messages = [message for _, message in results]
    assert "config parses (brix_dashboard_vfs_browse)" in messages
    assert any(message.startswith("pblock seeded via WebDAV PUT") for message in messages)
    assert "census lists posix + pblock exports" in messages
    assert "posix export lists via VFS (size+kind)" in messages
    assert "pblock export shows the LOGICAL namespace" in messages
    assert "pblock download byte-exact through VFS" in messages
    assert "unauthenticated -> 401" in messages
    assert "traversal path rejected (400)" in messages
    assert "feature off -> 404" in messages
