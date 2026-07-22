"""
WebDAV lock startup sweep (brix_webdav_lock_startup_sweep).

Phase 16 moved WebDAV lock state onto xattrs (WEBDAV_LOCK_XATTR_KEY), so locks
now persist across an nginx restart.  The brix_webdav_lock_startup_sweep
directive (off by default) clears every persisted lock xattr under the export
root at startup, restoring ephemeral RFC 4918 §10.1 semantics.

These tests spin up a dedicated, minimal nginx instance (independent of the
shared test servers) so they can toggle the directive and observe the effect on
seeded lock xattrs directly on disk.

Three behaviours are asserted:
  * sweep ON  + real start  -> all persisted lock xattrs removed
  * sweep OFF + real start  -> lock xattrs preserved (persistence is the default)
  * sweep ON  + `nginx -t`  -> NOT swept (config test must not mutate the FS)
"""

import os
import shutil

import pytest

from settings import BIND_HOST
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-sweep")]

LOCK_KEY = "user.nginx_xrootd.lock"
LOCK_VAL = (b"token=opaquelocktoken:11111111-2222-3333-4444-555555555555|"
            b"owner=cn=test|expires=9999999999999|scope=exclusive|depth=infinity")


def _xattr_supported(path):
    try:
        os.setxattr(path, LOCK_KEY, LOCK_VAL)
        os.removexattr(path, LOCK_KEY)
        return True
    except OSError:
        return False


def _seed_locks(paths):
    for p in paths:
        os.setxattr(p, LOCK_KEY, LOCK_VAL)


def _count_locks(paths):
    n = 0
    for p in paths:
        try:
            os.getxattr(p, LOCK_KEY)
            n += 1
        except OSError:
            pass
    return n


def _spec(name, root, sweep):
    return NginxInstanceSpec(
        name=name,
        template="nginx_lc_webdav_lock_startup_sweep.conf",
        protocol="webdav",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(root),
                         "SWEEP": sweep},
        reason="webdav lock startup sweep")


@pytest.fixture
def sweep_env(tmp_path):
    base = str(tmp_path)
    root = os.path.join(base, "root")
    sub = os.path.join(root, "sub")
    os.makedirs(sub, exist_ok=True)
    f = os.path.join(root, "file.txt")
    with open(f, "w") as fh:
        fh.write("hello")

    if not _xattr_supported(f):
        pytest.skip("filesystem does not support user xattrs")

    nodes = [root, f, sub]
    yield root, nodes
    shutil.rmtree(base, ignore_errors=True)


def test_lock_startup_sweep_on_removes_locks(lifecycle, sweep_env):
    root, nodes = sweep_env
    _seed_locks(nodes)
    assert _count_locks(nodes) == 3

    # The sweep runs at worker startup; by the time start() reports ready it has
    # already executed, so no explicit stop is needed before checking on disk.
    lifecycle.start(_spec("lc-sweep-on", root, "on"))

    assert _count_locks(nodes) == 0, "sweep on should remove every lock xattr"


def test_lock_startup_sweep_off_preserves_locks(lifecycle, sweep_env):
    root, nodes = sweep_env
    _seed_locks(nodes)
    assert _count_locks(nodes) == 3

    lifecycle.start(_spec("lc-sweep-off", root, "off"))

    assert _count_locks(nodes) == 3, "default (sweep off) must preserve lock xattrs"


def test_lock_startup_sweep_skipped_under_config_test(lifecycle, sweep_env):
    root, nodes = sweep_env
    _seed_locks(nodes)
    assert _count_locks(nodes) == 3

    # `nginx -t` loads the config (running merge_loc_conf) but must NOT mutate
    # the filesystem -- the sweep is guarded by !ngx_test_config.
    reg = lifecycle.register(_spec("lc-sweep-cfgtest", root, "on"))
    lifecycle.launcher.render_nginx(reg)
    res = lifecycle.launcher.nginx_test(reg)
    assert res.returncode == 0, f"nginx -t failed: {res.stdout + res.stderr}"

    assert _count_locks(nodes) == 3, "config test must not run the sweep"
