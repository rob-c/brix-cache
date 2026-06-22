"""
WebDAV lock startup sweep (xrootd_webdav_lock_startup_sweep).

Phase 16 moved WebDAV lock state onto xattrs (WEBDAV_LOCK_XATTR_KEY), so locks
now persist across an nginx restart.  The xrootd_webdav_lock_startup_sweep
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
import subprocess
import time

import pytest

from settings import NGINX_BIN, free_port

LOCK_KEY = "user.nginx_xrootd.lock"
LOCK_VAL = (b"token=opaquelocktoken:11111111-2222-3333-4444-555555555555|"
            b"owner=cn=test|expires=9999999999999|scope=exclusive|depth=infinity")

# A free OS port (env override honored) so the dedicated nginx instance never
# collides with the shared test fleet or another self-contained test.
SWEEP_PORT = int(os.environ.get("TEST_SWEEP_PORT") or free_port())


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


def _write_conf(base, root, sweep):
    # nginx opens <prefix>/logs/error.log and the default access_log relative to
    # the -p prefix before/while parsing; create the dir and silence access_log.
    os.makedirs(os.path.join(base, "logs"), exist_ok=True)
    conf = os.path.join(base, f"nginx_{sweep}.conf")
    with open(conf, "w") as fh:
        fh.write(f"""
worker_processes 1;
error_log {base}/logs/error_{sweep}.log info;
pid {base}/nginx_{sweep}.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    server {{
        listen {SWEEP_PORT};
        location / {{
            xrootd_webdav on;
            xrootd_webdav_root {root};
            xrootd_webdav_auth none;
            xrootd_webdav_lock_startup_sweep {sweep};
        }}
    }}
}}
""")
    return conf


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
    yield base, root, nodes
    shutil.rmtree(base, ignore_errors=True)


def _run_nginx(conf, base, test_only=False):
    args = [NGINX_BIN, "-c", conf, "-p", base]
    if test_only:
        args.insert(1, "-t")
    res = subprocess.run(args, capture_output=True, text=True)
    return res


def _stop_nginx(conf, base):
    subprocess.run([NGINX_BIN, "-c", conf, "-p", base, "-s", "stop"],
                   capture_output=True, text=True)
    time.sleep(0.5)


def test_lock_startup_sweep_on_removes_locks(sweep_env):
    base, root, nodes = sweep_env
    conf = _write_conf(base, root, "on")
    _seed_locks(nodes)
    assert _count_locks(nodes) == 3

    res = _run_nginx(conf, base)
    assert res.returncode == 0, f"nginx failed to start: {res.stderr}"
    time.sleep(1)
    _stop_nginx(conf, base)

    assert _count_locks(nodes) == 0, "sweep on should remove every lock xattr"


def test_lock_startup_sweep_off_preserves_locks(sweep_env):
    base, root, nodes = sweep_env
    conf = _write_conf(base, root, "off")
    _seed_locks(nodes)
    assert _count_locks(nodes) == 3

    res = _run_nginx(conf, base)
    assert res.returncode == 0, f"nginx failed to start: {res.stderr}"
    time.sleep(1)
    _stop_nginx(conf, base)

    assert _count_locks(nodes) == 3, "default (sweep off) must preserve lock xattrs"


def test_lock_startup_sweep_skipped_under_config_test(sweep_env):
    base, root, nodes = sweep_env
    conf = _write_conf(base, root, "on")
    _seed_locks(nodes)
    assert _count_locks(nodes) == 3

    # `nginx -t` loads the config (running merge_loc_conf) but must NOT mutate
    # the filesystem -- the sweep is guarded by !ngx_test_config.
    res = _run_nginx(conf, base, test_only=True)
    assert res.returncode == 0, f"nginx -t failed: {res.stderr}"

    assert _count_locks(nodes) == 3, "config test must not run the sweep"
