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
from pathlib import Path
import shutil

import pytest
import requests

from settings import BIND_HOST, HOST
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


def _seed_locks(paths, value=LOCK_VAL):
    for p in paths:
        os.setxattr(p, LOCK_KEY, value)


def _count_locks(paths):
    n = 0
    for p in paths:
        try:
            os.getxattr(p, LOCK_KEY)
            n += 1
        except OSError:
            pass
    return n


def _spec(name, root, sweep, *, write=False):
    return NginxInstanceSpec(
        name=name,
        template="nginx_lc_webdav_lock_startup_sweep.conf",
        protocol="webdav",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(root),
                         "SWEEP": sweep, "ALLOW_WRITE": 'on' if write else 'off'},
        reason="webdav lock startup sweep")


@pytest.fixture(params=['legacy', 'canonical', 'reordered'])
def sweep_env(tmp_path, request):
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
    value = LOCK_VAL
    if request.param == 'canonical':
        value = b'v=2|' + value + b'|null=0'
    elif request.param == 'reordered':
        value = b'future=preserved|v=2|null=0|' + value
    yield root, nodes, value
    shutil.rmtree(base, ignore_errors=True)


def test_lock_startup_sweep_on_removes_locks(lifecycle, sweep_env):
    root, nodes, value = sweep_env
    _seed_locks(nodes, value)
    assert _count_locks(nodes) == 3

    # The sweep runs at worker startup; by the time start() reports ready it has
    # already executed, so no explicit stop is needed before checking on disk.
    lifecycle.start(_spec("lc-sweep-on", root, "on"))

    assert _count_locks(nodes) == 0, "sweep on should remove every lock xattr"


def test_lock_startup_sweep_off_preserves_locks(lifecycle, sweep_env):
    root, nodes, value = sweep_env
    _seed_locks(nodes, value)
    assert _count_locks(nodes) == 3

    lifecycle.start(_spec("lc-sweep-off", root, "off"))

    assert _count_locks(nodes) == 3, "default (sweep off) must preserve lock xattrs"


def test_lock_startup_sweep_skipped_under_config_test(lifecycle, sweep_env):
    root, nodes, value = sweep_env
    _seed_locks(nodes, value)
    assert _count_locks(nodes) == 3

    # `nginx -t` loads the config (running merge_loc_conf) but must NOT mutate
    # the filesystem -- the sweep is guarded by !ngx_test_config.
    reg = lifecycle.register(_spec("lc-sweep-cfgtest", root, "on"))
    lifecycle.launcher.render_nginx(reg)
    res = lifecycle.launcher.nginx_test(reg)
    assert res.returncode == 0, f"nginx -t failed: {res.stdout + res.stderr}"

    assert _count_locks(nodes) == 3, "config test must not run the sweep"


def test_sweep_never_follows_an_export_symlink(lifecycle, sweep_env, tmp_path):
    """The exact-byte legacy migration must not widen the export boundary."""
    root, nodes, value = sweep_env
    outside = tmp_path / 'outside'
    outside.write_bytes(b'outside export')
    os.setxattr(outside, LOCK_KEY, value)
    os.symlink(outside, os.path.join(root, 'escape'))
    _seed_locks(nodes, value)
    lifecycle.start(_spec('lc-sweep-on', root, 'on'))
    assert _count_locks(nodes) == 0
    assert outside.read_bytes() == b'outside export'
    assert os.getxattr(outside, LOCK_KEY) == value


def _live_record(value):
    return value if b'v=2|' in value else b'v=2|' + value + b'|null=0'


def test_observed_live_record_can_be_refreshed_and_unlocked(lifecycle, sweep_env):
    """Unknown fields/order must not break exact refresh or UNLOCK transactions."""
    root, nodes, value = sweep_env
    live = _live_record(value)
    os.setxattr(nodes[1], LOCK_KEY, live)
    endpoint = lifecycle.start(_spec('lc-sweep-off', root, 'off', write=True))
    url = f'http://{HOST}:{endpoint.port}/file.txt'
    token = 'opaquelocktoken:11111111-2222-3333-4444-555555555555'
    response = requests.request('LOCK', url, headers={
        'If': f'(<{token}>)', 'Timeout': 'Second-60'}, timeout=5)
    assert response.status_code == 200, response.text
    refreshed = os.getxattr(nodes[1], LOCK_KEY)
    assert refreshed != live and refreshed.startswith(b'v=2|')
    assert token.encode() in refreshed
    response = requests.request('UNLOCK', url, headers={'Lock-Token': f'<{token}>'}, timeout=5)
    assert response.status_code == 204, response.text
    assert _count_locks([nodes[1]]) == 0
    assert Path(nodes[1]).read_bytes() == b'hello'


def test_expired_observation_is_reaped_before_a_new_lock(lifecycle, sweep_env):
    """Legacy normalization and noncanonical v2 records cannot poison re-lock."""
    root, nodes, value = sweep_env
    os.setxattr(nodes[1], LOCK_KEY, value.replace(b'9999999999999', b'0'))
    endpoint = lifecycle.start(_spec('lc-sweep-off', root, 'off', write=True))
    body = ('<D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope>'
            '<D:locktype><D:write/></D:locktype></D:lockinfo>')
    response = requests.request('LOCK', f'http://{HOST}:{endpoint.port}/file.txt',
        data=body, headers={'Content-Type': 'application/xml', 'Timeout': 'Second-60'},
        timeout=5)
    assert response.status_code in (200, 201), response.text
    assert '11111111-2222-3333-4444-555555555555' not in response.headers['Lock-Token']
    assert os.getxattr(nodes[1], LOCK_KEY).startswith(b'v=2|')
    assert Path(nodes[1]).read_bytes() == b'hello'


def test_read_only_lock_refuses_before_expiry_cleanup(lifecycle, sweep_env):
    """The snapshot fix never grants an expired-lock reaper write authority."""
    root, nodes, value = sweep_env
    expired = value.replace(b'9999999999999', b'0')
    os.setxattr(nodes[1], LOCK_KEY, expired)
    endpoint = lifecycle.start(_spec('lc-sweep-off', root, 'off'))
    response = requests.request('LOCK', f'http://{HOST}:{endpoint.port}/file.txt',
        headers={'If': '(<opaquelocktoken:11111111-2222-3333-4444-555555555555>)'},
        timeout=5)
    assert response.status_code == 403, response.text
    assert os.getxattr(nodes[1], LOCK_KEY) == expired
    assert Path(nodes[1]).read_bytes() == b'hello'
