"""``lib_py.fuse_host.with_host_mount_opts``: the per-host additions a FUSE
test's ``-o`` string needs.

On macOS that is ``daemon_timeout``: macFUSE's default is 60 s and it governs
shutdown too, so a mount helper that exits on SIGTERM lingers for the full
minute (measured exactly 60.0 s) before its session tears down.
"""
import subprocess
import sys
import pytest
from types import SimpleNamespace
from unittest import mock

from lib_py import fuse_host
from lib_py.fuse_host import with_host_mount_opts


def test_the_host_additions_are_appended():
    """success: the scenario's own options are kept, the host's are added."""
    with mock.patch.object(fuse_host, "HOST_MOUNT_OPTS", ("daemon_timeout=5",)):
        assert with_host_mount_opts("idle=0,timeout=30") == \
            "idle=0,timeout=30,daemon_timeout=5"


def test_an_explicit_value_is_never_overridden():
    """error path: a scenario that pins the option keeps its own value — the
    helper adds, it does not rewrite."""
    with mock.patch.object(fuse_host, "HOST_MOUNT_OPTS", ("daemon_timeout=5",)):
        assert with_host_mount_opts("daemon_timeout=99") == "daemon_timeout=99"


def test_no_additions_means_the_string_is_untouched():
    """security-negative: on a host with nothing to add (Linux) the option
    string is byte-identical — no empty element, no stray comma that libfuse
    would reject and no silently injected mount behaviour."""
    with mock.patch.object(fuse_host, "HOST_MOUNT_OPTS", ()):
        assert with_host_mount_opts("ro,allow_other") == "ro,allow_other"
        assert with_host_mount_opts("") == ""


def test_this_host_matches_its_platform():
    """the live value, so a future edit cannot quietly arm macFUSE options on
    Linux (where daemon_timeout is not a libfuse option at all)."""
    if sys.platform == "darwin":
        assert "daemon_timeout=5" in fuse_host.HOST_MOUNT_OPTS
    else:
        assert fuse_host.HOST_MOUNT_OPTS == ()


def test_darwin_requires_an_active_macfuse_extension():
    """An installed but unloaded macFUSE bundle is not mount-capable."""
    stopped = subprocess.CompletedProcess(["kextstat"], 0, "apple.kpi\n", "")
    loaded = subprocess.CompletedProcess(["kextstat"], 0,
                                         "io.macfuse.filesystems.macfuse\n", "")
    def exists(path):
        return path == fuse_host.MACFUSE_MOUNT
    with mock.patch.object(fuse_host.os.path, "exists", side_effect=exists), \
            mock.patch.object(fuse_host.shutil, "which", return_value="/usr/sbin/kextstat"), \
            mock.patch.object(fuse_host.subprocess, "run", return_value=stopped):
        assert not fuse_host._darwin_ready()
    with mock.patch.object(fuse_host.os.path, "exists", side_effect=exists), \
            mock.patch.object(fuse_host.shutil, "which", return_value="/usr/sbin/kextstat"), \
            mock.patch.object(fuse_host.subprocess, "run", return_value=loaded):
        assert fuse_host._darwin_ready()


def test_freebsd_uses_native_mount_prerequisites_not_linux_fusermount(monkeypatch):
    monkeypatch.setattr(fuse_host.sys, 'platform', 'freebsd15')
    monkeypatch.setattr(fuse_host.os, 'access', lambda path, mode: path == '/dev/fuse')
    monkeypatch.setattr(fuse_host.shutil, 'which', lambda name:
                        '/sbin/mount_fusefs' if name == 'mount_fusefs' else None)
    monkeypatch.setattr(fuse_host.os, 'geteuid', lambda: 2100)
    monkeypatch.setattr(fuse_host.subprocess, 'run', lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout='1\n'))
    assert fuse_host.fuse_ready()
    assert fuse_host.unmount_tiers() == [['umount']]
    assert fuse_host.unmount_tiers(lazy=True) == [['umount', '-f']]


def test_freebsd_inaccessible_device_cannot_claim_mount_readiness(monkeypatch):
    monkeypatch.setattr(fuse_host.os, 'access', lambda *args: False)
    assert not fuse_host._freebsd_ready()


def test_freebsd_denied_or_unreadable_mount_policy_fails_closed(monkeypatch):
    monkeypatch.setattr(fuse_host.os, 'geteuid', lambda: 2100)
    monkeypatch.setattr(fuse_host.subprocess, 'run', lambda *args, **kwargs:
                        SimpleNamespace(returncode=0, stdout='0\n'))
    assert not fuse_host._freebsd_usermount_allowed()

    def failed(*args, **kwargs):
        raise OSError('sysctl unavailable')

    monkeypatch.setattr(fuse_host.subprocess, 'run', failed)
    assert not fuse_host._freebsd_usermount_allowed()


def test_freebsd_mount_options_are_actual_flags_not_fabricated_nodev(monkeypatch):
    monkeypatch.setattr(fuse_host.os.path, 'ismount', lambda path: True)
    monkeypatch.setattr(fuse_host.os, 'statvfs', lambda path:
                        SimpleNamespace(f_flag=fuse_host.os.ST_RDONLY | fuse_host.os.ST_NOSUID))
    assert fuse_host.freebsd_mount_options('/owned/mount') == 'ro,nosuid'


def test_freebsd_unmounted_path_cannot_borrow_parent_filesystem_policy(monkeypatch):
    monkeypatch.setattr(fuse_host.os.path, 'ismount', lambda path: False)
    monkeypatch.setattr(fuse_host.os, 'statvfs', lambda path: pytest.fail('not a mount'))
    assert fuse_host.freebsd_mount_options('/not/mounted') is None


@pytest.mark.parametrize('host,options,expected', [
    ('freebsd15', None, False), ('freebsd15', 'nosuid', True),
    ('linux', 'nosuid', False), ('linux', 'nodev,nosuid', True),
    ('darwin', 'xnodev,nosuid', False),
])
def test_device_policy_is_exact_and_requires_mount_evidence(monkeypatch, host, options, expected):
    monkeypatch.setattr(fuse_host, 'sys', SimpleNamespace(platform=host))
    assert fuse_host.mount_device_access_disabled(options) is expected


def test_native_mount_cleanup_cannot_cross_a_prefix_boundary(monkeypatch):
    import psutil

    entries = [SimpleNamespace(mountpoint=path, fstype=kind) for path, kind in (
        ('/owned/test/mount', 'fusefs'), ('/owned/test-neighbor/mount', 'fusefs'),
        ('/owned/test/plain', 'zfs'))]
    monkeypatch.setattr(psutil, 'disk_partitions', lambda all: entries)
    assert fuse_host.freebsd_fuse_mounts_under('/owned/test') == ['/owned/test/mount']


@pytest.mark.parametrize('outcome', ['success', 'error', 'timeout'])
def test_live_cvmfs_unmount_uses_bounded_native_policy(monkeypatch, outcome):
    from cmdscripts import brixcvmfs_live

    calls = []

    def unmount(path, *, lazy, timeout):
        calls.append((path, lazy, timeout))
        if outcome == 'timeout' and not lazy:
            raise subprocess.TimeoutExpired('owned unmount', timeout)
        return SimpleNamespace(returncode=int(outcome == 'error' and not lazy))

    monkeypatch.setattr(brixcvmfs_live, 'host_unmount', unmount)
    brixcvmfs_live._unmount('/owned/test/mount')
    expected = [('/owned/test/mount', False, 5)]
    if outcome != 'success':
        expected.append(('/owned/test/mount', True, 5))
    assert calls == expected


def _default_cache_layout(tmp_path, layout):
    """Create only private unit-test paths, never the real system cache root."""
    base = tmp_path / 'cache'
    if layout == 'provisioned':
        base.mkdir()
    elif layout == 'file':
        base.write_text('not a directory')
    return base


@pytest.mark.parametrize('layout,allowed,expected', [
    ('provisioned', True, True), ('provisioned', False, False),
    ('absent', True, True), ('absent', False, False), ('file', True, False),
])
def test_default_cache_readiness_checks_only_its_actual_creation_parent(
        tmp_path, monkeypatch, layout, allowed, expected):
    """Support least-privilege provisioning without accepting a file as a root."""
    import _test_cvmfs_conformance_fuse_cache_helpers as cache

    base = _default_cache_layout(tmp_path, layout)
    calls = []

    def access(path, mode):
        calls.append((path, mode))
        return allowed

    monkeypatch.setattr(cache.os, 'access', access)
    assert cache._default_cache_parent_writable(base) is expected
    wanted = base if layout == 'provisioned' else tmp_path
    assert calls == ([] if layout == 'file' else [(wanted, cache.os.W_OK | cache.os.X_OK)])
