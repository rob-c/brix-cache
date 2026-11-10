"""Expired multipart uploads are cleaned without touching live or escaped data."""

import os
import subprocess
import time

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def mpu_reaper(server_native_compile):
    wrappers = ('s3_build_vfs_ctx', 'brix_vfs_opendir_quiet', 'brix_vfs_probe',
                'brix_fs_remove_tree_confined')
    return server_native_compile('mpu-reaper', 'tests/c/mpu_reaper_native_test.c',
                                 ['-Wl,--wrap=' + name for name in wrappers])


def tree(tmp_path):
    root = tmp_path / 'export'; root.mkdir()
    expired = root / '.expired.mpu-deadbeef'; expired.mkdir()
    (expired / 'nested').mkdir(); (expired / 'nested/part.1').write_bytes(b'expired')
    recent = root / '.recent.mpu-abc'; recent.mkdir(); (recent / 'part.1').write_bytes(b'active')
    outside = tmp_path / 'outside'; outside.mkdir(); (outside / 'secret').write_bytes(b'secret')
    (root / '.link.mpu-abc').symlink_to(outside, target_is_directory=True)
    (root / '.file.mpu-abc').write_bytes(b'ordinary file')
    (root / 'ordinary').mkdir(); (root / '.hidden').mkdir()
    old = time.time() - 7200
    for path in (expired, outside, root / '.file.mpu-abc', root / 'ordinary', root / '.hidden'):
        os.utime(path, (old, old))
    os.utime(root / '.link.mpu-abc', (old, old), follow_symlinks=False)
    return root, expired, recent, outside


def invoke(binary, root, mode, path, age, expected):
    result = subprocess.run([str(binary), str(root), mode, str(path), str(age), str(expected)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


def preserved(root, recent, outside):
    assert (recent / 'part.1').read_bytes() == b'active'
    assert (outside / 'secret').read_bytes() == b'secret'
    assert (root / '.link.mpu-abc').is_symlink()
    assert (root / '.file.mpu-abc').read_bytes() == b'ordinary file'
    assert (root / 'ordinary').is_dir() and (root / '.hidden').is_dir()


def test_only_expired_upload_directories_are_removed(mpu_reaper, tmp_path):
    root, expired, recent, outside = tree(tmp_path)
    invoke(mpu_reaper, root, 'normal', root / 'object', 3600, 1)
    assert not expired.exists()
    preserved(root, recent, outside)
    invoke(mpu_reaper, root, 'normal', root / 'object', 3600, 0)


@pytest.mark.parametrize('mode', ['opendir', 'probe', 'remove'])
def test_scan_or_removal_failure_never_reports_success(mpu_reaper, tmp_path, mode):
    root, expired, recent, outside = tree(tmp_path)
    invoke(mpu_reaper, root, mode, root / 'object', 3600, 0)
    assert (expired / 'nested/part.1').read_bytes() == b'expired'
    preserved(root, recent, outside)


@pytest.mark.parametrize('path,age', [('<null>', 3600), ('object', 3600), ('/object', 3600),
    ('<valid>', 0), ('<valid>', -1), ('/' + 'x' * 4096 + '/file', 3600), ('/absent/child/file', 3600)])
def test_disabled_or_unusable_parent_cannot_delete_data(mpu_reaper, tmp_path, path, age):
    root, expired, recent, outside = tree(tmp_path)
    invoke(mpu_reaper, root, 'normal', root / 'object' if path == '<valid>' else path, age, 0)
    assert expired.exists()
    preserved(root, recent, outside)
