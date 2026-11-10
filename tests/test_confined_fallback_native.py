"""Older-kernel confinement preserves mutations, errno and descriptor ownership."""

import errno
from pathlib import Path
import stat
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def fallback(server_native_compile):
    return server_native_compile('confined-fallback', 'tests/c/confined_fallback_native_test.c',
                                 ['-Wl,--wrap=brix_plat_openat2'])


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / 'root'
    (root / 'a/b').mkdir(parents=True)
    (root / 'a/b/file').write_bytes(b'payload')
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'secret').write_bytes(b'unchanged')
    (root / 'link-outside').symlink_to(outside, target_is_directory=True)
    return root, outside


def invoke(binary, operation, root, path, destination='unused', unavailable=errno.ENOSYS):
    result = subprocess.run([str(binary), operation, str(root), str(path), str(destination),
                             str(unavailable)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return {key: int(value) for key, value in (item.split('=') for item in result.stdout.split())}


@pytest.mark.parametrize('parent', ['', '.', 'a', 'a/b'])
def test_segment_walk_opens_only_existing_directories(fallback, tree, parent):
    root, _ = tree
    assert invoke(fallback, 'parent', root, parent) == {'rc': 0, 'error': 0}


@pytest.mark.parametrize('parent,error', [('a/../b', errno.EACCES), ('a/./b', errno.EACCES),
    ('a//b', errno.EACCES), ('/a', errno.EACCES), ('link-outside', errno.ENOTDIR),
    ('a/b/file/child', errno.ENOTDIR), ('absent', errno.ENOENT), ('x' * 4096, errno.ENAMETOOLONG)])
def test_forbidden_components_and_symlinks_cannot_escape_fallback(fallback, tree, parent, error):
    root, outside = tree
    assert invoke(fallback, 'parent', root, parent) == {'rc': -1, 'error': error}
    assert (outside / 'secret').read_bytes() == b'unchanged'


@pytest.mark.parametrize('parent', ['', '.', 'a/b'])
def test_invalid_root_descriptor_is_preserved_without_leak(fallback, tree, parent):
    assert invoke(fallback, 'bad-rootfd', tree[0], parent) == {'rc': -1, 'error': errno.EBADF}


@pytest.mark.parametrize('unavailable', [errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP])
@pytest.mark.parametrize('path', ['', 'a/b/file'])
def test_supported_kernel_absence_errors_use_confined_open_fallback(fallback, tree, unavailable, path):
    root, _ = tree
    assert invoke(fallback, 'open', root, root / path, unavailable=unavailable) == {'rc': 0, 'error': 0}


@pytest.mark.parametrize('operation', ['open', 'mkdir', 'unlink', 'rmdir', 'chmod', 'setattr', 'symlink'])
def test_hard_kernel_refusal_never_falls_back(fallback, tree, operation):
    root, _ = tree
    result = invoke(fallback, operation, root, root / 'a/b/file', unavailable=errno.EPERM)
    assert result == {'rc': -1, 'error': errno.EPERM}
    assert (root / 'a/b/file').read_bytes() == b'payload'


@pytest.mark.parametrize('operation', ['open', 'mkdir', 'unlink', 'rmdir', 'chmod', 'setattr', 'symlink'])
@pytest.mark.parametrize('escape', ['prefix', 'symlink'])
def test_mutation_or_open_cannot_reach_an_outside_parent(fallback, tree, operation, escape):
    root, outside = tree
    path = outside / 'secret' if escape == 'prefix' else root / 'link-outside/secret'
    result = invoke(fallback, operation, root, path)
    assert result['rc'] == -1
    assert (outside / 'secret').read_bytes() == b'unchanged'


@pytest.mark.parametrize('operation', ['rename', 'rename-excl', 'link'])
@pytest.mark.parametrize('side', ['source', 'destination'])
def test_both_paths_must_be_confined_before_two_name_operation(fallback, tree, operation, side):
    root, outside = tree
    source, destination = {
        'source': (outside / 'secret', root / 'a/b/other'),
        'destination': (root / 'a/b/file', outside / 'other'),
    }[side]
    assert invoke(fallback, operation, root, source, destination)['rc'] == -1
    assert (outside / 'secret').read_bytes() == b'unchanged' and not destination.exists()


@pytest.mark.parametrize('operation', ['rename', 'rename-excl', 'link'])
def test_two_name_operation_preserves_bytes_inside_export(fallback, tree, operation):
    root, _ = tree
    source, destination = root / 'a/b/file', root / 'a/b/other'
    assert invoke(fallback, operation, root, source, destination)['rc'] == 0
    assert destination.read_bytes() == b'payload'
    assert source.exists() == (operation == 'link')


@pytest.mark.parametrize('operation', ['mkdir', 'unlink', 'rmdir', 'chmod', 'setattr', 'symlink'])
def test_metadata_fallback_changes_only_the_requested_leaf(fallback, tree, operation):
    root, _ = tree
    path = root / 'a/b/new' if operation in ('mkdir', 'symlink') else root / 'a/b/file'
    if operation == 'rmdir':
        path = root / 'empty'
        path.mkdir()
    assert invoke(fallback, operation, root, path)['rc'] == 0
    verify_metadata(operation, path)


def verify_metadata(operation, path):
    """Check filesystem effects independently of the returned status."""
    if operation in ('unlink', 'rmdir'):
        assert not path.exists()
    elif operation == 'mkdir':
        assert path.is_dir() and stat.S_IMODE(path.stat().st_mode) == 0o751
    elif operation == 'symlink':
        assert path.readlink() == Path('../target')
    elif operation == 'chmod':
        assert stat.S_IMODE(path.stat().st_mode) == 0o751
    else:
        assert path.stat().st_mtime == 1234567891
