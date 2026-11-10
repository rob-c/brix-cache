"""Tree-copy policy uses local state faithfully and confines untrusted names."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def tree_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    return compile_client_contract(root, tmp_path_factory.mktemp('root-recursive-native'),
        'tests/c/root_recursive_native_test.c', ('brix_dirlist', 'copy_one_r2l', 'copy_one_l2r',
        'brix_rm', 'brix_rmdir', 'brix_rmtree', 'brix_mkdir', 'brix_stat', 'brix_query_cksum'))


@pytest.fixture
def tree_run(tree_binary, tmp_path):
    def run(entries, operation='download', mode='normal', expected=0, local=None):
        listing = tmp_path / 'entries'
        listing.write_text(''.join(f'{name} {kind}\n' for name, kind in entries))
        result = subprocess.run([str(tree_binary), operation, mode,
            str(local or tmp_path / 'local'), str(expected), ''], capture_output=True,
            text=True, timeout=10, env=dict(os.environ, BRIX_TREE_LIST=str(listing)))
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout + result.stderr
    return run


def test_download_preserves_tree_and_filters_files(tree_run, tmp_path):
    output = tree_run([('.', 1), ('..', 1), ('keep', 0), ('sub', 1), ('skip.omit', 0)])
    assert (tmp_path / 'local/keep').read_bytes() == b'payload'
    assert (tmp_path / 'local/sub/nested').read_bytes() == b'payload'
    assert not (tmp_path / 'local/skip.omit').exists()
    assert output.count('DOWNLOAD ') == 2


@pytest.mark.parametrize('kind,expected', [(0, 7), (2, -1), (3, -1)])
def test_only_regular_file_stat_sizes_are_trusted(tree_run, kind, expected):
    assert f'expected={expected}' in tree_run([('file', kind)])


@pytest.mark.parametrize('mode', ['dry', 'mirror-dry'])
def test_dry_run_does_not_create_destination(tree_run, tmp_path, mode):
    output = tree_run([('file', 0), ('sub', 1)], mode=mode)
    assert 'DOWNLOAD ' not in output and '[dry-run] copy ' in output
    assert not (tmp_path / 'local').exists()


@pytest.mark.parametrize('mode,expected_copies', [('sync', 0), ('cksum', 0), ('different', 1),
                                               ('bad-algo', 1), ('query-error', 1)])
@pytest.mark.parametrize('operation', ['download', 'upload'])
def test_sync_only_skips_proven_equal_content(tree_run, tmp_path, mode, expected_copies, operation):
    local = tmp_path / 'local'
    local.mkdir()
    (local / 'keep').write_bytes(b'payload')
    output = tree_run([('keep', 0)], operation=operation, mode=mode)
    prefix = 'DOWNLOAD ' if operation == 'download' else 'UPLOAD '
    assert output.count(prefix) == expected_copies


@pytest.mark.parametrize('mode', ['list-error', 'copy-error', 'long-rel', 'long-remote', 'long-local'])
def test_download_failures_stop_before_mirror_deletion(tree_run, mode):
    tree_run([('keep', 0)], mode=mode, expected=-1)


def test_existing_nondirectory_parent_is_preserved(tree_run, tmp_path):
    local = tmp_path / 'local'
    local.write_text('preserve')
    tree_run([('keep', 0)], local=local / 'child', expected=-1)
    assert local.read_text() == 'preserve'


def test_local_mirror_deletes_extras_without_following_symlinks(tree_run, tmp_path):
    local = tmp_path / 'local'
    (local / 'extra/sub').mkdir(parents=True)
    (local / 'extra/sub/data').write_text('obsolete')
    (local / 'skip.omit').write_text('protected')
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'data').write_text('preserved')
    (local / 'escape').symlink_to(outside, target_is_directory=True)
    tree_run([('keep', 0)], mode='mirror')
    assert sorted(p.name for p in local.iterdir()) == ['keep', 'skip.omit']
    assert (outside / 'data').read_text() == 'preserved'


@pytest.mark.parametrize('mode', ['normal', 'remove', 'dry'])
def test_upload_skips_symlinks_and_special_files(tree_run, tmp_path, mode):
    local = tmp_path / 'local'
    (local / 'sub').mkdir(parents=True)
    (local / 'sub/file').write_text('payload')
    (local / 'skip.omit').write_text('protected')
    (local / 'loop').symlink_to(local, target_is_directory=True)
    os.mkfifo(local / 'pipe')
    output = tree_run([], operation='upload', mode=mode)
    assert output.count('UPLOAD ') == (0 if mode == 'dry' else 1)
    assert (local / 'loop').is_symlink() and (local / 'skip.omit').exists()
    assert (local / 'sub/file').exists() == (mode != 'remove')


def test_remove_source_runs_only_after_successful_download(tree_run):
    output = tree_run([('sub', 1), ('keep', 0)], mode='remove')
    assert 'REMOVE /remote/sub/nested' in output and 'RMDIR /remote/sub' in output
    assert output.index('DOWNLOAD /remote/keep') < output.index('REMOVE /remote/keep')


@pytest.mark.parametrize('mode', ['normal', 'dry', 'delete-error', 'stat-dir', 'stat-error',
                                 'list-error', 'long-rel', 'long-local', 'long-remote'])
def test_remote_mirror_retains_existing_and_excluded_entries(tree_run, tmp_path, mode):
    local = tmp_path / 'local'
    local.mkdir()
    (local / 'keep').write_text('payload')
    output = tree_run([('.', 1), ('..', 1), ('keep', 0), ('skip.omit', 0),
                      ('extra', 0), ('sub', 1), ('unknown', 3)], operation='mirror', mode=mode)
    assert 'REMOVE /remote/keep' not in output and 'REMOVE /remote/skip.omit' not in output
    if mode == 'normal':
        assert 'REMOVE /remote/extra' in output and 'RMTREE /remote/sub' in output
        assert 'STAT /remote/unknown' in output


@pytest.mark.parametrize('name', ['../escape', 'sub/../../escape', '/absolute'])
@pytest.mark.parametrize('operation', ['download', 'mirror'])
def test_untrusted_remote_names_never_escape_tree(tree_run, name, operation):
    output = tree_run([(name, 0)], operation=operation,
                      expected=-1 if operation == 'download' else 0)
    assert 'DOWNLOAD ' not in output and 'REMOVE ' not in output and 'RMTREE ' not in output
