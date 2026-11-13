"""Packed-block namespace operations preserve metadata and reject unsafe changes."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def namespace(server_native_compile):
    return server_native_compile('pblock-namespace', 'tests/c/pblock_namespace_native_test.c',
        ['-Wl,--wrap=' + name for name in ('open64', 'fsync',
            'pblock_catalog_opendir', 'pblock_catalog_readdir')])


def invoke(binary, tmp_path, operation, mode='normal', expected=0, options=''):
    (tmp_path / 'pblock.opts').write_text(options + '\n')
    result = subprocess.run([str(binary), str(tmp_path), operation, mode, str(expected)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('operation', ['rename', 'unlink'])
@pytest.mark.parametrize('options', ['', 'lab=1&nearline=1&locks=1&trash=1&audit=1'])
def test_success_updates_catalog_and_optional_side_tables(namespace, tmp_path, operation, options):
    invoke(namespace, tmp_path, operation, options=options)


@pytest.mark.parametrize('operation,mode,error', [('rename', 'missing', errno.ENOENT),
    ('rename', 'noreplace', errno.EEXIST), ('rename', 'lock-source', errno.EBUSY),
    ('rename', 'lock-target', errno.EBUSY), ('unlink', 'missing', errno.ENOENT),
    ('unlink', 'rmdir-file', errno.ENOTDIR), ('unlink', 'directory', errno.EISDIR),
    ('unlink', 'nonempty', errno.ENOTEMPTY), ('unlink', 'lock-source', errno.EBUSY)])
def test_namespace_refusal_preserves_existing_names_and_bytes(namespace, tmp_path, operation, mode, error):
    invoke(namespace, tmp_path, operation, mode, error, 'locks=1')


@pytest.mark.parametrize('mode,error', [('normal', 0), ('missing', errno.ENOENT),
    ('transform', errno.EIO), ('hidden', errno.ENOENT)])
def test_stat_respects_transform_identity_and_visibility(namespace, tmp_path, mode, error):
    invoke(namespace, tmp_path, 'stat', mode, error, 'lab=1')


@pytest.mark.parametrize('mode,error', [('normal', 0), ('missing', errno.ENOENT),
    ('file', errno.ENOTDIR), ('iterator-open', errno.EIO), ('iterator-read', errno.EIO),
    ('list-hidden', 0)])
def test_directory_iterator_separates_errors_hidden_entries_and_eof(namespace, tmp_path, mode, error):
    invoke(namespace, tmp_path, 'directory', mode, error, 'lab=1')


@pytest.mark.parametrize('mode,error', [('normal', 0), ('sync-open', errno.EACCES),
    ('sync-zero', errno.EIO), ('sync-error', errno.ENOSPC)])
def test_directory_durability_barrier_closes_its_descriptor(namespace, tmp_path, mode, error):
    invoke(namespace, tmp_path, 'sync', mode, error)


@pytest.mark.parametrize('mode', ['now', 'omit'])
def test_attribute_update_preserves_unspecified_owners(namespace, tmp_path, mode):
    invoke(namespace, tmp_path, 'setattr', mode)
