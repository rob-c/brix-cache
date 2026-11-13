"""Ceph rename verifies data and metadata before deleting the source."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def rename(server_native_compile):
    wrappers = ('malloc', 'calloc', 'realloc', 'strdup', 'strndup', 'ngx_calloc',
        'rados_stat', 'rados_read', 'rados_write', 'rados_write_full', 'rados_remove',
        'rados_getxattrs', 'rados_getxattrs_next', 'rados_getxattrs_end', 'rados_setxattr',
        'rados_nobjects_list_open', 'rados_nobjects_list_next', 'rados_nobjects_list_close',
        'sd_ceph_striper_create', 'sd_ceph_striper_stat', 'sd_ceph_striper_read',
        'sd_ceph_striper_write', 'sd_ceph_striper_remove', 'sd_ceph_striper_listxattr',
        'sd_ceph_striper_getxattr', 'sd_ceph_striper_setxattr')
    binary = server_native_compile('ceph-rename', 'tests/c/ceph_rename_native_test.c',
                                    ['-Wl,--wrap=' + name for name in wrappers])
    def run(mode='normal', striped=0, size=7, error=0, source=None):
        if source is None:
            source = int(error != 0)
        result = subprocess.run([str(binary), mode, str(striped), str(size), str(error), str(source)],
                                capture_output=True, text=True, timeout=15)
        if result.returncode == 77:
            pytest.skip('configured server has no Ceph striper driver')
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout
    return run


@pytest.mark.parametrize('striped', [0, 1])
@pytest.mark.parametrize('size', [0, 7, 4194310])
@pytest.mark.parametrize('mode', ['normal', 'replace'])
def test_complete_copy_retains_bytes_and_user_metadata(rename, striped, size, mode):
    output = rename(mode=mode, striped=striped, size=size)
    assert f'destination=1 size={size} attrs=1' in output and 'source_removes=1' in output


@pytest.mark.parametrize('striped', [0, 1])
@pytest.mark.parametrize('mode,error', [('read-error', errno.EACCES), ('write-error', errno.ENOSPC),
    ('shrink', errno.EIO), ('attrs-open', errno.EACCES), ('attrs-next', errno.EIO),
    ('attrs-set', errno.EIO), ('verify-stat', errno.EIO), ('verify-size', errno.EIO),
    ('verify-missing', errno.EIO), ('allocation0', errno.ENOMEM)])
def test_failed_copy_removes_partial_destination_and_preserves_source(rename, striped, mode, error):
    output = rename(mode=mode, striped=striped, error=error)
    assert 'source=1 destination=0' in output and 'source_removes=0' in output
    assert 'destination_removes=1' in output


@pytest.mark.parametrize('striped', [0, 1])
@pytest.mark.parametrize('mode,error', [('source-stat', errno.EACCES), ('destination-stat', errno.EIO),
    ('destination-remove', errno.EACCES), ('exclusive', errno.EEXIST)])
def test_precondition_failure_cannot_mutate_source(rename, striped, mode, error):
    assert 'source_removes=0' in rename(mode=mode, striped=striped, error=error)


@pytest.mark.parametrize('striped', [0, 1])
def test_failed_final_remove_retains_both_verified_objects(rename, striped):
    assert 'source=1 destination=1 size=7 attrs=1' in rename(mode='source-remove', striped=striped, error=errno.EACCES)


@pytest.mark.parametrize('striped', [0, 1])
def test_cleanup_failure_preserves_original_error_and_source(rename, striped):
    assert 'source=1 destination=1' in rename(mode='cleanup-error', striped=striped, error=errno.EIO)


@pytest.mark.parametrize('mode', ['allocation1', 'allocation2'])
def test_striper_metadata_allocation_failure_cleans_up_copy(rename, mode):
    assert 'source=1 destination=0' in rename(mode=mode, striped=1, error=errno.ENOMEM)


@pytest.mark.parametrize('mode,error', [('missing', errno.ENOENT), ('directory', errno.EISDIR)])
def test_absent_source_and_synthetic_directory_are_distinct(rename, mode, error):
    assert 'writes=0' in rename(mode=mode, error=error, source=0)


@pytest.mark.parametrize('mode', ['unsafe-source', 'unsafe-destination'])
def test_traversal_is_rejected_before_any_cluster_probe(rename, mode):
    assert 'probes=0' in rename(mode=mode, error=errno.EINVAL)


def test_same_object_is_a_noop(rename):
    assert 'probes=0' in rename(mode='same', source=1)


@pytest.mark.parametrize('striped', [0, 1])
def test_short_reads_are_reassembled_without_losing_data(rename, striped):
    assert 'reads=3' in rename(mode='short-read', striped=striped)
