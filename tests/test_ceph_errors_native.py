"""Ceph driver errors preserve errno, cached state, and connection ownership."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def ceph(server_native_compile):
    wrappers = ('malloc', 'calloc', 'realloc', 'strdup', 'strndup', 'ngx_calloc', 'ngx_pcalloc',
        'rados_create', 'rados_conf_read_file', 'rados_conf_set', 'rados_connect', 'rados_ioctx_create',
        'rados_shutdown', 'rados_ioctx_destroy', 'rados_read', 'rados_write', 'rados_trunc',
        'rados_stat', 'rados_remove', 'rados_cluster_stat', 'rados_getxattr', 'rados_setxattr',
        'rados_rmxattr', 'rados_getxattrs', 'rados_getxattrs_next', 'rados_getxattrs_end',
        'sd_ceph_enumerate_io')
    binary = server_native_compile('ceph-errors', 'tests/c/ceph_errors_native_test.c',
                                    ['-Wl,--wrap=' + name for name in wrappers])
    def run(operation, failure='none', error=errno.EACCES, skip=0, expected=0):
        result = subprocess.run([str(binary), operation, failure, str(error), str(skip), str(expected)],
                                capture_output=True, text=True, timeout=10)
        if result.returncode == 77:
            pytest.skip('configured server has no Ceph driver')
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout
    return run


@pytest.mark.parametrize('operation', ['connection', 'default-user', 'bare-user', 'null-config', 'null-pool'])
def test_connection_configuration_and_last_pin_ownership(ceph, operation):
    ceph(operation)


@pytest.mark.parametrize('failure', ['create', 'config', 'connect', 'ioctx', 'allocation'])
@pytest.mark.parametrize('error', [errno.EACCES, errno.EIO, errno.ETIMEDOUT])
def test_failed_connection_releases_only_acquired_resources(ceph, failure, error):
    ceph('connection', failure=failure, error=error)


@pytest.mark.parametrize('operation,failure', [('pread', 'read'), ('preadv', 'read'),
    ('preadv2', 'read'), ('pwrite', 'write'), ('ftruncate', 'truncate'), ('fstat', 'stat'), ('space', 'space')])
@pytest.mark.parametrize('error', [0, errno.EACCES, errno.EIO, errno.ETIMEDOUT])
def test_data_plane_failures_preserve_errno_and_cached_size(ceph, operation, failure, error):
    ceph(operation, failure=failure if error else 'none', error=error, expected=error)


@pytest.mark.parametrize('operation,expected', [('null-space', errno.EINVAL), ('disconnected', errno.ENOTCONN)])
def test_capacity_requires_live_connection_and_output(ceph, operation, expected):
    ceph(operation, expected=expected)


@pytest.mark.parametrize('operation', ['staged-write', 'staged-commit'])
def test_staged_success_and_abort_cleanup(ceph, operation):
    assert 'removes=1' in ceph(operation)


@pytest.mark.parametrize('failure,error', [('truncate', errno.EACCES), ('truncate', errno.EIO),
                                        ('write', errno.EACCES), ('write', errno.ENOSPC)])
def test_staged_failure_is_reported_without_claiming_success(ceph, failure, error):
    ceph('staged-write', failure=failure, error=error, expected=error)


@pytest.mark.parametrize('skip', [0, 1])
def test_staged_allocation_failure_precedes_remote_mutation(ceph, skip):
    assert 'truncates=0' in ceph('staged-write', failure='allocation', skip=skip, expected=errno.ENOMEM)


def test_staged_traversal_cannot_reach_rados(ceph):
    assert 'truncates=0' in ceph('staged-unsafe', expected=errno.EINVAL)


def test_staged_conditional_publish_is_explicitly_unsupported(ceph):
    ceph('staged-conditional', expected=errno.ENOTSUP)


@pytest.mark.parametrize('operation', ['open', 'open-create', 'open-truncate', 'open-pinned'])
def test_open_metadata_and_handle_pin_lifecycle(ceph, operation):
    ceph(operation)


@pytest.mark.parametrize('operation', ['open', 'open-create', 'open-pinned'])
@pytest.mark.parametrize('error', [errno.EACCES, errno.EIO, errno.ETIMEDOUT])
def test_failed_probe_cannot_create_a_handle_or_pin_identity(ceph, operation, error):
    ceph(operation, failure='stat', error=error, expected=error)


@pytest.mark.parametrize('operation', ['open', 'open-pinned'])
@pytest.mark.parametrize('skip', [0, 1])
def test_open_allocation_failure_does_not_pin_connection(ceph, operation, skip):
    ceph(operation, failure='allocation', skip=skip, expected=errno.ENOMEM)


def test_create_permits_absent_object_and_reports_zero_size(ceph):
    ceph('open-create', failure='stat', error=errno.ENOENT)


def test_open_of_absent_object_does_not_create_it(ceph):
    ceph('open', failure='stat', error=errno.ENOENT, expected=errno.ENOENT)


def test_exclusive_create_preserves_existing_object(ceph):
    assert 'truncates=0' in ceph('open-exclusive', expected=errno.EEXIST)


def test_open_traversal_fails_before_existence_probe(ceph):
    assert 'stats=0' in ceph('open-unsafe', expected=errno.EINVAL)


@pytest.mark.parametrize('error', [errno.EACCES, errno.ENOSPC, errno.EIO])
def test_failed_truncate_prevents_open_success(ceph, error):
    ceph('open-truncate', failure='truncate', error=error, expected=error)


@pytest.mark.parametrize('prefix', ['meta', 'oid'])
@pytest.mark.parametrize('operation,capacity', [('getattr', 0), ('getattr', 3),
    ('listattr', 0), ('listattr', 14), ('setattr', 0), ('rmattr', 0), ('stat', 0), ('remove', 0)])
def test_object_and_namespace_metadata_keep_binary_values_and_iterator_ownership(ceph, prefix, operation, capacity):
    ceph(prefix + '-' + operation, skip=capacity)


@pytest.mark.parametrize('prefix', ['meta', 'oid'])
@pytest.mark.parametrize('operation,capacity', [('getattr', 2), ('listattr', 6), ('listattr', 13)])
def test_attribute_capacity_cannot_overwrite_callers_boundary(ceph, prefix, operation, capacity):
    ceph(prefix + '-' + operation, skip=capacity, expected=errno.ERANGE)


@pytest.mark.parametrize('prefix', ['meta', 'oid'])
@pytest.mark.parametrize('operation,failure', [('getattr', 'get-attribute'), ('listattr', 'open-iterator'),
    ('listattr', 'next-attribute'), ('setattr', 'set-attribute'), ('rmattr', 'remove-attribute'),
    ('stat', 'stat'), ('remove', 'remove')])
@pytest.mark.parametrize('error', [errno.EACCES, errno.EIO])
def test_metadata_provider_errors_preserve_errno_and_close_iterators(ceph, prefix, operation, failure, error):
    ceph(prefix + '-' + operation, failure=failure, error=error, expected=error)


@pytest.mark.parametrize('operation,failure', [('read', 'read'), ('write', 'write'),
                                            ('trunc', 'truncate'), ('stat-null', 'stat')])
@pytest.mark.parametrize('error', [0, errno.EIO, errno.EACCES])
def test_oid_byte_primitives_preserve_data_and_optional_stat_outputs(ceph, operation, failure, error):
    ceph('oid-' + operation, failure=failure if error else 'none', error=error, expected=error)


@pytest.mark.parametrize('operation', ['getattr', 'listattr', 'setattr', 'rmattr', 'stat',
                                     'remove', 'mkdir', 'rmdir'])
def test_namespace_traversal_is_rejected_before_provider_access(ceph, operation):
    output = ceph('meta-' + operation + '-unsafe', expected=errno.EINVAL)
    assert 'reads=0 writes=0 truncates=0 removes=0 stats=0' in output


@pytest.mark.parametrize('operation', ['root-stat', 'mkdir', 'rmdir'])
def test_synthetic_directory_success_does_not_create_or_remove_objects(ceph, operation):
    output = ceph('meta-' + operation)
    assert 'truncates=0 removes=0 stats=0' in output


@pytest.mark.parametrize('operation,error', [('rmdir-root', errno.EBUSY),
                                          ('rmdir-nonempty', errno.ENOTEMPTY)])
def test_root_and_nonempty_prefixes_cannot_be_removed(ceph, operation, error):
    assert 'removes=0' in ceph('meta-' + operation, expected=error)


def test_failed_directory_census_cannot_claim_removal(ceph):
    assert 'removes=0' in ceph('meta-rmdir', failure='enumerate', error=errno.EIO, expected=errno.EIO)
