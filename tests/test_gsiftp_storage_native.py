"""Origin storage validates metadata, bounds reads and cleans failed publications."""

import errno
from pathlib import Path
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def storage(server_native_compile):
    boundaries = ['gftp_session_open', 'gftp_session_close', 'gftp_command', 'gftp_expect',
        'gftp_slurp', 'gftp_retrieve', 'gftp_store', 'tmpfile64', 'RAND_bytes', 'pread64', 'pwrite64',
        'malloc', 'calloc', 'realloc', 'strdup', 'strndup', 'ngx_calloc']
    includes = ['-I' + str(Path(__file__).resolve().parents[1] / 'tests/c')]
    return server_native_compile('gsiftp-storage', 'tests/c/gsiftp_storage_native_test.c',
        includes + [f'-Wl,--wrap={name}' for name in boundaries])


def invoke(binary, action, mode='normal', path='/file', size='7', ordinal=0):
    result = subprocess.run([str(binary), action, mode, path, size, str(ordinal)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return {key: int(value) for key, value in
            (line.split('=', 1) for line in result.stdout.splitlines())}


@pytest.mark.parametrize('action', ['stat', 'read', 'stage', 'dir', 'mkdir', 'unlink', 'rmdir', 'rename', 'copy'])
def test_storage_success_preserves_bytes_and_balances_sessions(storage, action):
    result = invoke(storage, action)
    assert result['rc'] == (7 if action == 'read' else 0)
    assert result['published'] == int(action in ('stage', 'rename', 'copy'))


@pytest.mark.parametrize('action', ['stat', 'read', 'stage', 'dir', 'mkdir', 'unlink', 'rmdir', 'rename', 'copy'])
@pytest.mark.parametrize('path', ['/../escape', '/bad\r\nDELE /victim', '/a/./file', '/a\\file', 'relative'])
def test_untrusted_paths_never_open_an_origin_session(storage, action, path):
    result = invoke(storage, action, path=path)
    assert result['rc'] == -1 and result['opened'] == 0 and result['published'] == 0


@pytest.mark.parametrize('action', ['stat', 'read', 'stage', 'dir', 'mkdir', 'unlink', 'rmdir', 'rename', 'copy'])
def test_fallback_denial_stops_before_origin_access(storage, action):
    result = invoke(storage, action, 'denied')
    assert result['rc'] == -1 and result['errno'] == errno.EACCES and result['opened'] == 0


@pytest.mark.parametrize('action', ['stat', 'read', 'stage', 'dir', 'mkdir', 'unlink', 'rmdir', 'rename', 'copy'])
def test_session_failure_never_publishes(storage, action):
    result = invoke(storage, action, 'session')
    assert result['rc'] == -1 and result['errno'] == errno.ECONNREFUSED and result['published'] == 0


@pytest.mark.parametrize('size', ['', 'garbage', '-1', '7tail', '18446744073709551616', '9223372036854775808'])
def test_invalid_size_is_a_protocol_error(storage, size):
    result = invoke(storage, 'stat', size=size)
    assert result['rc'] == -1 and result['errno'] == errno.EPROTO


@pytest.mark.parametrize('mode', ['directory', 'no-mtime', 'bad-mtime'])
def test_optional_metadata_and_directory_fallback(storage, mode):
    assert invoke(storage, 'stat', mode)['rc'] == 0


@pytest.mark.parametrize('size', [' 7 ', '+7', '0007'])
def test_size_whitespace_and_numeric_forms(storage, size):
    assert invoke(storage, 'stat', size=size)['rc'] == 0


@pytest.mark.parametrize('mode,error', [('negative', errno.EINVAL), ('overflow', errno.EOVERFLOW),
    ('buffer', errno.ENOMEM), ('retrieve', errno.EIO), ('negative-block', errno.EPROTO),
    ('outside-block', errno.EPROTO), ('write-flag', errno.EROFS), ('directory', errno.EISDIR)])
def test_read_failures_preserve_buffer_guards(storage, mode, error):
    result = invoke(storage, 'read', mode)
    assert result['rc'] == -1 and result['errno'] == error


@pytest.mark.parametrize('mode,count', [('empty', 0), ('eof', 0), ('short', 6)])
def test_empty_and_short_reads_report_exact_counts(storage, mode, count):
    assert invoke(storage, 'read', mode)['rc'] == count


@pytest.mark.parametrize('action', ['stage', 'copy'])
@pytest.mark.parametrize('mode', ['write-short', 'write-eintr', 'read-eintr'])
def test_scratch_io_retries_and_partial_progress(storage, action, mode):
    result = invoke(storage, action, mode)
    assert result['rc'] == 0 and result['published'] == 1


@pytest.mark.parametrize('action', ['stage', 'copy'])
@pytest.mark.parametrize('mode', ['scratch', 'random', 'write-zero', 'write-error',
    'read-error', 'store', 'rename-from', 'rename-to'])
def test_failed_publication_never_renames_partial_data(storage, action, mode):
    result = invoke(storage, action, mode)
    assert result['rc'] == -1 and result['published'] == 0
    if result['stored']:
        assert result['deleted'] == 1


@pytest.mark.parametrize('mode,error', [('exists', errno.EEXIST), ('etag', errno.ENOTSUP), ('negative', errno.EINVAL)])
def test_staged_preconditions_refuse_without_remote_writes(storage, mode, error):
    result = invoke(storage, 'stage', mode)
    assert result['rc'] == -1 and result['errno'] == error and result['stored'] == 0


def test_create_if_absent_publishes_after_missing_probe(storage):
    result = invoke(storage, 'stage', 'absent')
    assert result['rc'] == 0 and result['published'] == 1


@pytest.mark.parametrize('mode,error', [('short', errno.EIO), ('same', errno.EINVAL), ('retrieve', errno.EIO)])
def test_copy_cannot_publish_truncated_or_self_replacing_data(storage, mode, error):
    result = invoke(storage, 'copy', mode)
    assert result['rc'] == -1 and result['errno'] == error and result['stored'] == 0


@pytest.mark.parametrize('action', ['read', 'stage', 'dir'])
@pytest.mark.parametrize('ordinal', [0, 1])
def test_object_allocation_failure_releases_sessions(storage, action, ordinal):
    result = invoke(storage, action, 'allocation', ordinal=ordinal)
    assert result['rc'] == -1 and result['errno'] == errno.ENOMEM


@pytest.mark.parametrize('action', ['mkdir', 'unlink', 'rmdir'])
@pytest.mark.parametrize('mode,error', [('reply-missing', errno.ENOENT), ('reply-bad', errno.EIO), ('command', errno.EIO)])
def test_namespace_reply_classes_map_to_errno(storage, action, mode, error):
    result = invoke(storage, action, mode)
    assert result['rc'] == -1 and result['errno'] == error


def test_failed_directory_listing_does_not_return_a_handle(storage):
    result = invoke(storage, 'dir', 'listing')
    assert result['rc'] == -1 and result['errno'] == errno.EIO
