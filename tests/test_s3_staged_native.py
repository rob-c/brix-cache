"""S3 staged writes preserve credentials, atomic predicates, and MPU cleanup."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def s3_staged_binary(server_native_compile):
    return server_native_compile('s3-staged', 'tests/c/s3_staged_native_test.c',
        ['-Wl,--wrap=' + name for name in
         ('malloc', 'calloc', 'realloc', 'strdup', 'strndup', 'ngx_calloc')])


@pytest.fixture
def staged(s3_staged_binary):
    def run(mode='normal', phase='none', status=200, identity='service', declared=-1,
            size=3, condition=0, allocation='', expected=0):
        arguments = [mode, phase, status, identity, declared, size, condition, allocation, expected]
        result = subprocess.run([str(s3_staged_binary), *map(str, arguments)],
                                capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout
    return run


@pytest.mark.parametrize('identity', ['service', 'user', 'empty'])
@pytest.mark.parametrize('declared,size', [(-1, 0), (3, 3), (-1, 3), (20000000, 3), (20000000, 0),
                                        (-1, 17000000)])
def test_real_single_and_multipart_publishes_preserve_identity(staged, identity, declared, size):
    output = staged(identity=identity, declared=declared, size=size)
    assert 'VERDICT 0' in output and 'abort=0' in output
    assert ('put=1' if declared <= 16000000 and size <= 16000000 else 'complete=1') in output


@pytest.mark.parametrize('condition', [1, 2])
@pytest.mark.parametrize('declared', [3, 20000000])
def test_atomic_predicate_is_signed_on_publish(staged, condition, declared):
    output = staged(condition=condition, declared=declared, identity='user')
    assert 'atomic=1' in output
    assert ('if-none-match: *' if condition == 1 else 'if-match: "original"') in output


@pytest.mark.parametrize('condition,error', [(1, errno.EEXIST), (2, errno.ECANCELED)])
@pytest.mark.parametrize('declared,phase', [(3, 'put'), (20000000, 'complete')])
def test_failed_precondition_remains_atomic(staged, condition, error, declared, phase):
    output = staged(condition=condition, declared=declared, phase=phase, status=412, expected=error)
    assert 'atomic=1' in output


@pytest.mark.parametrize('mode', ['etag-empty', 'etag-long', 'etag-null'])
def test_invalid_etag_never_publishes(staged, mode):
    assert 'put=0' in staged(mode=mode, condition=2, expected=errno.EINVAL)


def test_metadata_predicate_is_not_emulated(staged):
    assert 'put=0' in staged(condition=3, expected=errno.ENOTSUP)


def test_unconditional_lost_reply_retries_identical_put_once(staged):
    assert 'put=2' in staged(mode='lost-once', phase='put', status=-1)


@pytest.mark.parametrize('condition', [1, 2])
def test_conditional_lost_reply_never_replays(staged, condition):
    assert 'put=1' in staged(mode='lost-once', phase='put', status=-1,
                            condition=condition, expected=errno.EIO)


@pytest.mark.parametrize('phase', ['create', 'part', 'complete'])
@pytest.mark.parametrize('status', [-1, 403, 500])
def test_multipart_failures_abort_before_publication(staged, phase, status):
    output = staged(phase=phase, status=status, declared=20000000, expected=errno.EIO)
    assert ('abort=0' if phase == 'create' else 'abort=1') in output


@pytest.mark.parametrize('mode', ['xml-empty', 'xml-unclosed', 'xml-missing', 'xml-null'])
def test_malformed_multipart_id_cannot_create_writable_handle(staged, mode):
    output = staged(mode=mode, declared=20000000, expected=errno.EIO)
    assert 'part=0 complete=0 put=0' in output


def test_missing_part_etag_prevents_completion(staged):
    output = staged(mode='no-etag', declared=20000000, expected=errno.EIO)
    assert 'complete=0 put=0 abort=1' in output


@pytest.mark.parametrize('allocation,error', [('open:calloc:0', errno.EIO),
    ('open:calloc:1', errno.ENOMEM), ('open:calloc:2', errno.ENOMEM),
    ('open:malloc:0', errno.EIO), ('write:realloc:0', errno.EIO)])
def test_allocation_failures_retain_abortable_state(staged, allocation, error):
    size = 3000000 if allocation.startswith('write') else 3
    assert 'put=0' in staged(allocation=allocation, size=size, expected=error)


def test_missing_caller_keys_never_use_service_identity(staged):
    assert 'create=0 part=0 complete=0 put=0' in staged(identity='deny', expected=errno.EACCES)


def test_nonsequential_write_is_refused(staged):
    assert 'put=0' in staged(mode='offset', expected=errno.EIO)


@pytest.mark.parametrize('allocation,declared,size,error', [
    ('open:malloc:0', 20000000, 3, errno.EIO),
    ('open:calloc:1', 20000000, 3, errno.ENOMEM),
    ('open:calloc:2', 20000000, 3, errno.ENOMEM),
    ('write:malloc:0', -1, 17000000, errno.EIO),
    ('write:realloc:0', -1, 17000000, errno.EIO),
    ('commit:realloc:0', 20000000, 3, errno.EIO),
    ('commit:malloc:0', 20000000, 3, errno.EIO),
])
def test_multipart_allocation_failure_aborts_created_upload(staged, allocation, declared, size, error):
    output = staged(allocation=allocation, declared=declared, size=size, expected=error)
    assert 'create=1' in output and 'complete=0 put=0 abort=1' in output


@pytest.mark.parametrize('phase', ['create', 'part', 'complete'])
@pytest.mark.parametrize('status', [-1, 403])
def test_lazy_upgrade_failure_remains_abortable(staged, phase, status):
    output = staged(phase=phase, status=status, size=17000000, expected=errno.EIO)
    assert 'create=1' in output and 'put=0' in output
    assert ('abort=0' if phase == 'create' else 'abort=1') in output
