"""HTTP staged uploads carry caller identity and fail closed on conditional PUTs."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def staged_binary(server_native_compile):
    return server_native_compile('http-staged', 'tests/c/http_staged_native_test.c',
        ['-Wl,--wrap=' + name for name in
         ('malloc', 'calloc', 'realloc', 'strdup', 'strndup', 'ngx_calloc')])


@pytest.fixture
def staged(staged_binary):
    def run(status=201, probe=412, mode='normal', identity='service', condition='none',
            expected=0, cert_transport=True):
        arguments = [status, probe, mode, identity, condition, expected, int(cert_transport)]
        result = subprocess.run([str(staged_binary), *map(str, arguments)],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout
    return run


@pytest.mark.parametrize('status', [200, 201, 204])
@pytest.mark.parametrize('identity', ['service', 'bearer', 'proxy', 'both', 'empty'])
def test_commit_copies_credentials_and_validates_body(staged, status, identity):
    output = staged(status=status, identity=identity)
    token = 'caller-token' if identity in ('bearer', 'both') else 'service-token'
    assert 'Authorization: Bearer ' + token in output
    assert 'Content-MD5: kAFQmDzST7DWlj99KOF/cg==' in output
    assert 'calls=1 freed=1' in output and 'puts=1 deletes=0' in output
    assert ('certs=1' if identity in ('proxy', 'both') else 'certs=0') in output


@pytest.mark.parametrize('status,error', [(-1, errno.EIO), (401, errno.EACCES),
    (403, errno.EACCES), (404, errno.EIO), (412, errno.EIO), (500, errno.EIO)])
def test_failure_retains_abortable_handle_without_failover(staged, status, error):
    output = staged(status=status, expected=error)
    assert 'calls=1' in output and 'puts=1 deletes=0' in output
    assert 'secondary.test' not in output


@pytest.mark.parametrize('condition', ['absent', 'etag'])
@pytest.mark.parametrize('identity', ['service', 'proxy', 'both'])
def test_conditional_probe_and_commit_use_same_identity(staged, condition, identity):
    output = staged(condition=condition, identity=identity)
    assert 'calls=2 freed=2' in output and 'atomic=1' in output
    assert ('If-None-Match: *' if condition == 'absent' else 'If-Match: "original"') in output
    assert ('certs=0' if identity == 'service' else 'certs=2') in output


@pytest.mark.parametrize('condition,error', [('absent', errno.EEXIST), ('etag', errno.ECANCELED)])
def test_failed_atomic_precondition_is_preserved(staged, condition, error):
    output = staged(status=412, condition=condition, expected=error)
    assert 'atomic=1' in output and 'puts=1 deletes=0' in output


@pytest.mark.parametrize('probe,deletes', [(200, 1), (201, 1), (403, 0), (500, 0), (-1, 0)])
def test_unsupported_or_unproven_conditional_origin_cannot_publish(staged, probe, deletes):
    output = staged(probe=probe, condition='absent', expected=errno.ENOTSUP)
    assert f'puts=0 deletes={deletes}' in output and 'atomic=0' in output


@pytest.mark.parametrize('condition,error', [('meta', errno.ENOTSUP), ('etag-empty', errno.EINVAL),
                                          ('etag-long', errno.EINVAL), ('etag-null', errno.EINVAL)])
def test_invalid_precondition_never_reaches_origin(staged, condition, error):
    assert 'calls=0' in staged(condition=condition, expected=error)


@pytest.mark.parametrize('probe,expected,calls', [(412, 0, 3), (200, errno.ENOTSUP, 2),
                                               (500, errno.ENOTSUP, 2), (-1, errno.ENOTSUP, 2)])
def test_probe_caches_only_definitive_capability(staged, probe, expected, calls):
    assert f'calls={calls}' in staged(probe=probe, mode='twice', condition='absent', expected=expected)


@pytest.mark.parametrize('mode,error', [('oversize', errno.ENOSPC), ('calloc0', errno.ENOMEM),
    ('calloc1', errno.ENOMEM), ('realloc', errno.ENOMEM), ('write-cap', errno.ENOSPC), ('offset', errno.ESPIPE)])
def test_staging_failures_publish_nothing(staged, mode, error):
    assert 'calls=0' in staged(mode=mode, expected=error)


def test_proxy_only_identity_cannot_fall_back_to_service(staged):
    assert 'calls=0' in staged(identity='proxy', cert_transport=False, expected=errno.EACCES)


def test_growing_buffer_preserves_sequential_body(staged):
    assert 'puts=1' in staged(mode='grow')


def test_null_precondition_is_unconditional(staged):
    assert 'calls=1' in staged(condition='null')
