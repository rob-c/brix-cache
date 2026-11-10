"""Forwarded namespace requests retain policy, errno and backend ownership."""

import os
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401

# Local clean-room CMS definitions: src/net/cms/cms_internal.h.
OPS = {'chmod': 1, 'mkdir': 3, 'mkpath': 4, 'mv': 5, 'rm': 8, 'rmdir': 9, 'trunc': 23}


@pytest.fixture(scope='module')
def cms_forward(server_native_compile):
    return server_native_compile('cms-forward', 'tests/c/cms_forward_native_test.c',
        ['-Wl,--wrap=' + name for name in ('brix_vfs_backend_resolve',
            'brix_vfs_export_mkpath', 'brix_cms_fsxeq_dispatch', 'ngx_brix_cms_send_error')])


def forward(binary, root, operation, mode='normal', path='/source'):
    result = subprocess.run([str(binary), mode, str(OPS[operation]), str(root), path],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    lines = result.stdout.splitlines()
    return {key: int(value) for key, value in (item.split('=') for item in lines[0].split())}, lines[1]


@pytest.mark.parametrize('operation', OPS)
def test_success_is_silent_and_truncate_closes_once(cms_forward, tmp_path, operation):
    result, message = forward(cms_forward, tmp_path, operation)
    assert result == dict(result=0, calls=1, opens=int(operation == 'trunc'),
                          closes=int(operation == 'trunc'), overrides=1, errors=0)
    assert message == ''


@pytest.mark.parametrize('operation', OPS)
def test_backend_error_survives_cleanup(cms_forward, tmp_path, operation):
    result, message = forward(cms_forward, tmp_path, operation, 'failure')
    assert result['errors'] == 1 and message == os.strerror(28)
    assert result['closes'] == int(operation == 'trunc')


@pytest.mark.parametrize('operation', OPS)
@pytest.mark.parametrize('mode,message', [('readonly', 'Read-only file system'),
    ('no-export', 'no local storage'), ('bad-frame', 'badly formed request')])
def test_refusals_precede_operator_override_and_storage(cms_forward, tmp_path, operation, mode, message):
    result, text = forward(cms_forward, tmp_path, operation, mode)
    assert result['calls'] == result['opens'] == result['overrides'] == 0
    assert result['errors'] == 1 and text == message


@pytest.mark.parametrize('operation', OPS)
def test_operator_override_owns_the_request(cms_forward, tmp_path, operation):
    result, _ = forward(cms_forward, tmp_path, operation, 'override')
    assert result['result'] == -2 and result['overrides'] == 1
    assert result['calls'] == result['errors'] == 0


@pytest.mark.parametrize('operation', ['chmod', 'mkdir', 'rm', 'rmdir', 'mv', 'trunc'])
def test_missing_driver_slots_are_explicit(cms_forward, tmp_path, operation):
    result, message = forward(cms_forward, tmp_path, operation, 'missing')
    assert result['calls'] == result['opens'] == 0
    assert result['errors'] == int(operation != 'chmod')
    assert message == ('' if operation == 'chmod' else os.strerror(38))


@pytest.mark.parametrize('mode,error,opens,closes', [('no-truncate', 38, 0, 0),
    ('open-fail', 13, 1, 0), ('open-zero', 5, 1, 0), ('no-close', None, 1, 0)])
def test_truncate_failure_and_optional_close(cms_forward, tmp_path, mode, error, opens, closes):
    result, message = forward(cms_forward, tmp_path, 'trunc', mode)
    assert result['opens'] == opens and result['closes'] == closes
    assert message == (os.strerror(error) if error else '')


@pytest.mark.parametrize('operation', ['chmod', 'mkdir', 'mkpath', 'trunc'])
def test_invalid_numeric_mode_never_reaches_storage(cms_forward, tmp_path, operation):
    result, message = forward(cms_forward, tmp_path, operation, 'bad-mode')
    assert result['errors'] == 1 and message == 'badly formed request'
    assert result['calls'] == result['overrides'] == 0


@pytest.mark.parametrize('operation', OPS)
@pytest.mark.parametrize('mode', ['posix', 'default'])
def test_real_confined_filesystem_leg(cms_forward, tmp_path, operation, mode):
    source = tmp_path / 'source'
    seed_source(source, operation)
    result, message = forward(cms_forward, tmp_path, operation, mode)
    assert result['errors'] == 0, message
    assert result['calls'] == result['opens'] == 0
    assert_namespace(source, operation)


def seed_source(source, operation):
    if operation == 'rmdir':
        source.mkdir()
    elif operation not in ('mkdir', 'mkpath'):
        source.write_bytes(b'payload')


def assert_namespace(source, operation):
    if operation in ('mkdir', 'mkpath'):
        assert source.is_dir()
    elif operation == 'mv':
        assert not source.exists()
        assert (source.parent / 'destination').read_bytes() == b'payload'
    elif operation in ('rm', 'rmdir'):
        assert not source.exists()
    elif operation == 'trunc':
        assert source.read_bytes() == b'payload' + bytes(10)
    else:
        assert source.stat().st_mode & 0o777 == 0o750


@pytest.mark.parametrize('operation', ['chmod', 'trunc'])
def test_symlink_escape_is_refused(cms_forward, tmp_path, operation):
    root = tmp_path / 'export'; root.mkdir()
    outside = tmp_path / 'protected'; outside.write_bytes(b'untouched'); outside.chmod(0o600)
    (root / 'escape').symlink_to(outside)
    result, _ = forward(cms_forward, root, operation, 'posix', '/escape')
    assert result['errors'] == 1
    assert outside.read_bytes() == b'untouched' and outside.stat().st_mode & 0o777 == 0o600
