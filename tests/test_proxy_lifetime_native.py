"""Proxy defaults, expiry and best-effort shredding use only private fixture files."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from test_gftp_gsi_native import credential, proxy_files
from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def lifetime_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    return compile_client_contract(root, tmp_path_factory.mktemp('proxy-lifetime'),
        'tests/c/proxy_lifetime_native_test.c', ('getpwuid', 'ASN1_TIME_diff', 'write', 'unlink'))


def invoke(binary, action, mode, path, root):
    result = subprocess.run([str(binary), action, mode, str(path), str(root)],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.mark.parametrize('action', ['info', 'remaining'])
@pytest.mark.parametrize('mode', ['normal', 'default', 'expired'])
def test_proxy_inspection_and_default_selection(lifetime_binary, proxy_files, action, mode):
    text = invoke(lifetime_binary, action, mode, proxy_files / 'valid', proxy_files)
    assert text.startswith('RESULT 0 ')
    if action == 'remaining':
        left = int(text.split()[2])
        assert (left < 0) == (mode == 'expired')
    else:
        assert 'finite-gsi-signer' in text and ('EXPIRED' in text) == (mode == 'expired')


@pytest.mark.parametrize('action', ['info', 'remaining'])
@pytest.mark.parametrize('name', ['missing', 'empty', 'key', 'writable', 'symlink', 'directory'])
def test_unsafe_or_unparseable_proxy_cannot_be_inspected(lifetime_binary, proxy_files, action, name):
    assert invoke(lifetime_binary, action, 'normal', proxy_files / name, proxy_files).startswith('RESULT -1 ')


@pytest.mark.parametrize('mode', ['invalid-time', 'null-output'])
def test_failed_lifetime_does_not_overwrite_output(lifetime_binary, proxy_files, mode):
    assert invoke(lifetime_binary, 'remaining', mode, proxy_files / 'valid', proxy_files) == 'RESULT -1 7654321\n'


def test_unavailable_time_does_not_invent_validity(lifetime_binary, proxy_files):
    text = invoke(lifetime_binary, 'info', 'invalid-time', proxy_files / 'valid', proxy_files)
    assert text.startswith('RESULT 0 ') and 'validity' not in text


@pytest.mark.parametrize('mode', ['normal', 'default', 'short-write', 'write-error', 'write-zero', 'unlink-error'])
@pytest.mark.parametrize('size', [0, 19, 8193])
def test_proxy_destroy_shreds_then_unlinks_and_reports_refusal(lifetime_binary, tmp_path, mode, size):
    path = tmp_path / 'proxy'
    path.write_bytes(b'x' * size)
    path.chmod(0o600)
    result = invoke(lifetime_binary, 'destroy', mode, path, tmp_path).split()
    rc, code, exists, writes = map(int, result[1:])
    assert (rc, exists) == ((-1, 1) if mode == 'unlink-error' else (0, 0))
    assert bool(code) == (mode == 'unlink-error')
    assert (writes > 0) == (size > 0)


def test_missing_proxy_destruction_reports_failure(lifetime_binary, tmp_path):
    assert invoke(lifetime_binary, 'missing-destroy', 'normal', tmp_path / 'missing', tmp_path) == 'RESULT -1\n'


@pytest.mark.parametrize('mode', ['environment', 'passwd', 'null-options'])
def test_proxy_creation_resolves_explicit_environment_and_private_home(lifetime_binary, tmp_path, mode):
    cert, key = credential()
    directory = tmp_path / '.globus'
    directory.mkdir()
    (directory / 'usercert.pem').write_bytes(cert)
    (directory / 'userkey.pem').write_bytes(key)
    assert invoke(lifetime_binary, 'create', mode, tmp_path / 'proxy', tmp_path) == 'RESULT 0 0\n'


@pytest.mark.parametrize('mode', ['normal', 'unset'])
def test_default_proxy_name_is_owned_by_effective_user(lifetime_binary, tmp_path, mode):
    text = invoke(lifetime_binary, 'default-path', mode, tmp_path / 'proxy', tmp_path)
    expected = f'/tmp/x509up_u{os.geteuid()}' if mode == 'unset' else str(tmp_path / 'proxy')
    assert text.strip() == expected
