"""Checksum query helpers use confined files and preserve borrowed descriptor state."""

import hashlib
import subprocess
import zlib

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def query_checksum(server_native_compile):
    return server_native_compile('query-checksum', 'tests/c/query_checksum_native_test.c')


def run_query(binary, root, path, algorithm, mode, failed=False):
    result = subprocess.run([str(binary), str(root), str(path), algorithm, mode, str(int(failed))],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


@pytest.mark.parametrize('algorithm', ['adler32', 'crc32', 'md5', 'sha1', 'sha256'])
@pytest.mark.parametrize('mode', ['file', 'fd'])
@pytest.mark.parametrize('size', [0, 19, 131073])
def test_query_checksum_matches_independent_digest(query_checksum, tmp_path, algorithm, mode, size):
    data = (bytes(range(256)) * ((size + 255) // 256))[:size]
    source = tmp_path / 'source'
    source.write_bytes(data)
    expected = (f'{getattr(zlib, algorithm)(data):08x}' if algorithm in ['adler32', 'crc32']
                else hashlib.new(algorithm, data).hexdigest())
    assert run_query(query_checksum, tmp_path, source, algorithm, mode) == expected


@pytest.mark.parametrize('algorithm', ['adler32', 'crc32', 'sha256'])
@pytest.mark.parametrize('failure', ['missing', 'directory', 'bad-fd', 'outside', 'escape'])
def test_query_failure_never_hashes_an_unconfined_target(query_checksum, tmp_path, algorithm, failure):
    root = tmp_path / 'export'; root.mkdir()
    secret = tmp_path / 'secret'; secret.write_bytes(b'outside export')
    escape = root / 'escape'; escape.symlink_to(secret)
    targets = {'directory': root, 'outside': secret, 'escape': escape}
    target = targets.get(failure, root / 'absent')
    mode = 'bad-fd' if failure == 'bad-fd' else 'file'
    assert run_query(query_checksum, root, target, algorithm, mode, failed=True) == ''
    assert secret.read_bytes() == b'outside export'


@pytest.mark.parametrize('mode', ['file', 'fd'])
def test_unknown_digest_does_not_publish_a_checksum(query_checksum, tmp_path, mode):
    source = tmp_path / 'source'; source.write_bytes(b'data')
    assert run_query(query_checksum, tmp_path, source, 'invalid', mode, failed=True) == ''
