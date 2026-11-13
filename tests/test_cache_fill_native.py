"""Cache fills publish exact private bytes or abort their staged output."""

import hashlib
import stat
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def cache_fill(server_native_compile):
    return server_native_compile('cache-fill', 'tests/c/cache_fill_native_test.c',
                                 ['-Wl,--wrap=malloc'])


def invoke(binary, tmp_path, mode='normal', *, size=123, verify=False):
    source, cache = tmp_path / 'source', tmp_path / 'cache'
    source.mkdir()
    cache.mkdir()
    content = (bytes(range(251)) * (size // 251 + 1))[:size]
    if mode != 'source-missing':
        (source / 'file').write_bytes(content)
    digest = '0' * 64 if mode == 'bad-digest' else hashlib.sha256(content).hexdigest()
    result = subprocess.run([str(binary), str(source), str(cache), mode, digest, str(int(verify))],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return dict(line.split('=', 1) for line in result.stdout.splitlines()), cache, content


@pytest.mark.parametrize('size', [0, 31, 1048576, 1048583])
@pytest.mark.parametrize('verify', [False, True])
def test_fill_publishes_exact_private_bytes_and_metadata(cache_fill, tmp_path, size, verify):
    result, cache, content = invoke(cache_fill, tmp_path, size=size, verify=verify)
    assert result['rc'] == '0' and result['size'] == str(size)
    assert result['commits'] == '1' and result['aborts'] == '0'
    assert (cache / 'file').read_bytes() == content
    assert stat.S_IMODE((cache / 'file').stat().st_mode) == 0o600


@pytest.mark.parametrize('mode', ['no-source', 'no-storage', 'no-root', 'wrong-root',
    'source-missing', 'source-open', 'source-stat', 'stage-open', 'buffer', 'source-read', 'stage-write', 'commit'])
def test_failed_fill_never_publishes_partial_bytes(cache_fill, tmp_path, mode):
    result, cache, _content = invoke(cache_fill, tmp_path, mode)
    assert result['rc'] == '-1' and result['commits'] == '0'
    assert not [path for path in cache.rglob('*') if path.is_file()]


def test_admission_decline_does_not_create_a_stage(cache_fill, tmp_path):
    result, cache, _content = invoke(cache_fill, tmp_path, 'admission')
    assert result['rc'] == '1' and result['stages'] == '0'
    assert not (cache / 'file').exists()


def test_checksum_mismatch_evicts_the_untrusted_entry(cache_fill, tmp_path):
    result, cache, _content = invoke(cache_fill, tmp_path, 'bad-digest', verify=True)
    assert result['rc'] == '-1' and result['commits'] == '1'
    assert not (cache / 'file').exists()


def test_post_commit_stat_error_is_not_reported_as_success(cache_fill, tmp_path):
    result, cache, content = invoke(cache_fill, tmp_path, 'commit-stat')
    assert result['rc'] == '-1' and result['commits'] == '1'
    assert (cache / 'file').read_bytes() == content
