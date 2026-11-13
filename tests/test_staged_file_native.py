"""Confined staging preserves private uploads, resume identity and publish failures."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def staged_binary(server_native_compile):
    return server_native_compile('staged-file', 'tests/c/staged_file_native_test.c',
                                 ['-Wl,--wrap=fsync', '-Wl,--wrap=brix_open_beneath'])


@pytest.mark.parametrize('mode', [
    'commit', 'exclusive', 'exclusive-exists', 'fsync', 'dirsync', 'rename',
    'closed-fd', 'abort-remove', 'abort-retain', 'abort-outside',
    'commit-outside', 'commit-root-missing', 'commit-temp-outside',
    'resume', 'resume-external', 'resume-symlink',
    'null-request', 'null-stage', 'null-path', 'null-commit', 'inactive-commit',
    'open-outside', 'open-root-missing', 'open-long', 'collision',
    'resume-long', 'resume-outside', 'resume-root-missing',
    'dirsync-null', 'dirsync-missing', 'dirsync-root-missing',
])
def test_staged_publication_and_confinement(staged_binary, tmp_path, mode):
    root = tmp_path / 'root'
    root.mkdir()
    result = subprocess.run([str(staged_binary), mode, str(root)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not (tmp_path / 'outside').exists()
