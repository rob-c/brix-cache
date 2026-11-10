"""Offline conformance CLI verifies real bytes and confines its scratch files."""

from pathlib import Path
import re
import shutil
import stat
import subprocess

import pytest


@pytest.fixture(scope='module')
def conform_binary():
    binary = Path(__file__).resolve().parents[1] / 'client/bin/xrd'
    if not binary.is_file():
        pytest.skip('Build the native xrd client before running offline contracts')
    return binary


def conform(binary, *arguments):
    return subprocess.run([str(binary), 'conform', *map(str, arguments)],
                          capture_output=True, text=True, timeout=60)


@pytest.fixture(scope='module')
def planted(conform_binary, tmp_path_factory):
    directory = tmp_path_factory.mktemp('conform-corpus')
    result = conform(conform_binary, 'plant', directory)
    assert result.returncode == 0, result.stderr
    assert result.stdout.count('verdict=PASS') == 11
    assert 'reason=large-object-disabled' in result.stdout
    return directory


@pytest.mark.parametrize('budget', ['exhaustive', 'pairwise', 'boundary'])
def test_offline_plan_reports_selected_geometry(conform_binary, budget):
    result = conform(conform_binary, 'plan', '--budget', budget, '--print-cases')
    assert result.returncode == 0, result.stderr
    assert f'budget={budget} objects=12 cases=' in result.stdout
    assert 'page offset=' in result.stdout
    assert 'vector count=' in result.stdout
    assert 'expected=' in result.stdout


def test_planted_corpus_verifies_with_private_key(conform_binary, planted):
    key = planted / 'brix-conform.key'
    assert len(key.read_bytes()) == 16
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    result = conform(conform_binary, 'verify', planted)
    assert result.returncode == 0, result.stderr
    assert result.stdout.count('verdict=PASS') == 11


def test_adopt_requires_matching_bytes_and_persists_key(conform_binary, planted,
                                                       tmp_path):
    directory = tmp_path / 'adopt'
    shutil.copytree(planted, directory)
    keyfile = directory / 'brix-conform.key'
    key = keyfile.read_bytes().hex()
    keyfile.unlink()
    result = conform(conform_binary, 'adopt', directory, key)
    assert result.returncode == 0, result.stderr
    assert keyfile.read_bytes().hex() == key
    assert conform(conform_binary, 'adopt', directory, key).returncode == 52


@pytest.mark.parametrize('damage', ['missing', 'truncated', 'corrupt', 'oversized'])
def test_verify_rejects_wrong_object_content_or_length(conform_binary, planted,
                                                      tmp_path, damage):
    directory = tmp_path / 'verify'
    shutil.copytree(planted, directory)
    target = directory / 'brix-conform-B1'
    replacements = {'truncated': b'', 'corrupt': bytes([target.read_bytes()[0] ^ 1]),
                    'oversized': (directory / 'brix-conform-P1').read_bytes()[:2]}
    if damage == 'missing':
        target.unlink()
    else:
        target.write_bytes(replacements[damage])
    result = conform(conform_binary, 'verify', directory)
    assert result.returncode == 52, result.stdout + result.stderr
    assert 'B1 failed verification' in result.stderr


@pytest.mark.parametrize('size', [0, 1, 15, 17, 32])
def test_key_file_requires_exact_length(conform_binary, tmp_path, size):
    (tmp_path / 'brix-conform.key').write_bytes(b'x' * size)
    result = conform(conform_binary, 'verify', tmp_path)
    assert result.returncode == 51
    assert 'cannot read persisted run key' in result.stderr


@pytest.mark.parametrize('operation', ['plant', 'verify', 'adopt'])
def test_scratch_directory_symlink_is_refused(conform_binary, tmp_path, operation):
    outside = tmp_path / 'outside'
    outside.mkdir()
    link = tmp_path / 'link'
    link.symlink_to(outside, target_is_directory=True)
    result = conform(conform_binary, operation, link, *adopt_key(operation))
    assert result.returncode == 51
    assert list(outside.iterdir()) == []


def adopt_key(operation):
    return ['00' * 16] if operation == 'adopt' else []


def test_existing_object_cannot_be_overwritten_through_symlink(conform_binary,
                                                             tmp_path):
    outside = tmp_path / 'outside'
    outside.write_bytes(b'protected')
    directory = tmp_path / 'scratch'
    directory.mkdir()
    (directory / 'brix-conform-Z').symlink_to(outside)
    result = conform(conform_binary, 'plant', directory)
    assert result.returncode == 52
    assert outside.read_bytes() == b'protected'
    assert not (directory / 'brix-conform.key').exists()


@pytest.mark.parametrize('key', ['', 'x' * 32, '00' * 15, '00' * 17])
def test_adopt_rejects_invalid_key_before_mutation(conform_binary, tmp_path, key):
    assert conform(conform_binary, 'adopt', tmp_path, key).returncode == 4
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('operation', ['plant', 'verify', 'adopt'])
def test_unknown_option_is_refused_before_opening_scratch(conform_binary,
                                                        tmp_path, operation):
    result = conform(conform_binary, operation, tmp_path, *adopt_key(operation),
                     '--unknown-option')
    assert result.returncode == 4
    assert re.search('unknown .*option', result.stderr)
    assert list(tmp_path.iterdir()) == []
