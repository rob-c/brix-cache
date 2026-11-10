"""OCI command refusals, local layouts and credential-file cleanup without a registry."""

import json
import os
from pathlib import Path
import subprocess

import pytest


@pytest.fixture
def oci_cli(tmp_path):
    """Run the built command with a private cwd and temporary PEM directory."""
    binary = Path(__file__).resolve().parents[1] / 'client/bin/brixoci'
    assert binary.is_file(), 'Build the native client first'

    def invoke(*arguments):
        return subprocess.run([str(binary), *arguments], cwd=tmp_path,
                              env=dict(os.environ, TMPDIR=str(tmp_path)),
                              capture_output=True, text=True, timeout=10)

    return invoke


@pytest.mark.parametrize('arguments', [
    [], ['unknown-command'], ['pull'], ['push'], ['copy', 'one'],
    ['copy', 'one', 'two', 'three'], ['convert'], ['convert', 'a', 'b'],
    ['convert', '--estargz', '--tag', 'v1', 'a', 'registry.invalid/app'],
    ['ls', 'a', 'b'], ['tags'], ['rm'], ['inspect'],
    ['ls', '--not-an-option'], ['ls', '--key', 'key.pem'],
    *[['ls', flag] for flag in ('--grace', '--to', '--from', '--tag',
                               '--platform', '--token-file', '--cert', '--key')],
    *[['gc', '--grace', value] for value in ('', '-1', '1x', 'never')],
])
def test_usage_errors_stop_before_storage_or_network(oci_cli, tmp_path, arguments):
    result = oci_cli(*arguments)
    assert result.returncode == 2, result.stdout + result.stderr
    assert result.stdout == '' and result.stderr
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('option', ['--help', '-h', '--version'])
def test_offline_help_and_version(oci_cli, option):
    result = oci_cli(option)
    assert result.returncode == 0 and 'brixoci' in result.stdout
    assert result.stderr == ''


@pytest.fixture
def empty_layout(tmp_path):
    layout = tmp_path / 'layout'
    layout.mkdir()
    (layout / 'oci-layout').write_text('{"imageLayoutVersion":"1.0.0"}\n')
    (layout / 'index.json').write_text('{"schemaVersion":2,"manifests":[]}\n')
    return layout


@pytest.mark.parametrize('prefix', ['', 'oci:'])
def test_empty_layout_listing_is_success(oci_cli, empty_layout, prefix):
    result = oci_cli('ls', prefix + str(empty_layout))
    assert result.returncode == 0, result.stderr
    assert result.stdout == ''


@pytest.mark.parametrize('verb', ['tags', 'rm', 'inspect'])
def test_remote_verbs_refuse_local_layout(oci_cli, empty_layout, verb):
    before = (empty_layout / 'index.json').read_bytes()
    result = oci_cli(verb, 'oci:' + str(empty_layout))
    assert result.returncode == 2 and 'needs a registry ref' in result.stderr
    assert (empty_layout / 'index.json').read_bytes() == before


@pytest.mark.parametrize('marker', ['{}', '{', '{"imageLayoutVersion":"2.0.0"}'])
def test_unknown_layout_version_is_rejected(oci_cli, empty_layout, marker):
    (empty_layout / 'oci-layout').write_text(marker)
    result = oci_cli('ls', str(empty_layout))
    assert result.returncode == 6 and 'unsupported imageLayoutVersion' in result.stderr


def test_layout_listing_preserves_ref_and_media_type(oci_cli, empty_layout):
    digest = 'sha256:' + 'a' * 64
    entries = [dict(digest=digest, mediaType='application/vnd.oci.image.manifest.v1+json',
                    annotations={'org.opencontainers.image.ref.name': 'v1'}),
               dict(digest=digest, mediaType='application/vnd.oci.image.index.v1+json')]
    (empty_layout / 'index.json').write_text(json.dumps({'manifests': entries}))
    result = oci_cli('ls', 'oci:' + str(empty_layout))
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        'v1 ' + digest + ' application/vnd.oci.image.manifest.v1+json',
        '- ' + digest + ' application/vnd.oci.image.index.v1+json']


@pytest.mark.parametrize('content', [None, b'', b' \r\n\t', b'x' * 20000])
def test_invalid_bearer_files_fail_before_transfer(oci_cli, tmp_path, content):
    token = tmp_path / 'token'
    if content is not None:
        token.write_bytes(content)
    destination = tmp_path / 'destination'
    result = oci_cli('pull', 'registry.invalid/app:v1', '--token-file', str(token),
                     '--to', str(destination))
    assert result.returncode == 3 and '--token-file' in result.stderr
    assert not destination.exists()
    assert 'x' * 40 not in result.stderr


def pem_files(tmp_path, key_mode):
    """Create only the credential inputs requested by this cleanup scenario."""
    cert = tmp_path / 'cert.pem'
    cert.write_text('private fixture certificate\n')
    key = cert if key_mode == 'same-file' else tmp_path / 'key.pem'
    if key_mode == 'separate-file':
        key.write_text('private fixture key\n')
    if key_mode == 'oversized':
        key.write_bytes(b'x' * (256 * 1024))
    return cert, key


@pytest.mark.parametrize('key_mode,expected', [
    ('same-file', 0), ('separate-file', 0), ('missing', 3), ('oversized', 3)])
def test_client_pem_is_cleaned_after_local_command(oci_cli, empty_layout, tmp_path,
                                                  key_mode, expected):
    cert, key = pem_files(tmp_path, key_mode)
    result = oci_cli('ls', str(empty_layout), '--cert', str(cert), '--key', str(key))
    assert result.returncode == expected
    assert list(tmp_path.glob('brixoci-pem.*')) == []
    assert 'private fixture' not in result.stdout + result.stderr


def test_pem_cleanup_also_runs_when_command_fails(oci_cli, tmp_path):
    cert, key = tmp_path / 'cert', tmp_path / 'key'
    cert.write_text('fixture cert\n')
    key.write_text('fixture key\n')
    result = oci_cli('ls', 'missing-layout', '--cert', str(cert), '--key', str(key))
    assert result.returncode == 4 and 'no layout' in result.stderr
    assert list(tmp_path.glob('brixoci-pem.*')) == []
