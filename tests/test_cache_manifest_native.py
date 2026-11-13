"""CVMFS chain verification separates tampering from unavailable source data."""

import shutil
import subprocess
import zlib

import pytest

from test_cvmfs_verify_manifest import _forge
from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def manifest_binary(server_native_compile):
    return server_native_compile('cache-manifest', 'tests/c/cache_manifest_native_test.c',
        ['-Wl,--wrap=' + name for name in ('malloc', 'open64', 'read')])


@pytest.fixture(scope='module')
def signed_repo(tmp_path_factory):
    forge, web, pub = _forge(tmp_path_factory.mktemp('cache-manifest-signed'))
    yield forge, web, pub
    forge.close()


@pytest.fixture
def manifest_run(manifest_binary, signed_repo, tmp_path):
    forge, web, pub = signed_repo
    local = tmp_path / 'web'
    shutil.copytree(web, local)
    repo = local / 'cvmfs/test.cern.ch'

    def run(mode='normal', expected=0, name='.cvmfspublished', part=None):
        staged = part or repo / name
        result = subprocess.run([str(manifest_binary), str(local), str(pub),
            str(staged), '/cvmfs/test.cern.ch/' + name, mode, str(expected)],
            capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout

    return run, repo, forge


@pytest.mark.parametrize('mode', ['normal', 'part-eintr', 'source-eintr'])
@pytest.mark.parametrize('name', ['.cvmfspublished', '.cvmfswhitelist'])
def test_real_signed_metadata_verifies_with_interrupted_reads(manifest_run, mode, name):
    run, _, _ = manifest_run
    run(mode, name=name)


@pytest.mark.parametrize('mode', ['part-null', 'part-read', 'malloc-1',
    'source-null', 'source-no-open', 'source-no-read', 'source-open',
    'source-read', 'cert-open', 'malloc-2', 'malloc-3'])
def test_incomplete_trust_chain_is_unavailable_and_closes_every_object(manifest_run, mode):
    run, _, _ = manifest_run
    run(mode, expected=-5)


@pytest.mark.parametrize('source', [False, True])
def test_oversized_metadata_cannot_exhaust_verifier_memory(manifest_run, tmp_path, source):
    run, repo, _ = manifest_run
    if source:
        (repo / '.cvmfswhitelist').write_bytes(b'x' * 65536)
        run(expected=-5)
    else:
        part = tmp_path / 'oversized'
        part.write_bytes(b'x' * 65536)
        run(expected=-5, part=part)


def test_missing_staged_file_is_unavailable(manifest_run, tmp_path):
    run, _, _ = manifest_run
    run(expected=-5, part=tmp_path / 'absent')


@pytest.mark.parametrize('artifact', ['.cvmfspublished', '.cvmfswhitelist'])
def test_malformed_signed_metadata_is_definitive_refusal(manifest_run, artifact):
    run, repo, _ = manifest_run
    (repo / artifact).write_bytes(b'invalid signed metadata')
    run(expected=-1)


@pytest.mark.parametrize('mode', ['normal', 'malloc-4'])
def test_raw_certificate_fallback_verifies_actual_certificate(manifest_run, mode):
    run, repo, forge = manifest_run
    relative = forge.artifact_path('cert').relative_to(forge.repo_dir)
    certificate = repo / relative
    certificate.write_bytes(zlib.decompress(certificate.read_bytes()))
    run(mode)


def test_certificate_not_in_whitelist_is_refused(manifest_run):
    run, repo, forge = manifest_run
    certificate = repo / forge.artifact_path('cert').relative_to(forge.repo_dir)
    certificate.write_bytes(b'not a certificate')
    run(expected=-1)


def test_failed_inflate_allocation_does_not_accept_compressed_bytes_as_certificate(manifest_run):
    run, _, _ = manifest_run
    run('malloc-4', expected=-1)


@pytest.mark.parametrize('name', ['.cvmfsreflog', 'data/invalid', 'api/v1/geo/x'])
def test_unsigned_shapes_do_not_open_signature_artifacts(manifest_run, name):
    run, _, _ = manifest_run
    assert 'calls=0 opens=0 closes=0' in run(name=name)


def test_explicitly_disabled_trust_gate_retains_transparent_mode(manifest_run):
    run, _, _ = manifest_run
    assert 'calls=0 opens=0 closes=0' in run('disabled')
