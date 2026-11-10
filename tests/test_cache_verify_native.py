"""Real cache digests, policy refusal and quarantine ownership across key grammars."""

import hashlib
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401

DATA = bytes(range(256)) * 301


@pytest.fixture(scope='module')
def verify_binary(server_native_compile):
    return server_native_compile('cache-verify', 'tests/c/cache_verify_native_test.c')


def prepare_part(tmp_path, fault):
    """Own the staged file or deliberately unusable name."""
    path = tmp_path / 'part'
    if fault == 'directory':
        path.mkdir()
    elif fault != 'missing':
        path.write_bytes(DATA)
    if fault == 'symlink':
        path.rename(tmp_path / 'target')
        path.symlink_to(tmp_path / 'target')
    return path


def assert_unchanged_part(path, family):
    """Verification must not edit staged bytes, including a refused symlink target."""
    if family != 'quarantine' and path.is_file():
        assert path.read_bytes() == DATA


def run_verify(binary, tmp_path, family, spec, digest='', policy=2, expected=0,
               fault='', log=True, outputs=True):
    """Run the real verifier and retain its diagnostic output."""
    path = prepare_part(tmp_path, fault)
    logfile = tmp_path / 'verify.log'
    result = subprocess.run([str(binary), family, str(path), spec, digest, str(policy),
        str(expected), str(int(log)), str(int(outputs)), str(logfile)],
        capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert_unchanged_part(path, family)
    return result.stdout, logfile.read_text()


@pytest.mark.parametrize('algorithm', ['md5', 'sha1', 'sha256', 'sha512'])
@pytest.mark.parametrize('policy', [0, 1, 2])
@pytest.mark.parametrize('outputs', [False, True])
def test_origin_digest_and_policy(verify_binary, tmp_path, algorithm, policy, outputs):
    digest = hashlib.new(algorithm, DATA).hexdigest()
    stdout, _ = run_verify(verify_binary, tmp_path, 'part', algorithm, digest.upper(),
                          policy, expected=1 if policy == 0 else 0, outputs=outputs)
    if policy and outputs:
        assert f'algorithm={algorithm}\ndigest={digest}\n' in stdout


@pytest.mark.parametrize('algorithm,digest', [('null', ''), ('', 'a'), ('sha256', ''),
                                           ('unsupported', '1234')])
@pytest.mark.parametrize('policy', [0, 1, 2])
def test_unverifiable_origin_obeys_required_policy(verify_binary, tmp_path, algorithm, digest, policy):
    run_verify(verify_binary, tmp_path, 'part', algorithm, digest, policy,
               expected=3 if policy == 2 else 1)


@pytest.mark.parametrize('digest', ['0' * 64, 'abc'])
@pytest.mark.parametrize('log', [False, True])
def test_origin_mismatch_never_populates_verified_outputs(verify_binary, tmp_path, digest, log):
    stdout, logged = run_verify(verify_binary, tmp_path, 'part', 'sha256', digest,
                               expected=2, log=log)
    assert 'error=3019' in stdout
    assert ('discarding fill' in logged) == log


def content_key(family, algorithm, digest):
    """Use the repository's three content-addressed path grammars."""
    if family == 'cvmfs':
        return f'/cvmfs/repo.invalid/data/{digest[:2]}/{digest[2:]}C'
    if family == 'oci':
        return f'/v2/repo/blobs/{algorithm}:{digest}'
    return f'/repo/repodata/{digest}-primary.xml.gz'


@pytest.mark.parametrize('family,algorithm', [('cvmfs', 'sha1'), ('oci', 'sha256'),
    ('oci', 'sha512'), ('rpm', 'sha1'), ('rpm', 'sha256'), ('rpm', 'sha512')])
@pytest.mark.parametrize('corrupt,expected', [(False, 0), (True, 2)])
@pytest.mark.parametrize('outputs', [False, True])
def test_content_address_uses_the_named_digest(verify_binary, tmp_path, family, algorithm,
                                              corrupt, expected, outputs):
    digest = hashlib.new(algorithm, DATA).hexdigest()
    named = '0' * len(digest) if corrupt else digest
    stdout, logged = run_verify(verify_binary, tmp_path, family, content_key(family, algorithm, named),
                               expected=expected, outputs=outputs)
    if not corrupt and outputs:
        assert f'algorithm={algorithm}\ndigest={digest}\n' in stdout
    assert ('verify FAILED' in logged) == corrupt


@pytest.mark.parametrize('family,key', [('cvmfs', '/cvmfs/repo.invalid/.cvmfspublished'),
    ('cvmfs', '/broken'), ('cvmfs', content_key('cvmfs', 'sha256', 'a' * 64)),
    ('oci', '/v2/repo/manifests/latest'), ('oci', '/v2/repo/tags/list'), ('oci', '/broken'),
    ('rpm', '/repo/repodata/repomd.xml'), ('rpm', '/repo/package.rpm'), ('rpm', '/broken')])
def test_mutable_or_invalid_keys_are_not_falsely_verified(verify_binary, tmp_path, family, key):
    run_verify(verify_binary, tmp_path, family, key, expected=1, fault='missing')


@pytest.mark.parametrize('family,algorithm', [('part', 'sha256'), ('cvmfs', 'sha1'),
                                           ('oci', 'sha256'), ('rpm', 'sha256')])
@pytest.mark.parametrize('fault', ['missing', 'symlink', 'directory'])
def test_unreadable_staged_object_never_verifies(verify_binary, tmp_path, family, algorithm, fault):
    digest = hashlib.new(algorithm, DATA).hexdigest()
    spec = algorithm if family == 'part' else content_key(family, algorithm, digest)
    run_verify(verify_binary, tmp_path, family, spec, digest, expected=3, fault=fault)


def quarantine_target(tmp_path, target):
    """Only the valid destination exists; every path stays inside the fixture."""
    directory = tmp_path / 'quarantine'
    if target == 'valid':
        directory.mkdir()
    argument = str(directory) if target in ('missing', 'valid') else target
    return directory, argument


def assert_quarantined_bytes(directory, target):
    """A successful move retains one exact copy; fallback removes the corrupt part."""
    quarantined = list(directory.iterdir()) if directory.exists() else []
    assert len(quarantined) == (1 if target == 'valid' else 0)
    for path in quarantined:
        assert path.read_bytes() == DATA


@pytest.mark.parametrize('target', ['null', '', 'oversized', 'missing', 'valid'])
@pytest.mark.parametrize('log', [False, True])
def test_quarantine_removes_the_publishable_name(verify_binary, tmp_path, target, log):
    directory, argument = quarantine_target(tmp_path, target)
    _, logged = run_verify(verify_binary, tmp_path, 'quarantine', argument, log=log)
    assert not (tmp_path / 'part').exists()
    assert_quarantined_bytes(directory, target)
    assert ('corrupt fill quarantined' in logged) == (log and target == 'valid')
