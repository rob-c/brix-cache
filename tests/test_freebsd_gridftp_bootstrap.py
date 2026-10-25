"""Native GridFTP dependencies stay pinned, isolated and actually executable."""
import hashlib
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml

from tools.ci import freebsd_gridftp as bootstrap
from tools.ci.freebsd_gfal import verify_archive


def test_release_is_the_published_archive_with_full_sha512():
    url, digest = bootstrap.source_release()
    assert url == 'https://repo.gridcf.org/gct6/sources/gct-6.2.1767880040.tar.gz'
    assert len(digest) == 128 and set(digest) <= set('0123456789abcdef')


def test_published_digest_algorithm_checks_exact_bytes(tmp_path):
    source = tmp_path / 'archive'
    payload = b'exact dependency bytes\x00'
    source.write_bytes(payload)
    verify_archive(source, hashlib.sha512(payload).hexdigest(), algorithm='sha512')


@pytest.mark.parametrize('payload', [b'', b'changed', b'\x00hostile'])
def test_changed_archive_cannot_be_extracted_or_built(tmp_path, monkeypatch, payload):
    (tmp_path / 'gct.tar.gz').write_bytes(payload)
    calls = []
    monkeypatch.setattr(bootstrap, 'run_dependency', lambda command, env: calls.append(command))
    with pytest.raises(ValueError, match='checksum mismatch'):
        bootstrap._fetch(tmp_path, {})
    assert len(calls) == 1 and calls[0][0] == 'curl'
    assert calls[0][calls[0].index('--proto-redir') + 1] == '=https'
    assert not (tmp_path / 'source').exists()


def test_previous_lab_is_not_overwritten(tmp_path, monkeypatch):
    marker = tmp_path / 'preserved'
    marker.write_bytes(b'old evidence')
    def forbidden(*_args, **_kwargs):
        pytest.fail('existing lab must not run commands')
    monkeypatch.setattr(bootstrap, 'run_dependency', forbidden)
    with pytest.raises(FileExistsError):
        bootstrap.build_dependency(tmp_path, 1)
    assert marker.read_bytes() == b'old evidence'


@pytest.mark.parametrize('host,uid,jobs', [('Darwin', 2101, 1), ('FreeBSD', 0, 1),
                                        ('FreeBSD', 2101, 0), ('FreeBSD', 2101, 5)])
def test_wrong_host_root_or_unbounded_jobs_are_refused(monkeypatch, host, uid, jobs):
    monkeypatch.setattr(bootstrap.platform, 'system', lambda: host)
    monkeypatch.setattr(bootstrap.os, 'geteuid', lambda: uid)
    with pytest.raises(SystemExit) as refused:
        bootstrap._arguments(['--work-dir', '/unused/private-build', '--jobs', str(jobs)])
    assert refused.value.code == 2


@pytest.mark.parametrize('corrupt', [False, True])
def test_probe_requires_byte_exact_native_copy(tmp_path, monkeypatch, corrupt):
    def copy(command, env):
        assert command[0] == str(tmp_path / 'install/bin/globus-url-copy')
        data = (tmp_path / 'copy-probe-source').read_bytes()
        (tmp_path / 'copy-probe-target').write_bytes(data[:-1] if corrupt else data)
    monkeypatch.setattr(bootstrap, 'run_dependency', copy)
    if corrupt:
        with pytest.raises(ValueError, match='changed bytes'):
            bootstrap._verify_client(tmp_path / 'install', {}, tmp_path)
    else:
        bootstrap._verify_client(tmp_path / 'install', {}, tmp_path)


def test_subset_build_stays_inside_its_private_prefix(tmp_path, monkeypatch):
    work = tmp_path / 'private'
    calls = []
    monkeypatch.setenv('LD_LIBRARY_PATH', '/foreign/library')
    monkeypatch.setenv('GLOBUS_LOCATION', '/foreign/globus')
    monkeypatch.setattr(bootstrap, '_fetch', lambda root, env: root / 'source')
    monkeypatch.setattr(bootstrap, '_verify_client', lambda *_args: None)
    monkeypatch.setattr(bootstrap, 'run_dependency', lambda command, env, **kw:
                        calls.append((command, env, kw)))
    assert bootstrap.build_dependency(work, 2) == work / 'install'
    configure = calls[1][0]
    assert configure == ['./configure', '--prefix=' + str(work / 'install'),
                         '--disable-gram5', '--disable-gsi-openssh']
    assert [command[-1] for command, _, _ in calls[-2:]] == ['gridftp', 'install']
    assert all('LD_LIBRARY_PATH' not in env and env['GLOBUS_LOCATION'] == str(work / 'install')
               and kw['cwd'] == work / 'source' for _, env, kw in calls)


@pytest.mark.parametrize('reported,expected', [(-1, 16384), (0, 16384), (4096, 4096)])
def test_passwd_patch_handles_indeterminate_without_changing_valid_limits(tmp_path, reported, expected):
    """Compile the exact added compatibility block, not a Python imitation."""
    patch = Path(bootstrap.__file__).parent / 'dependency-patches/gct-freebsd.patch'
    additions = '\n'.join(line[1:] for line in patch.read_text().splitlines()
                          if line.startswith('+') and not line.startswith('+++'))
    source = tmp_path / 'probe.c'
    source.write_text('#include <assert.h>\nint main(void) { long buflen = ' + str(reported) + ';\n' +
                      additions + '\nreturn buflen != ' + str(expected) + '; }\n')
    compiler = shutil.which('cc')
    assert compiler is not None, 'native validation requires a C compiler'
    subprocess.run([compiler, '-Wall', '-Wextra', '-Werror', str(source),
                    '-o', str(tmp_path / 'probe')], check=True, timeout=30)
    subprocess.run([str(tmp_path / 'probe')], check=True, timeout=10)


def test_full_workflow_builds_and_enables_native_gridftp():
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / '.github/workflows/freebsd.yml').read_text())
    commands = next(step['with']['run'] for step in workflow['jobs']['native']['steps']
                    if 'prepare' in step.get('with', {}))
    assert 'tools/ci/freebsd_gridftp.py --work-dir /home/brixvalidate/gridftp-deps --jobs 1' in commands
    assert 'export PATH="/home/brixvalidate/gridftp-deps/install/bin:$PATH"' in commands
    assert commands.index('tools/ci/freebsd_gridftp.py') < commands.index('tools/ci/freebsd_pending_peer.py')
