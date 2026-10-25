"""Pinned external dependencies fail closed without touching system prefixes."""
import hashlib
from pathlib import Path
import subprocess

import pytest
import yaml

from tools.ci import freebsd_gfal as bootstrap
from tools.ci.freebsd_native import native_environment


def test_only_pinned_gfal_and_davix_sources_are_fetched():
    releases = bootstrap.source_releases()
    assert {name for name, _, _ in releases} == {'davix', 'gfal2', 'gfal2-python', 'gfal2-util'}
    for _, revision, digest in releases:
        assert len(revision) == 40 and len(digest) == 64
        assert set(revision + digest) <= set('0123456789abcdef')


def test_matching_archive_is_accepted(tmp_path):
    archive = tmp_path / 'source.tar.gz'
    payload = b'exact upstream bytes\x00'
    archive.write_bytes(payload)
    bootstrap.verify_archive(archive, hashlib.sha256(payload).hexdigest())


@pytest.mark.parametrize('payload', [b'', b'changed bytes', b'\x00hostile'])
def test_changed_archive_is_never_extracted(tmp_path, monkeypatch, payload):
    (tmp_path / 'gfal2.tar.gz').write_bytes(payload)
    calls = []
    monkeypatch.setattr(bootstrap, '_run', lambda command, env: calls.append(command))
    with pytest.raises(ValueError, match='checksum mismatch'):
        bootstrap._fetch_release(tmp_path, 'gfal2', 'a' * 40, 'f' * 64, {})
    assert len(calls) == 1 and calls[0][0] == 'curl'
    assert calls[0][calls[0].index('--proto-redir') + 1] == '=https'
    assert not (tmp_path / 'source').exists()


def test_existing_dependency_lab_is_preserved(tmp_path, monkeypatch):
    marker = tmp_path / 'owned-by-previous-run'
    marker.write_bytes(b'preserved')

    def no_command(*args, **kwargs):
        pytest.fail('existing dependency tree must not be rebuilt or overwritten')

    monkeypatch.setattr(bootstrap, '_run', no_command)
    with pytest.raises(FileExistsError):
        bootstrap.build_dependencies(tmp_path, 1)
    assert marker.read_bytes() == b'preserved'
    assert list(tmp_path.iterdir()) == [marker]


@pytest.mark.parametrize('host,uid,jobs', [('Darwin', 2101, 1), ('FreeBSD', 0, 1),
                                        ('FreeBSD', 2101, 0), ('FreeBSD', 2101, 5)])
def test_unsupported_host_root_or_unbounded_jobs_are_refused(monkeypatch, host, uid, jobs):
    monkeypatch.setattr(bootstrap.platform, 'system', lambda: host)
    monkeypatch.setattr(bootstrap.os, 'geteuid', lambda: uid)
    with pytest.raises(SystemExit) as refused:
        bootstrap._arguments(['--work-dir', '/unused/private-build', '--jobs', str(jobs)])
    assert refused.value.code == 2


def test_davix_links_its_required_native_uuid_dependency(tmp_path):
    davix = tmp_path / 'davix'
    assert '-DUUID_LIBRARY:FILEPATH=/usr/local/lib/libuuid.so' in bootstrap._davix_options(davix)


def test_gfal_enables_all_three_interoperability_plugins(tmp_path):
    options = bootstrap._gfal_options(tmp_path / 'gfal2', tmp_path / 'davix')
    for name in ('FILE', 'HTTP', 'XROOTD'):
        assert '-DPLUGIN_' + name + '=ON' in options


def test_gfal_embeds_the_complete_private_loader_path(tmp_path):
    davix, prefix = tmp_path / 'davix', tmp_path / 'gfal2'
    options = bootstrap._gfal_options(prefix, davix)
    rpath = next(option.split('=', 1)[1] for option in options
                 if option.startswith('-DCMAKE_INSTALL_RPATH='))
    assert set(rpath.split(';')) == {str(prefix / 'lib'), str(prefix / 'lib64'), str(davix / 'lib')}


def test_python_extension_embeds_its_installed_loader_path(tmp_path):
    assert '-DCMAKE_BUILD_WITH_INSTALL_RPATH=ON' in bootstrap._python_options(tmp_path / 'gfal2')


def test_extension_install_cannot_escape_private_python_prefix(tmp_path, monkeypatch):
    response = subprocess.CompletedProcess([], 0, stdout=str(tmp_path / 'outside') + '\n')
    monkeypatch.setattr(bootstrap.subprocess, 'run', lambda *args, **kwargs: response)
    with pytest.raises(ValueError, match='escaped the private prefix'):
        bootstrap._python_site(tmp_path / 'private', {})


def test_extension_install_selects_the_real_private_interpreter(tmp_path, monkeypatch):
    prefix = tmp_path / 'private'
    site = prefix / 'lib/python3.12/site-packages'
    calls = []

    def invoke(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout=str(site) + '\n')

    monkeypatch.setattr(bootstrap.subprocess, 'run', invoke)
    assert bootstrap._python_site(prefix, {}) == site
    assert calls[0][0][0] == str(prefix / 'bin/python3')
    assert calls[0][1]['check'] and calls[0][1]['timeout'] == 20


def test_native_suite_preserves_the_optional_gfal_command_path(tmp_path):
    directory = str(tmp_path / 'private-gfal/bin')
    env = native_environment({'PATH': directory + ':/usr/local/bin'})
    assert directory in env['PATH'].split(':')
    assert env['CC'] == '/usr/bin/cc'
    assert 'LD_LIBRARY_PATH' not in env


def test_external_command_failure_is_not_reported_as_a_success(monkeypatch):
    def fail(command, **kwargs):
        raise subprocess.CalledProcessError(23, command)

    monkeypatch.setattr(bootstrap.subprocess, 'run', fail)
    with pytest.raises(subprocess.CalledProcessError) as failure:
        bootstrap._run(['external-tool', 'probe'], {})
    assert failure.value.returncode == 23


def _workflow_vm():
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / '.github/workflows/freebsd.yml').read_text())
    return next(step['with'] for step in workflow['jobs']['native']['steps']
                if 'prepare' in step.get('with', {}))


def test_full_workflow_installs_the_real_plugin_build_dependencies():
    required = {'libuuid', 'cryptopp', 'openldap26-client', 'nlohmann-json',
                'gsoap', 'py312-boost-libs', 'py312-setuptools', 'py312-wheel'}
    assert required <= set(_workflow_vm()['prepare'].split())


def test_full_workflow_uses_the_private_plugins_as_the_test_user():
    commands = _workflow_vm()['run']
    assert commands.index('tools/ci/freebsd_gfal.py') < commands.index('tools/ci/freebsd_pending_peer.py')
    assert 'su -l brixvalidate -c' in commands[:commands.index('tools/ci/freebsd_gfal.py')]
    assert 'PATH="/home/brixvalidate/gfal-deps/install/gfal2/bin:$PATH"' in commands
