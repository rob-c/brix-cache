"""Coverage's explicit root lane must preserve counters and test failures."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.ci import coverage, coverage_privileged


@pytest.mark.parametrize('failure,calls', [(None, 4), (0, 1), (3, 4)])
def test_main_coverage_build_uses_atomic_counters_and_retains_failures(
        tmp_path, monkeypatch, failure, calls):
    from cmdscripts import operator_build
    configure = tmp_path / 'configure'
    configure.write_text('#!/bin/sh\nexit 0\n')
    configure.chmod(0o755)
    commands = []

    def run(argv, **_options):
        commands.append(argv)
        return SimpleNamespace(returncode=int(len(commands) - 1 == failure),
                               stderr='build diagnostic', stdout='')

    monkeypatch.setattr(operator_build, 'run', run)
    results = operator_build.build_coverage(tmp_path)
    assert len(commands) == calls
    assert results[0][0] == (failure is None)
    flags = '--coverage -O0 -g -fprofile-update=atomic'
    assert '--with-cc-opt=' + flags in commands[0]
    if failure != 0:
        assert 'CFLAGS=' + flags in commands[-1]
        assert ('LDFLAGS=-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack ' + flags) in commands[-1]


def test_coverage_selects_the_instrumented_binary_and_sdk(tmp_path):
    """A nondefault nginx build must be the one every test executes."""
    env = coverage._build_environment(tmp_path, {'KEEP': 'value'})
    assert env['TEST_NGINX_BIN'] == env['NGINX_BIN'] == str(tmp_path / 'objs/nginx')
    assert env['BRIX_NGINX_BUILD_DIR'] == str(tmp_path / 'objs')
    assert env['TEST_NGINX_SRC'] == env['NGX_SRC'] == str(tmp_path)
    assert env['KEEP'] == 'value'


def test_stale_noninstrumented_binary_cannot_supply_coverage(tmp_path):
    """Caller state cannot silently send traffic to a different executable."""
    original = {'TEST_NGINX_BIN': '/unrelated/nginx', 'NGINX_BIN': '/other/nginx'}
    env = coverage._build_environment(tmp_path, original)
    assert env['TEST_NGINX_BIN'] == str(tmp_path / 'objs/nginx')
    assert original['TEST_NGINX_BIN'] == '/unrelated/nginx'


def test_static_coverage_build_cannot_load_stale_dynamic_modules(tmp_path):
    """An inherited module from another SDK cannot change the measured program."""
    env = coverage._build_environment(tmp_path, {'TEST_NGINX_LOAD_MODULES': '/old.so'})
    assert env['TEST_NGINX_LOAD_MODULES'] == ''


@pytest.mark.parametrize('enabled,ordinary,root,expected,count', [
    ('0', 0, 7, 0, 1), ('1', 0, 0, 0, 3),
    ('1', 0, 7, 7, 3), ('1', 9, 0, 9, 2),
])
def test_privileged_lane_keeps_test_verdicts(monkeypatch, enabled, ordinary,
                                           root, expected, count):
    """An opt-in runs both lanes; a failure in either cannot become success."""
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if isinstance(command, str):
            return SimpleNamespace(returncode=ordinary)
        result = 0 if command[-1] == 'true' else root
        return SimpleNamespace(returncode=result)

    monkeypatch.setattr(coverage.subprocess, 'run', run)
    namespaces = []
    monkeypatch.setattr(coverage, '_run_userns_group',
                        lambda *args: namespaces.append(args) or 0)
    assert coverage._run_suites('/repo', 'ordinary',
        {'COVERAGE_PRIVILEGED': enabled}) == expected
    assert len(calls) == count
    assert bool(namespaces) == (enabled == '1' and ordinary == 0 and root == 0)


@pytest.mark.parametrize('prepare,suite,finish,expected,count', [
    (0, 0, 0, 0, 3), (7, 0, 0, 7, 1), (0, 9, 0, 9, 3), (0, 0, 8, 8, 3)])
def test_namespace_lane_preserves_failures_and_cleans_counters(
        tmp_path, monkeypatch, prepare, suite, finish, expected, count):
    calls = []
    environment = {'TEST_ROOT': str(tmp_path / 'suite'), 'KEEP': 'value',
                   'COVERAGE_USERNS_PROFILE': 'private-test-profile'}

    def run(command, **kwargs):
        calls.append((command, kwargs))
        status = {'prepare': prepare, 'finish': finish}.get(command[-1], suite)
        return SimpleNamespace(returncode=status)

    monkeypatch.setattr(coverage.subprocess, 'run', run)
    assert coverage._run_userns_group(str(tmp_path), environment) == expected
    assert len(calls) == count
    assert environment['TEST_ROOT'] == str(tmp_path / 'suite')
    for _command, options in calls:
        assert options['env']['TEST_ROOT'] == str(tmp_path / 'suite-userns')
        assert options['env']['KEEP'] == 'value'
    if prepare == 0:
        assert calls[1][0][:4] == ['aa-exec', '-p', 'private-test-profile', '--']
        assert '--confcutdir=' + str(tmp_path / 'tests/userns') in calls[1][0]
        assert calls[-1][0][-1] == 'finish'


def test_namespace_launch_exception_still_cleans_counters(tmp_path, monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if '-m' in command:
            raise OSError('test process could not start')
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(coverage.subprocess, 'run', run)
    with pytest.raises(OSError, match='could not start'):
        coverage._run_userns_group(str(tmp_path), {'TEST_ROOT': str(tmp_path / 'suite')})
    assert calls[-1][-1] == 'finish'


@pytest.mark.parametrize('mode', ['prepare', 'finish'])
def test_counter_only_modes_require_root_authority(monkeypatch, mode):
    monkeypatch.setattr(coverage_privileged.os, 'geteuid', lambda: 1000)
    with pytest.raises(RuntimeError, match='requires Linux root'):
        coverage_privileged.main(['--counters-only', mode])


@pytest.mark.parametrize('mode', ['prepare', 'finish'])
def test_counter_only_modes_preserve_execution_without_running_root_tests(
        tmp_path, monkeypatch, mode):
    objects = tmp_path / 'nginx/objs'
    objects.mkdir(parents=True)
    (objects / 'executed.gcno').touch()
    measured = objects / 'executed.gcda'
    measured.write_bytes(b'passing ordinary execution')
    (objects / 'unused.gcno').touch()
    (objects / 'unused.gcda').touch()
    monkeypatch.setattr(coverage_privileged, 'ROOT', tmp_path)
    monkeypatch.setattr(coverage_privileged.sys, 'platform', 'linux')
    monkeypatch.setattr(coverage_privileged.os, 'geteuid', lambda: 0)
    monkeypatch.setenv('COVERAGE_PRIVILEGED', '1')
    monkeypatch.setenv('BRIX_COVERAGE_COUNTERS', str(tmp_path))
    monkeypatch.setenv('NGINX_SRC', str(tmp_path / 'nginx'))
    monkeypatch.setenv('PATH', coverage_privileged.os.environ['PATH'])
    monkeypatch.delenv('SUDO_UID', raising=False)
    identities, groups = [], []
    monkeypatch.setattr(coverage_privileged, '_prepare_namespace_identity',
                        lambda: identities.append(True))
    monkeypatch.setattr(coverage_privileged, '_run_root_group', lambda: groups.append(True))
    assert coverage_privileged.main(['--counters-only', mode]) == 0
    assert measured.read_bytes() == b'passing ordinary execution'
    assert groups == []
    assert bool(identities) == (mode == 'prepare')
    assert (objects / 'unused.gcda').exists() == (mode == 'prepare')


@pytest.mark.parametrize('existing,expected', [
    ('', '100000-165535'), ('other:100000:65536\n', '165536-231071'),
    ('builder:100000:65536\n', None)])
def test_namespace_ranges_keep_existing_and_avoid_other_users(
        tmp_path, monkeypatch, existing, expected):
    path = tmp_path / 'subuid'
    path.write_text(existing)
    calls = []
    monkeypatch.setattr(coverage_privileged.subprocess, 'run',
                        lambda command, **kwargs: calls.append((command, kwargs)))
    coverage_privileged._prepare_namespace_ranges('builder', [(path, '--add-subuids')])
    assert path.read_text() == existing
    assert calls == ([] if expected is None else [
        (['usermod', '--add-subuids', expected, 'builder'], {'check': True})])


@pytest.mark.parametrize('existing', ['owner:-1:65536\n', 'owner:100000:0\n',
                                       'malformed\n', 'other:4294901760:65536\n'])
def test_invalid_namespace_range_never_runs_account_command(tmp_path, monkeypatch, existing):
    path = tmp_path / 'subgid'
    path.write_text(existing)
    calls = []
    monkeypatch.setattr(coverage_privileged.subprocess, 'run',
                        lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError):
        coverage_privileged._prepare_namespace_ranges('builder', [(path, '--add-subgids')])
    assert calls == []


def test_unavailable_root_authority_aborts_before_full_suite(monkeypatch):
    """A requested privileged run cannot silently skip its root tests."""
    monkeypatch.setattr(coverage.subprocess, 'run',
                        lambda *args, **kwargs: SimpleNamespace(returncode=1))
    assert coverage._run_suites('/repo', 'ordinary', {'COVERAGE_PRIVILEGED': '1'}) == 1


def test_root_helper_requires_explicit_opt_in(monkeypatch):
    """Root alone never authorizes account/network fixture mutations."""
    monkeypatch.setattr(coverage_privileged.sys, 'platform', 'linux')
    monkeypatch.setattr(coverage_privileged.os, 'geteuid', lambda: 0)
    monkeypatch.delenv('COVERAGE_PRIVILEGED', raising=False)
    with pytest.raises(RuntimeError, match='COVERAGE_PRIVILEGED=1'):
        coverage_privileged.main()


def test_root_helper_rejects_unprivileged_execution(monkeypatch):
    """The privileged group must not report skips as a successful root run."""
    monkeypatch.setattr(coverage_privileged.os, 'geteuid', lambda: 1000)
    with pytest.raises(RuntimeError, match='requires Linux root'):
        coverage_privileged.main()


def test_counter_preparation_preserves_prior_execution(tmp_path, monkeypatch):
    """Prepare missing files without truncating ordinary-suite measurements."""
    for name in ('executed', 'unexecuted'):
        (tmp_path / f'{name}.gcno').touch()
    measured = tmp_path / 'executed.gcda'
    measured.write_bytes(b'existing execution counters')
    coverage_privileged._prepare_counters([tmp_path])
    assert measured.read_bytes() == b'existing execution counters'
    assert measured.stat().st_mode & 0o666 == 0o666
    monkeypatch.delenv('SUDO_UID', raising=False)
    coverage_privileged._finish_counters([tmp_path], Path(tmp_path))
    assert not (tmp_path / 'unexecuted.gcda').exists()
    assert measured.read_bytes() == b'existing execution counters'


@pytest.mark.parametrize('result', [0, 7, 'exception'])
def test_shared_counters_survive_root_lane_outcomes(tmp_path, monkeypatch, result):
    """Shared build counters remain writable and intact even when tests fail."""
    shared = tmp_path / 'shared/xrdproto/build'
    shared.mkdir(parents=True)
    (shared / 'executed.gcno').touch()
    (shared / 'unused.gcno').touch()
    measured = shared / 'executed.gcda'
    measured.write_bytes(b'ordinary suite execution')
    monkeypatch.setattr(coverage_privileged, 'ROOT', tmp_path)
    monkeypatch.setattr(coverage_privileged.sys, 'platform', 'linux')
    monkeypatch.setattr(coverage_privileged.os, 'geteuid', lambda: 0)
    monkeypatch.delenv('SUDO_UID', raising=False)
    for name, value in {'COVERAGE_PRIVILEGED': '1', 'NGINX_SRC': str(tmp_path),
                        'BRIX_COVERAGE_COUNTERS': str(tmp_path),
                        'TEST_ROOT': str(tmp_path / 'suite')}.items():
        monkeypatch.setenv(name, value)
    # main adjusts these for its child; retain the caller's environment.
    monkeypatch.setenv('PATH', coverage_privileged.os.environ['PATH'])
    monkeypatch.setenv('TMPDIR', str(tmp_path))

    def run_group():
        assert measured.stat().st_mode & 0o666 == 0o666
        assert measured.read_bytes() == b'ordinary suite execution'
        if result == 'exception':
            raise RuntimeError('test runner failed')
        return result

    monkeypatch.setattr(coverage_privileged, '_run_root_group', run_group)
    if result == 'exception':
        with pytest.raises(RuntimeError, match='test runner failed'):
            coverage_privileged.main()
    else:
        assert coverage_privileged.main() == result
    assert not (shared / 'unused.gcda').exists()
    assert measured.read_bytes() == b'ordinary suite execution'
