"""Interrupted or mismatched coverage phases must never satisfy the CI gate."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.ci import coverage, coverage_host, coverage_stages as stages


@pytest.fixture
def measurement(tmp_path, monkeypatch):
    root, sdk, report = (tmp_path / name for name in ('repo', 'sdk', 'report'))
    units = report / 'unit-counters-current'
    units.mkdir(parents=True)
    calls = []
    monkeypatch.setenv('COVERAGE_PRIVILEGED', '1')
    monkeypatch.setenv('COVERAGE_MIN', '90')
    monkeypatch.delenv('COVERAGE_CEPH', raising=False)
    monkeypatch.setattr(coverage, '_build', lambda *args: calls.append('build'))

    def prepare(*_args):
        calls.append('reset')
        return [], str(report / 'coverage.initial.info'), units

    monkeypatch.setattr(coverage, '_prepare_measurement', prepare)
    monkeypatch.setattr(stages, '_execute', lambda stage, *_args: calls.append(stage) or 0)
    monkeypatch.setattr(coverage, '_report', lambda *args: args[-1])
    args = tuple(map(str, (root, sdk, report))) + ('full-suite',)
    return SimpleNamespace(args=args, report=report, units=units, calls=calls)


def test_stages_keep_one_inventory_and_all_counters(measurement):
    for phase in ('prepare', 'ordinary', 'privileged', 'userns', 'report'):
        assert stages.run(phase, *measurement.args) == 0
    assert measurement.calls == ['build', 'reset', 'ordinary', 'privileged', 'userns']
    state = json.loads((measurement.report / 'stages.json').read_text())
    assert state['results'] == dict.fromkeys(('ordinary', 'privileged', 'userns'), 0)


@pytest.mark.parametrize('ceph_result', [0, 7])
def test_live_ceph_phase_is_required_and_keeps_its_verdict(measurement, monkeypatch, ceph_result):
    """A missing lab or a native contract failure cannot satisfy the floor."""
    monkeypatch.setenv('COVERAGE_CEPH', '1')
    monkeypatch.setattr(stages, '_execute',
                        lambda phase, *_args: {'ceph': ceph_result}.get(phase, 0))
    stages.run('prepare', *measurement.args)
    for phase in ('ordinary', 'privileged', 'userns'):
        stages.run(phase, *measurement.args)
    assert stages.run('report', *measurement.args) == 1
    assert stages.run('ceph', *measurement.args) == ceph_result
    assert stages.run('report', *measurement.args) == (1 if ceph_result else 0)


@pytest.mark.parametrize('phase', ['ordinary', 'privileged', 'userns'])
def test_failed_phase_still_fails_after_later_success(measurement, monkeypatch, phase):
    monkeypatch.setattr(stages, '_execute', lambda current, *_args: 7 if current == phase else 0)
    assert stages.run('prepare', *measurement.args) == 0
    for current in ('ordinary', 'privileged', 'userns'):
        assert stages.run(current, *measurement.args) == (7 if current == phase else 0)
    assert stages.run('report', *measurement.args) == 1


@pytest.mark.parametrize('result', [None, 'running', False, True, 3])
def test_missing_or_interrupted_phases_cannot_pass_with_full_coverage(result):
    state = {'identity': {'privileged': True},
             'results': {'ordinary': 0, 'privileged': result, 'userns': 0}}
    assert stages._phase_verdict(state) == 1


def test_stale_preparation_cannot_reset_or_reuse_a_previous_run(measurement):
    assert stages.run('prepare', *measurement.args) == 0
    with pytest.raises(FileExistsError):
        stages.run('prepare', *measurement.args)
    assert measurement.calls == ['build', 'reset']


def test_a_phase_cannot_run_twice_or_out_of_order(measurement):
    stages.run('prepare', *measurement.args)
    with pytest.raises(ValueError, match='previous'):
        stages.run('privileged', *measurement.args)
    stages.run('ordinary', *measurement.args)
    with pytest.raises(ValueError, match='already started'):
        stages.run('ordinary', *measurement.args)


@pytest.mark.parametrize('variable,value', [('COVERAGE_MIN', '0'), ('COVERAGE_PRIVILEGED', '0'),
                                          ('COVERAGE_CEPH', '1')])
def test_floor_and_required_groups_cannot_change_mid_measurement(
        measurement, monkeypatch, variable, value):
    stages.run('prepare', *measurement.args)
    monkeypatch.setenv(variable, value)
    with pytest.raises(ValueError, match='prepared SDK'):
        stages.run('report', *measurement.args)


@pytest.mark.parametrize('target', ['../unit-counters-outside', '/tmp/unit-counters-outside'])
def test_checkpoint_cannot_redirect_counter_capture(measurement, target):
    stages.run('prepare', *measurement.args)
    path = measurement.report / 'stages.json'
    state = json.loads(path.read_text())
    state['units'] = target
    path.write_text(json.dumps(state))
    with pytest.raises(ValueError):
        stages.run('report', *measurement.args)


def test_symlink_cannot_redirect_counter_capture(measurement, tmp_path):
    stages.run('prepare', *measurement.args)
    measurement.units.rmdir()
    measurement.units.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match='escaped'):
        stages.run('report', *measurement.args)


def test_killed_phase_keeps_an_incomplete_verdict(measurement, monkeypatch):
    stages.run('prepare', *measurement.args)

    def interrupted(*_args):
        raise KeyboardInterrupt

    monkeypatch.setattr(stages, '_execute', interrupted)
    with pytest.raises(KeyboardInterrupt):
        stages.run('ordinary', *measurement.args)
    assert stages.run('report', *measurement.args) == 1


def test_host_wrapper_bounds_memory_and_uses_a_private_pid_namespace():
    environment = {'PATH': '/tools/bin', 'COVERAGE_MIN': '90',
                   'GITHUB_TOKEN': 'must-not-reach-service', 'AWS_SECRET_ACCESS_KEY': 'secret'}
    command = coverage_host._command('ordinary', Path('/repo path'), '/venv/python',
                                     'runner', 16 * 1024**3, environment)
    assert '--property=MemoryMax=12884901888' in command
    assert '--property=MemorySwapMax=0' in command
    assert '--property=OOMPolicy=kill' in command
    assert '--pid' in command and '--mount-proc' in command and '--kill-child' in command
    assert '--net' not in command
    assert '--working-directory=/repo path' in command
    assert 'PATH=/tools/bin' in command and 'COVERAGE_MIN=90' in command
    assert not any('secret' in arg or 'TOKEN' in arg for arg in command)


def test_host_wrapper_uses_a_reaper_before_starting_the_test_identity():
    command = coverage_host._command('ordinary', Path('/repo'), '/python', 'runner', 1024, {})
    first = command.index('/usr/bin/tini')
    assert command[first:first + 3] == ['/usr/bin/tini', '--', '/usr/sbin/runuser']


def test_host_environment_passes_literal_values_without_a_shell():
    hostile = 'value with spaces; $(touch /tmp/should-not-exist)'
    assert coverage_host._environment({'TEST_ROOT': hostile}) == ['TEST_ROOT=' + hostile]


@pytest.mark.parametrize('code,extra,expected', [
    (25, '', ['/repo/src/*']), (2, '', ['/repo/src/*']),
    (-9, '', []), (0, '', []), (2, '\ngeninfo: ERROR: corrupt counter', []),
])
def test_unused_filter_retry_never_masks_data_errors_or_signals(code, extra, expected):
    error = "geninfo: ERROR: 'include' pattern '/repo/src/*' is unused."
    result = SimpleNamespace(returncode=code, stderr=error + extra)
    assert coverage._unused_capture_patterns(result, ['/repo/src/*']) == expected


@pytest.mark.parametrize('code', [0, 7, 137])
def test_host_wrapper_preserves_failures_and_takes_final_snapshot(monkeypatch, code):
    snapshots = []
    monkeypatch.setattr(coverage_host.sys, 'platform', 'linux')
    monkeypatch.setattr(coverage_host.os, 'getuid', lambda: 2100)
    monkeypatch.setattr(coverage_host.os, 'sysconf', lambda _name: 4096)
    monkeypatch.setattr(coverage_host.pwd, 'getpwuid', lambda _uid: SimpleNamespace(pw_name='runner'))
    monkeypatch.setattr(coverage_host, '_snapshot', lambda: snapshots.append(True))
    monkeypatch.setattr(coverage_host.subprocess, 'run',
                        lambda _command, **_kw: SimpleNamespace(returncode=code))
    assert coverage_host.main(['ordinary']) == code
    assert len(snapshots) == 2
