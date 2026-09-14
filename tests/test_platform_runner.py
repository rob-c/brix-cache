"""Offline argv, report, platform-boundary and child-verdict checks for PAL runners."""

from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent / 'platform'))
import platform_test_runner as runner


def test_common_runner_selects_host_and_shared_tests_once(tmp_path):
    options = runner._parser().parse_args([])
    command = runner.command(options, False, tmp_path, 'linux', 'arm64')
    assert command[:3] == [sys.executable, '-m', 'pytest']
    assert command.count(str(tmp_path / 'test_arm64_linux.py')) == 1
    assert str(tmp_path / 'test_pal_api.py') in command
    assert not any('test_windows.py' in item for item in command)


def test_integration_reports_and_performance_use_actual_owner(tmp_path):
    options = runner._parser().parse_args(['--performance', '--coverage', '--html', '--junit', '-q'])
    command = runner.command(options, True, tmp_path, 'linux', 'x86_64')
    assert str(tmp_path / 'test_phase3_integration.py') + '::TestPerformanceRegression' in command
    assert '--cov=pal_test_helpers' in command
    assert '--junitxml=' + str(tmp_path / 'test_results/results.xml') in command
    assert '--html=' + str(tmp_path / 'test_results/report.html') in command
    assert '-q' in command and '-m performance' not in command


def test_environment_retains_parent_safety_options(monkeypatch, tmp_path):
    monkeypatch.setenv('PYTEST_ADDOPTS', '--deselect=tests/fixture.py::excluded')
    monkeypatch.setenv('PYTHONPATH', str(tmp_path / 'inherited'))
    directory = tmp_path / 'tests/platform'
    env = runner._environment(directory)
    assert env['PYTEST_ADDOPTS'] == '--deselect=tests/fixture.py::excluded'
    assert str(tmp_path / 'inherited') in env['PYTHONPATH']
    assert str(tmp_path / 'brixtest/src') in env['PYTHONPATH']


@pytest.mark.parametrize('code,expected', [(0, 0), (1, 1), (5, 5), (-15, 143)])
def test_runner_propagates_child_verdict(monkeypatch, tmp_path, code, expected):
    directory = tmp_path / 'tests/platform'
    directory.mkdir(parents=True)
    monkeypatch.setattr(runner, '__file__', str(directory / 'platform_test_runner.py'))
    monkeypatch.setattr(runner, '_host', lambda: ('linux', 'x86_64'))
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, code)

    monkeypatch.setattr(runner.subprocess, 'run', run)
    assert runner.main(['--platform', 'linux'], integration=True) == expected
    assert len(calls) == 1
    assert str(directory / 'test_phase3_integration.py') in calls[0][0]
    assert calls[0][1]['cwd'] == directory


@pytest.mark.parametrize('arguments', [['--platform', 'windows'], ['--not-an-option']])
def test_runner_rejects_invalid_scope_before_child(monkeypatch, arguments):
    monkeypatch.setattr(runner, '_host', lambda: ('linux', 'x86_64'))

    def forbidden(*args, **kwargs):
        pytest.fail('invalid scope must not execute pytest')

    monkeypatch.setattr(runner.subprocess, 'run', forbidden)
    with pytest.raises(SystemExit) as exc:
        runner.main(arguments)
    assert exc.value.code == 2
