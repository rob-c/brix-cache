"""Contract jobs retain native proofs without building unused metric engines."""

import os
from pathlib import Path
import subprocess

import pytest

from test_native_target_runners import _freebsd_workflow_step
from tools.ci import freebsd_native


def _dependency_script(level):
    run = _freebsd_workflow_step()['run']
    start = run.index("su -l brixvalidate -c '/home/brixvalidate/test-python/bin/python -m pip install")
    end = run.index("su -l brixvalidate -c 'env GOBIN=/tmp/gohep-bin")
    return 'set -eu\n' + run[start:end].replace("${{ inputs.test_level || 'contracts' }}", level)


def _run_dependencies(tmp_path, level, failure='0'):
    fake = tmp_path / 'su'
    fake.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CI_SU_LOG"\n'
                    'case "$*" in *complexipy*) exit "$CI_METRICS_EXIT";; esac\n')
    fake.chmod(0o755)
    record = tmp_path / 'commands'
    result = subprocess.run(['bash', '-c', _dependency_script(level)],
        env={**os.environ, 'PATH': str(tmp_path) + os.pathsep + os.environ['PATH'],
             'CI_SU_LOG': str(record), 'CI_METRICS_EXIT': failure}, capture_output=True)
    return result, record.read_text().splitlines()


@pytest.mark.parametrize('level,metrics', [('contracts', False), ('full', True)])
def test_only_full_validation_builds_the_metric_engine(tmp_path, level, metrics):
    result, commands = _run_dependencies(tmp_path, level)
    assert result.returncode == 0
    assert any('pyOpenSSL' in command for command in commands)
    assert any('complexipy' in command for command in commands) == metrics
    assert all(command.startswith('-l brixvalidate -c ') for command in commands)


def test_full_validation_metric_install_failure_is_preserved(tmp_path):
    result, _commands = _run_dependencies(tmp_path, 'full', '17')
    assert result.returncode == 17


def test_emulated_crypto_fixture_keeps_a_finite_compile_budget(tmp_path):
    command = freebsd_native.validation_commands(tmp_path, 'contracts')[1]
    assert '--timeout=180' in command
    assert 'no:rerunfailures' in command
    assert 'tests/test_openssl_key_compat.py' in command
    assert 'tests/test_gsi_proxy_crypto.py' in command
