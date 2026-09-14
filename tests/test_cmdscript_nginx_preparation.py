"""Exercise selected nginx command preparation without starting listeners."""
from pathlib import Path
import subprocess

import pytest

import cmdscripts
from cmdscripts import fake_nginx, live_common
from config_templates import render_config


@pytest.fixture
def command_fixture(tmp_path, monkeypatch):
    source_dir = tmp_path / 'source'
    source_dir.mkdir()
    source = Path(fake_nginx.install(source_dir, 'chosen-engine'))
    monkeypatch.setattr(live_common, '_FROZEN_NGINX', {})
    monkeypatch.setattr(live_common, '_FREEZE_ROOT', tmp_path / 'freeze')
    monkeypatch.setenv('TEST_NGINX_BIN', str(source))
    monkeypatch.setenv('NGINX_BIN', str(source))
    frozen = live_common.freeze_nginx(source)
    prefix = tmp_path / 'prefix'
    prefix.mkdir()
    config = prefix / 'nginx.conf'
    original = render_config('nginx_live_call_preparation.conf', strict=True)
    config.write_text(original)
    module = tmp_path / 'fixture_module.so'
    monkeypatch.setenv('TEST_NGINX_LOAD_MODULES', str(module))
    return source, frozen, prefix, config, original, module


def _capture_commands(monkeypatch, outcome):
    calls = []

    def invoke(arguments, **options):
        calls.append((arguments, options))
        return subprocess.CompletedProcess(arguments, outcome, '', 'configuration diagnostic')

    monkeypatch.setattr(cmdscripts.subprocess, 'run', invoke)
    return calls


@pytest.mark.parametrize('selection', ['configured', 'frozen', 'lookalike'])
def test_run_prepares_exact_selected_identity(command_fixture, monkeypatch, selection):
    source, frozen, prefix, config, original, module = command_fixture
    executable = {'configured': source, 'frozen': frozen,
                  'lookalike': prefix / frozen.name}[selection]
    calls = _capture_commands(monkeypatch, 17)
    result = cmdscripts.run([executable, '-t', '-p', prefix, '-c', config])
    assert result.returncode == 17 and result.stderr == 'configuration diagnostic'
    assert len(calls) == 1
    command, options = calls[0]
    assert options['timeout'] == 120
    _assert_identity_preparation(selection, config, original, module, command, prefix)


def _assert_identity_preparation(selection, config, original, module, command, prefix):
    if selection == 'lookalike':
        assert config.read_text() == original
        assert '-e' not in command and not (prefix / 'logs').exists()
        return
    text = config.read_text()
    assert f'load_module "{module}";' in text
    assert 'client_body_temp_path' in text
    assert command[command.index('-e') + 1] == str(prefix / 'logs/bootstrap.log')


def test_run_preserves_explicit_log_and_timeout_diagnostic(command_fixture, monkeypatch):
    _, frozen, prefix, config, _, _ = command_fixture

    def expire(arguments, **_options):
        raise subprocess.TimeoutExpired(arguments, 3, output=b'partial', stderr=b'parse detail')

    monkeypatch.setattr(cmdscripts.subprocess, 'run', expire)
    result = cmdscripts.run([frozen, '-t', '-p', prefix, '-c', config, '-e', 'stderr'], timeout=3)
    assert result.returncode == 124 and result.stdout == 'partial'
    assert result.stderr == 'parse detail\n[timed out after 3s]'
    assert result.args.count('-e') == 1 and result.args[-1] == 'stderr'


@pytest.mark.parametrize('probe', [None, '-t', '-T', '-s', '-v', '-V'])
def test_only_selected_server_start_opens_worker_tree(command_fixture, monkeypatch, probe):
    _, frozen, prefix, config, _, _ = command_fixture
    opened = []
    monkeypatch.setattr(cmdscripts.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(cmdscripts, 'open_tree_for_worker', lambda *args: opened.append(args))
    _capture_commands(monkeypatch, 0)
    command = [frozen, '-p', prefix, '-c', config]
    command.extend([] if probe is None else [probe])
    assert cmdscripts.run(command).returncode == 0
    assert opened == ([(prefix, config)] if probe is None else [])


def test_selected_static_binary_refuses_dynamic_stream_module(command_fixture, monkeypatch):
    _, frozen, prefix, config, original, _ = command_fixture
    monkeypatch.setenv('TEST_NGINX_LOAD_MODULES', str(prefix / 'ngx_stream_module.so'))
    calls = _capture_commands(monkeypatch, 0)
    with pytest.raises(live_common.LiveFailure, match='static/dynamic build overlap'):
        cmdscripts.run([frozen, '-t', '-p', prefix, '-c', config])
    assert calls[0][0] == [str(frozen), '-V'] and len(calls) == 1
    assert config.read_text() == original and not (prefix / 'logs').exists()
