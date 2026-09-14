"""Verify raw LiveRun nginx calls receive preparation without starting servers."""

from types import SimpleNamespace

import pytest

from cmdscripts import live_common
from config_templates import render_config


@pytest.mark.parametrize('mode', ['frozen-binary', 'explicit-log', 'other-command'])
def test_live_call_prepares_only_its_selected_nginx(tmp_path, monkeypatch, mode):
    """Prepare the owned binary, preserve -e, and leave unrelated programs alone."""
    prefix = tmp_path / 'prefix'
    prefix.mkdir()
    config = prefix / 'nginx.conf'
    original = render_config('nginx_live_call_preparation.conf', strict=True)
    config.write_text(original)
    module = tmp_path / 'fixture_module.so'
    monkeypatch.setenv('TEST_NGINX_LOAD_MODULES', str(module))
    run = live_common.LiveRun.__new__(live_common.LiveRun)
    run.root = prefix
    run.nginx = tmp_path / 'nginx-frozen-fixture'
    calls = []

    def popen(arguments, **options):
        calls.append((arguments, options))
        return SimpleNamespace(returncode=7, communicate=lambda _: ('', 'parse refused'))

    monkeypatch.setattr(live_common.subprocess, 'Popen', popen)
    arguments = _arguments(run, tmp_path, mode)
    result = run.call(arguments, cwd=tmp_path, check=False)
    assert result.returncode == 7 and result.stderr == 'parse refused'
    assert len(calls) == 1
    command, options = calls[0]
    assert options['cwd'] == str(tmp_path)
    _assert_preparation(mode, config, original, module, command, prefix)


def _arguments(run, tmp_path, mode):
    executable = tmp_path / 'other' / run.nginx.name if mode == 'other-command' else run.nginx
    arguments = [executable, '-t', '-p', 'prefix', '-c', 'nginx.conf']
    if mode == 'explicit-log':
        arguments += ['-e', 'stderr']
    return arguments


def _assert_preparation(mode, config, original, module, command, prefix):
    """Inspect the prepared config and the exact bootstrap logging choice."""
    if mode == 'other-command':
        assert config.read_text() == original
        assert '-e' not in command
        assert not (prefix / 'logs').exists()
        return
    text = config.read_text()
    assert f'load_module "{module}";' in text
    assert 'client_body_temp_path' in text
    assert str(prefix / 'logs') in text
    assert command.count('-e') == 1
    expected = 'stderr' if mode == 'explicit-log' else str(prefix / 'logs/bootstrap.log')
    assert command[command.index('-e') + 1] == expected
