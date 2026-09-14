"""Preserve forwarding subprocess contracts while preparing selected nginx."""
from types import SimpleNamespace

import pytest

from cmdscripts import fwd_matrix_live
from test_cmdscript_nginx_preparation import command_fixture


@pytest.mark.parametrize('mode,returncode', [
    ('success', 0), ('parse-error', 1), ('unrelated', 0),
])
def test_forward_call_prepares_owned_binary(command_fixture, monkeypatch, mode, returncode):
    _, frozen, prefix, config, original, module = command_fixture
    selected = prefix / frozen.name if mode == 'unrelated' else frozen
    calls = []

    def popen(arguments, **options):
        calls.append((arguments, options))
        return SimpleNamespace(returncode=returncode,
                               communicate=lambda *args, **kwargs: ('output', 'diagnostic'))

    monkeypatch.setenv('NGINX', 'fixture inherited socket marker')
    monkeypatch.setenv('XRDC_GSI_DELEGATE', 'fixture delegation marker')
    monkeypatch.setattr(fwd_matrix_live.subprocess, 'Popen', popen)
    result = fwd_matrix_live._call(
        [selected, '-t', '-p', prefix, '-c', config],
        env_drop=('NGINX', 'XRDC_GSI_DELEGATE'), env_add={'FORWARD_FIXTURE': 'present'},
    )
    assert result.returncode == returncode
    assert result.stdout == 'output' and result.stderr == 'diagnostic'
    assert len(calls) == 1
    _assert_forward_preparation(mode, calls[0], config, original, module, prefix)


def _assert_forward_preparation(mode, call, config, original, module, prefix):
    arguments, options = call
    assert 'NGINX' not in options['env']
    assert 'XRDC_GSI_DELEGATE' not in options['env']
    assert options['env']['FORWARD_FIXTURE'] == 'present'
    if mode == 'unrelated':
        assert config.read_text() == original and '-e' not in arguments
        return
    text = config.read_text()
    assert f'load_module "{module}";' in text
    assert 'proxy_temp_path' in text
    assert arguments[arguments.index('-e') + 1] == str(prefix / 'logs/bootstrap.log')


def test_forward_file_output_preserves_bytes_and_stderr(tmp_path, monkeypatch):
    output = tmp_path / 'transfer.bin'

    def popen(arguments, **options):
        assert options['text'] is False
        options['stdout'].write(b'owned transfer bytes\x00')
        return SimpleNamespace(returncode=0,
                               communicate=lambda *args, **kwargs: (None, b'byte diagnostic'))

    monkeypatch.setattr(fwd_matrix_live.subprocess, 'Popen', popen)
    result = fwd_matrix_live._call(['fixture-client'], stdout_to=output)
    assert result.returncode == 0 and result.stderr == 'byte diagnostic'
    assert result.stdout == ''
    assert output.read_bytes() == b'owned transfer bytes\x00'
