"""Standalone OCI probes must link the real host adapter and selected SDKs."""
from pathlib import Path
from types import SimpleNamespace
import subprocess

import pytest

import test_oci_flatten as flatten
import test_oci_stargz as stargz


def _build(module, output):
    """Exercise the actual fixture builder without launching a fleet."""
    if module is flatten:
        return module.flatten_ut.__wrapped__(SimpleNamespace(mktemp=lambda _: output))
    return module._build('native-cc', ['fixture.c'], str(output / 'probe'))


@pytest.fixture(params=[flatten, stargz], ids=['flatten', 'stargz'])
def builder(request, monkeypatch):
    """Record compiler argv while preserving the production builder's decisions."""
    module = request.param
    commands = []

    def compile_probe(command, **options):
        commands.append((command, options))
        return subprocess.CompletedProcess(command, 0, '', '')

    monkeypatch.setattr(flatten, '_compiler', lambda: 'native-cc')
    monkeypatch.setattr(module.subprocess, 'run', compile_probe)
    monkeypatch.setattr(module, 'pal_xattr_sources',
                        lambda: ['src/platform/freebsd/xattr_wrapper.c'])
    monkeypatch.setattr(module, 'library_compile_args',
                        lambda arguments: [*arguments, '-I/selected/sdk include'])
    return module, commands


def test_oci_driver_links_exact_native_xattr_owner(builder, tmp_path):
    """Success: FreeBSD is not allowed to compile out the xattr implementation."""
    module, commands = builder
    _build(module, tmp_path)
    command, _ = commands[0]
    assert command.count(str(Path(module.REPO) / 'src/platform/freebsd/xattr_wrapper.c')) == 1
    assert '-I/selected/sdk include' in command
    assert '-lsqlite3' in command and '-lcrypto' in command


def test_oci_compile_failure_remains_a_failure(builder, monkeypatch, tmp_path):
    """Error: unavailable symbols must not become a dependency skip."""
    module, _ = builder
    monkeypatch.setattr(module.subprocess, 'run', lambda command, **options:
                        subprocess.CompletedProcess(command, 1, '', 'missing native symbol'))
    with pytest.raises(AssertionError, match='missing native symbol'):
        _build(module, tmp_path)


def test_oci_sdk_and_output_paths_are_never_shell_commands(builder, tmp_path):
    """Security-negative: spaces and shell syntax remain literal argv fields."""
    module, commands = builder
    output = tmp_path / 'build space; echo SHOULD_NOT_EXECUTE'
    output.mkdir()
    _build(module, output)
    command, options = commands[0]
    assert any(str(output) in argument for argument in command)
    assert '-I/selected/sdk include' in command
    assert options.get('shell') is not True
