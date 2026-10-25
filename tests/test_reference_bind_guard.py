"""Prove the external-oracle socket adapter using real libc binds, not mocks."""
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.fixture(scope='module')
def bind_adapter(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    build = tmp_path_factory.mktemp('reference-bind')
    guard, probe = build / 'guard.so', build / 'probe'
    flag = '-dynamiclib' if sys.platform == 'darwin' else '-shared'
    libraries = ['-ldl'] if sys.platform.startswith('linux') else []
    subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-fPIC', flag,
        str(root / 'tools/ci/reference_bind_guard.c'), *libraries, '-o', str(guard)], check=True, timeout=30)
    subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', str(root / 'tests/c/reference_bind_probe.c'),
        '-o', str(probe)], check=True, timeout=30)
    # Other fixture modules intentionally use umask(0) for shared data trees.
    # Executable adapters are private authority, never shared writable data.
    guard.chmod(0o700)
    probe.chmod(0o700)
    return guard, probe


def _probe(bind_adapter, host, *, adapted=True):
    from ephemeral_port import free_port

    guard, executable = bind_adapter
    environment = dict(os.environ)
    if adapted:
        from tools.ci.remote_reference_daemon import environment as selected_environment
        from types import SimpleNamespace
        environment = selected_environment(SimpleNamespace(daemon_bind_guard=guard), environment)
    return subprocess.run([str(executable), host, str(free_port())], env=environment,
                          capture_output=True, text=True, timeout=5)


@pytest.mark.parametrize('host,expected', [('0.0.0.0', '127.0.0.1'), ('::', '::1'),  # net-literal-allow: bind adapter wildcard-to-loopback contract
                                         ('127.0.0.1', '127.0.0.1'), ('::1', '::1')])  # net-literal-allow: external-oracle loopback adapter probe
def test_adapter_constrains_wildcards_and_preserves_explicit_loopback(bind_adapter, host, expected):
    result = _probe(bind_adapter, host)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected


@pytest.mark.parametrize('host', ['192.0.2.1', '2001:db8::1'])  # net-literal-allow: forbidden bind destinations
def test_adapter_refuses_non_loopback_before_kernel_address_selection(bind_adapter, host):
    result = _probe(bind_adapter, host)
    assert result.returncode == 13, (result.returncode, result.stderr)
    assert result.stdout == ''


def test_unadapted_control_really_observes_a_wildcard(bind_adapter):
    result = _probe(bind_adapter, '0.0.0.0', adapted=False)  # net-literal-allow: isolated closed control socket
    assert result.returncode == 0
    assert result.stdout.strip() == '0.0.0.0'  # net-literal-allow: exact wildcard control observation
