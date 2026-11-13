"""Run the actual configure profiles with strict and warning-only compilers."""

import os
from pathlib import Path
import subprocess
import sys

import pytest


def _profile_script():
    source = (Path(__file__).resolve().parents[1] / 'config').read_text()
    probe = source.split('brix_cc_supports() {', 1)[1].split('\n}', 1)[0]
    profile = source.split('# x86_64 optimization profiles\n', 1)[1]
    profile = profile.split('\nelse\n    # Unknown architecture', 1)[0]
    return ('brix_cc_supports() {' + probe + '\n}\n'
            'if false; then :;\n' + profile + '\nfi\nprintf "%s\\n" "$CFLAGS"\n')


def _run_profile(compiler, profile='v2'):
    environment = {**os.environ, 'CC': compiler, 'BRIX_ARCH_X86_64': '1',
                   'BRIX_OPTIMIZE': profile,
                   'CFLAGS': '-Werror=format-security -fstack-protector-strong'}
    result = subprocess.run(['sh', '-eu', '-c', _profile_script()], env=environment,
                            capture_output=True, text=True, check=True)
    return result.stdout.splitlines()[-1].split()


@pytest.fixture
def compiler_stub(tmp_path):
    compiler = tmp_path / 'cc'
    compiler.write_text('#!/bin/sh\ncat >/dev/null\n'
                        'printf "%s\\n" "$BRIX_CC_DIAGNOSTIC" >&2\n'
                        'exit "$BRIX_CC_RESULT"\n')
    compiler.chmod(0o755)
    return str(compiler)


@pytest.mark.parametrize('profile,march', [('v2', 'x86-64-v2'), ('v3', 'x86-64-v3'),
                                         ('native', 'native'), ('unknown', 'x86-64-v2')])
def test_supported_compiler_keeps_the_existing_x86_flags(compiler_stub, monkeypatch,
                                                        profile, march):
    monkeypatch.setenv('BRIX_CC_RESULT', '0')
    monkeypatch.setenv('BRIX_CC_DIAGNOSTIC', '')
    assert _run_profile(compiler_stub, profile) == [
        '-Werror=format-security', '-fstack-protector-strong', '-O3',
        '-march=' + march, '-fno-plt']


@pytest.mark.parametrize('returncode,diagnostic', [
    (1, 'error: unsupported flag -fno-plt'),
    (0, "warning: argument unused during compilation: '-fno-plt'"),
])
def test_rejected_or_diagnostic_flags_cannot_disable_build_hardening(
        compiler_stub, monkeypatch, returncode, diagnostic):
    monkeypatch.setenv('BRIX_CC_RESULT', str(returncode))
    monkeypatch.setenv('BRIX_CC_DIAGNOSTIC', diagnostic)
    assert _run_profile(compiler_stub) == [
        '-Werror=format-security', '-fstack-protector-strong', '-O3', '-march=x86-64-v2']


def test_disabled_profile_does_not_add_optimization_flags(monkeypatch):
    monkeypatch.setenv('BRIX_CC_RESULT', '1')
    assert _run_profile('/no/compiler/is/needed', 'none') == [
        '-Werror=format-security', '-fstack-protector-strong']


@pytest.mark.skipif(sys.platform != 'darwin', reason='requires Apple Clang')
def test_real_intel_apple_clang_omits_the_unsupported_elf_flag():
    flags = _run_profile('cc -arch x86_64')
    assert '-fno-plt' not in flags
    assert '-Werror=format-security' in flags
