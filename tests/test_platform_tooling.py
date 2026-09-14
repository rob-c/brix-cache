"""Deterministic platform-tool contracts without a fleet or host mutation."""

import importlib
from pathlib import Path

import pytest


@pytest.fixture()
def tooling(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / 'tools/ci'))
    return importlib.import_module


def test_pal_checker_accepts_platform_owner_and_wrapped_call(tooling):
    module = tooling('check_pal_seam')
    checker = module.PALChecker('.')
    for path, body in ((Path('src/platform/linux/posix_wrapper.c'), 'getrandom(b, n, 0);'),
                       (Path('src/protocols/demo.c'), 'brix_plat_random(b, n);')):
        checker.check_source(path, body)
    assert checker.violations == []
    assert checker.report() == 0


def test_pal_checker_reports_private_definitions_and_includes(tooling, capsys):
    checker = tooling('check_pal_seam').PALChecker('.')
    path = Path('src/protocols/demo.c')
    body = '#include "platform/linux/posix_wrapper.h"\nint brix_plat_random(void) { return 0; }'
    checker.check_source(path, body)
    assert len(checker.violations) == 2
    assert ':1: private PAL header' in checker.violations[0]
    assert ':2: PAL definition brix_plat_random' in checker.violations[1]
    assert checker.report() == 1
    assert 'check_pal_seam: FAIL' in capsys.readouterr().out


def test_pal_missing_build_selection_cannot_pass(tooling, tmp_path):
    checker = tooling('check_pal_seam').PALChecker(str(tmp_path))
    (tmp_path / 'src/platform/linux').mkdir(parents=True)
    checker.check_pal_implementation()
    assert any('implementation source closure failed:' in item
               for item in checker.violations)
    assert checker.report() == 1


@pytest.mark.parametrize('body,expected', [
    ('flags : sse sse2 avx2 aes avx512f\n', (True, True, True)),
    ('', (False, False, False)),
    ('unrecognized : avx2 avx512f aes\n', (False, False, False)),
])
def test_x86_feature_probe_does_not_invent_missing_flags(
    tooling, monkeypatch, body, expected
):
    cpu = tooling('platform_detect_cpu')
    monkeypatch.setattr(cpu.platform, 'system', lambda: 'Linux')
    monkeypatch.setattr(cpu, 'read_optional', lambda path: body)
    result = cpu.detect_x86_features()
    assert tuple(result[name] for name in ('has_avx2', 'has_aes', 'has_avx512')) == expected


@pytest.mark.parametrize('family,host,features,march,tune', [
    ('x86_64', 'linux', {'has_avx2': True}, 'x86-64-v3', 'haswell'),
    ('arm64', 'darwin', {'is_apple_silicon': True, 'apple_chip': 'Apple M2'},
     'armv8.4-a', 'apple-m2'),
    ('arm', 'linux', {'has_neon': True}, 'armv7-a', 'cortex-a9'),
])
def test_optimization_policy_survives_probe_decomposition(
    tooling, monkeypatch, family, host, features, march, tune
):
    build = tooling('platform_detect_build')
    monkeypatch.setattr(build, 'detect_architecture', lambda: {
        'family': family, 'features': features})
    monkeypatch.setattr(build, 'detect_platform', lambda: {'name': host})
    monkeypatch.setattr(build, 'run_command', lambda command: None)
    flags = build.detect_optimization_flags()
    assert flags['march'] == ['-march=' + march]
    assert flags['mtune'] == ['-mtune=' + tune]


def test_failed_compiler_probe_does_not_enable_lto(tooling, monkeypatch):
    build = tooling('platform_detect_build')
    monkeypatch.setattr(build, 'run_command', lambda command: 'gcc 12.3.0')
    monkeypatch.setattr(build, '_compiler_accepts', lambda compiler, flag: False)
    result = build.detect_compiler_support()
    assert result['name'] == 'gcc'
    assert result['supports_lto'] is False
    assert result['supports_lto_thin'] is False


def test_missing_probe_program_returns_no_observation(tooling, monkeypatch):
    command = tooling('platform_detect_command')

    def unavailable(*args, **kwargs):
        raise FileNotFoundError('test fixture: absent probe')

    monkeypatch.setattr(command.subprocess, 'run', unavailable)
    assert command.run_command(['missing-probe']) is None
