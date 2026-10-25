"""Analyzer wrappers must inspect the same configured build as their runners."""

from pathlib import Path

import pytest

import test_ci_guards as guards


@pytest.fixture
def configured_build(tmp_path, monkeypatch):
    build = tmp_path / "configured-nginx"
    makefile = build / "objs/Makefile"
    makefile.parent.mkdir(parents=True)
    makefile.write_text("CFLAGS = -O2\n")
    monkeypatch.setenv("NGX_BUILD", str(build))
    monkeypatch.delenv("NGX_MAKEFILE", raising=False)
    monkeypatch.setattr(guards, "_have", lambda tool: True)
    return makefile


def test_custom_configured_build_runs_analyzer(configured_build, monkeypatch):
    calls = []
    monkeypatch.setattr(guards, "_run", lambda runner: (calls.append(runner) or 0, "clean"))
    guards.test_ci_analyzer_runner_green("run_fanalyzer", "gcc")
    assert guards._analyzer_makefile() == configured_build
    assert calls == ["run_fanalyzer"]


def test_missing_custom_build_reports_its_path(tmp_path, monkeypatch):
    missing = tmp_path / "missing-build"
    monkeypatch.setenv("NGX_BUILD", str(missing))
    monkeypatch.delenv("NGX_MAKEFILE", raising=False)
    with pytest.raises(pytest.skip.Exception, match=str(missing)):
        guards.test_ci_analyzer_runner_green("run_fanalyzer", "gcc")


def test_analyzer_failure_is_not_hidden(configured_build, monkeypatch):
    monkeypatch.setattr(guards, "_run", lambda runner: (1, "analysis failed"))
    with pytest.raises(AssertionError, match="analysis failed"):
        guards.test_ci_analyzer_runner_green("run_fanalyzer", "gcc")


def test_missing_analyzer_is_explicit(configured_build, monkeypatch):
    monkeypatch.setattr(guards, "_have", lambda tool: False)
    with pytest.raises(pytest.skip.Exception, match="CodeChecker not installed"):
        guards.test_ci_analyzer_runner_green("run_codechecker", "CodeChecker")


def test_default_build_matches_runner_default(monkeypatch):
    monkeypatch.delenv("NGX_BUILD", raising=False)
    monkeypatch.delenv("NGX_MAKEFILE", raising=False)
    assert guards._analyzer_makefile() == Path("/tmp/nginx-1.28.3/objs/Makefile")


def test_separate_cmake_graph_runs_without_an_in_tree_objs_directory(tmp_path, monkeypatch):
    makefile = tmp_path / 'modules/Makefile'
    makefile.parent.mkdir()
    makefile.write_text('CFLAGS = -O2\n')
    monkeypatch.setenv('NGX_BUILD', str(tmp_path / 'nginx-src'))
    monkeypatch.setenv('NGX_MAKEFILE', str(makefile))
    monkeypatch.setattr(guards, '_have', lambda tool: True)
    monkeypatch.setattr(guards, '_run', lambda runner: (0, 'clean'))
    guards.test_ci_analyzer_runner_green('run_fanalyzer', 'gcc')
    assert guards._analyzer_makefile() == makefile


def test_missing_explicit_graph_cannot_borrow_an_unrelated_build(configured_build, monkeypatch):
    missing = configured_build.parent.parent / 'foreign/missing-Makefile'
    monkeypatch.setenv('NGX_MAKEFILE', str(missing))
    monkeypatch.setattr(guards, '_run', lambda runner: pytest.fail('must not analyze a different SDK'))
    with pytest.raises(pytest.skip.Exception, match='foreign'):
        guards.test_ci_analyzer_runner_green('run_fanalyzer', 'gcc')
    assert guards._analyzer_makefile() == missing


@pytest.mark.parametrize('name', ['run_fanalyzer', 'run_codechecker'])
def test_analyzer_extracts_flags_from_the_selected_graph_and_compiler_cwd(monkeypatch, tmp_path, name):
    import importlib
    import subprocess

    runner = importlib.import_module('tools.ci.' + name)
    makefile = tmp_path / 'modules/Makefile'
    source = tmp_path / 'nginx-src'
    monkeypatch.setattr(runner, 'MK', str(makefile))
    monkeypatch.setattr(runner, 'NGX_BUILD', str(source))
    monkeypatch.setattr(runner.shutil, 'which', lambda command: '/native/gmake')
    calls = []
    monkeypatch.setattr(runner.subprocess, 'run', lambda command, **kwargs:
        calls.append(command) or subprocess.CompletedProcess(command, 0, stdout='-O2'))
    assert runner.read_var('CFLAGS') == '-O2'
    assert calls[0][0] == '/native/gmake'
    assert calls[0][calls[0].index('-f') + 1] == str(makefile)
    assert calls[0][calls[0].index('-C') + 1] == str(source)


def test_gcc_analyzer_translates_clang_warning_without_dropping_checks(monkeypatch):
    from tools.ci import run_fanalyzer as runner

    flags = '-O2 -Wall -Wextra -Wconditional-uninitialized -Wunknown-negative-probe'
    monkeypatch.setattr(runner, 'read_var', lambda name: flags if name == 'CFLAGS' else '-Iselected-sdk')
    cflags, includes = runner._compiler_flags()
    assert cflags == ['-O2', '-Wall', '-Wextra', '-Wmaybe-uninitialized', '-Wunknown-negative-probe']
    assert includes == ['-Iselected-sdk']


def test_analyzer_compile_failures_cannot_be_counted_as_analyzed():
    from tools.ci import run_fanalyzer as runner

    with pytest.raises(SystemExit) as refused:
        runner._fail_compile_errors(['COMPILE-ERROR: selected-source.c\nunknown option'])
    assert refused.value.code == 2


def test_clang_analyzer_retains_its_native_warning_spelling(monkeypatch):
    from tools.ci import run_codechecker as runner

    monkeypatch.setattr(runner, 'read_var', lambda name:
        '-O2 -Wall -Wconditional-uninitialized' if name == 'CFLAGS' else '-Iselected-sdk')
    cflags, includes = runner._compiler_flags()
    assert '-Wconditional-uninitialized' in cflags.split()
    assert includes == '-Iselected-sdk'


def test_explicit_gcc_analyzer_does_not_replace_the_server_compiler(monkeypatch):
    from tools.ci import run_fanalyzer as runner

    monkeypatch.setenv('CC', '/native/clang')
    monkeypatch.setenv('FANALYZER_CC', '/selected/gcc16')
    calls = []
    import subprocess
    monkeypatch.setattr(runner.subprocess, 'run', lambda command, **kwargs:
        calls.append(command) or subprocess.CompletedProcess(command, 0, stderr=''))
    assert runner.analyze_one('source.c', ['-O2'], ['-Iselected'], None) == ([], None)
    assert calls[0][0] == '/selected/gcc16'
    assert runner.os.environ['CC'] == '/native/clang'


def test_missing_explicit_analyzer_never_borrows_an_installed_gcc(monkeypatch):
    from tools.ci import run_fanalyzer as runner

    monkeypatch.setenv('FANALYZER_CC', '/missing/gcc')
    checked = []
    monkeypatch.setattr(runner.shutil, 'which', lambda compiler: checked.append(compiler))
    with pytest.raises(SystemExit) as refused:
        runner._validate_environment()
    assert refused.value.code == 2
    assert checked == ['/missing/gcc']


def test_empty_analyzer_selection_retains_the_existing_gcc_default(monkeypatch):
    from tools.ci import run_fanalyzer as runner

    monkeypatch.setenv('CC', '/native/clang')
    monkeypatch.setenv('FANALYZER_CC', '')
    assert runner._analyzer_compiler() == 'gcc'


def test_successful_analyzer_warnings_remain_findings_not_compile_errors(monkeypatch):
    from tools.ci import run_fanalyzer as runner
    import subprocess

    warning = 'source.c:1:1: warning: leaked descriptor [-Wanalyzer-fd-leak]\n'
    monkeypatch.setattr(runner.subprocess, 'run', lambda *args, **kwargs:
        subprocess.CompletedProcess(args, 0, stderr=warning))
    assert runner.analyze_one('source.c', [], [], None) == ([warning.strip()], None)


def test_failed_analyzer_compilation_retains_the_compiler_error(monkeypatch):
    from tools.ci import run_fanalyzer as runner
    import subprocess

    message = 'source.c:4:1: fatal error: selected dependency missing\n'
    monkeypatch.setattr(runner.subprocess, 'run', lambda *args, **kwargs:
        subprocess.CompletedProcess(args, 1, stderr=message))
    findings, error = runner.analyze_one('source.c', [], [], None)
    assert findings == []
    assert error == 'COMPILE-ERROR: source.c\n' + message.strip()


def test_analyzer_warning_cannot_mask_a_later_fatal_compile_error(monkeypatch):
    from tools.ci import run_fanalyzer as runner
    import subprocess

    warning = 'source.c:1:1: warning: leaked descriptor [-Wanalyzer-fd-leak]\n'
    fatal = 'source.c:4:1: fatal error: selected dependency missing\n'
    monkeypatch.setattr(runner.subprocess, 'run', lambda *args, **kwargs:
        subprocess.CompletedProcess(args, 1, stderr=warning + fatal))
    findings, error = runner.analyze_one('source.c', [], [], None)
    assert findings == [warning.strip()]
    with pytest.raises(SystemExit) as refused:
        runner._fail_compile_errors([error])
    assert refused.value.code == 2
