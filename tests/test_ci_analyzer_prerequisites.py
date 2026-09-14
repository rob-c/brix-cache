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
    assert guards._analyzer_makefile() == Path("/tmp/nginx-1.28.3/objs/Makefile")
