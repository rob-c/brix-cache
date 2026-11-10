"""Standalone-test execution must contribute real, isolated gcov counters."""

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from tools.ci.coverage_compiler import install, instrument_arguments


def test_repository_compiles_have_distinct_persistent_counter_directories(tmp_path):
    root, output = tmp_path / "repo", tmp_path / "counters"
    args = ["-O2", "src/worker.c", "-o", str(tmp_path / "unit")]
    first = instrument_arguments(args, root, output, root)
    second = instrument_arguments(args, root, output, root)
    assert first[:len(args)] == args
    assert "--coverage" in first and "-fprofile-abs-path" in first
    assert first[-1] != second[-1]
    assert Path(first[-1]).is_relative_to(output)
    assert Path(first[-1]).is_dir()


@pytest.mark.parametrize("args", [
    ["--version"], ["-dumpmachine"], ["-print-file-name=libgcc.a"],
    ["-E", "src/worker.c"], ["-M", "src/worker.c"],
    ["-S", "src/worker.c"], ["-fsyntax-only", "src/worker.c"],
    ["-###", "worker.o"],
])
def test_nonexecuting_compiler_calls_remain_unchanged(tmp_path, args):
    output = tmp_path / "counters"
    assert instrument_arguments(args, tmp_path, output, tmp_path) == args
    assert not output.exists()


def test_foreign_paths_and_preprocessor_values_do_not_select_repository_coverage(tmp_path):
    root, output = tmp_path / "repo", tmp_path / "counters"
    args = [str(tmp_path / "repo-other" / "probe.c"),
            '-DVALUE="' + str(root) + '"', "-o", str(tmp_path / "probe")]
    assert instrument_arguments(args, root, output, tmp_path) == args
    assert not output.exists()


def test_object_only_links_receive_the_runtime_without_recompiling(tmp_path):
    args = [str(tmp_path / "unit.o"), "-o", str(tmp_path / "unit")]
    selected = instrument_arguments(args, tmp_path / "repo", tmp_path / "counters", tmp_path)
    assert selected == [*args, "--coverage"]
    assert not (tmp_path / "counters").exists()


def _gcc_environment(tmp_path):
    """Use the coverage lane's GCC format; Apple Clang emits different notes."""
    if sys.platform != "linux":
        pytest.skip("GCC/lcov coverage lane runs on Linux")
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("GCC is not installed")
    root, output = tmp_path / "repo", tmp_path / "counters"
    root.mkdir()
    environment = install(root, output, dict(os.environ))
    return root, output, environment


@pytest.mark.parametrize("filename", ["branch.c", "branch ' $(false).c"])
def test_launcher_records_execution_after_the_test_binary_is_removed(tmp_path, filename):
    root, output, environment = _gcc_environment(tmp_path)
    source = root / filename
    source.write_text("int main(int argc, char **argv) {\n"
                      "    (void)argv;\n"
                      "    return argc == 2 ? 0 : 9;\n}\n")
    binary = tmp_path / "program"
    built = subprocess.run(["gcc", str(source), "-o", str(binary)], env=environment,
                           capture_output=True, text=True)
    assert built.returncode == 0, built.stderr
    assert subprocess.run([str(binary), "success"]).returncode == 0
    assert subprocess.run([str(binary)]).returncode == 9
    binary.unlink()
    assert list(output.glob("compile-*/*.gcno"))
    counters = list(output.glob("compile-*/*.gcda"))
    assert counters and all(path.stat().st_size > 0 for path in counters)


def test_launcher_preserves_compile_errors_and_never_records_execution(tmp_path):
    root, output, environment = _gcc_environment(tmp_path)
    source = root / "broken.c"
    source.write_text("#error intentional compile failure\n")
    binary = tmp_path / "program"
    built = subprocess.run(["gcc", str(source), "-o", str(binary)], env=environment,
                           capture_output=True, text=True)
    assert built.returncode != 0
    assert "intentional compile failure" in built.stderr
    assert not binary.exists()
    assert not list(output.rglob("*.gcda"))


def test_launcher_preserves_requested_optimization_and_fortify(tmp_path):
    root, output, environment = _gcc_environment(tmp_path)
    source = root / "fortified.c"
    source.write_text('#include <string.h>\nint main(void) {\n'
                      '    char text[4]; memcpy(text, "abc", 4);\n'
                      '    return strcmp(text, "abc");\n}\n')
    binary = tmp_path / "fortified"
    built = subprocess.run(["gcc", "-O2", "-D_FORTIFY_SOURCE=2", "-Werror",
                            str(source), "-o", str(binary)], env=environment,
                           capture_output=True, text=True)
    assert built.returncode == 0, built.stderr
    assert subprocess.run([str(binary)]).returncode == 0
    assert list(output.rglob("*.gcda"))


def test_coverage_environment_clears_inherited_counter_redirection(tmp_path):
    original = {"PATH": os.defpath, "GCOV_PREFIX": "/foreign/counters",
                "GCOV_PREFIX_STRIP": "99"}
    selected = install(tmp_path / "repo", tmp_path / "counters", original)
    assert selected["BRIX_COVERAGE_COUNTERS"] == str(tmp_path / "counters")
    assert selected["GCOV_PREFIX"] == "" and selected["GCOV_PREFIX_STRIP"] == "0"
    assert original["GCOV_PREFIX"] == "/foreign/counters"


def test_ordinary_regression_units_cannot_overwrite_production_profiles(tmp_path, monkeypatch):
    from cmdscripts.c_regression_units import _unit_runtime_environment

    monkeypatch.delenv("BRIX_COVERAGE_COUNTERS", raising=False)
    environment = _unit_runtime_environment(tmp_path / "unit")
    assert environment["GCOV_PREFIX"] == str(tmp_path)
    assert environment["GCOV_PREFIX_STRIP"] == "99"


def test_nested_collector_replaces_only_its_parents_launchers(tmp_path):
    parent = install(tmp_path / "repo", tmp_path / "parent", {"PATH": os.defpath})
    child = install(tmp_path / "repo", tmp_path / "child", parent)
    assert child["PATH"].split(os.pathsep) == [str(tmp_path / "child/bin"),
                                              *os.defpath.split(os.pathsep)]
    assert parent["BRIX_COVERAGE_COUNTERS"] == str(tmp_path / "parent")



@pytest.mark.parametrize("exit_code", [0, 7])
def test_regression_runner_retains_real_counters_and_exit_status(tmp_path, monkeypatch, exit_code):
    from cmdscripts.c_regression_units import _compile_and_run

    root, output, environment = _gcc_environment(tmp_path)
    source = root / "unit.c"
    source.write_text(f"int main(void) {{ return {exit_code}; }}\n")
    binary = tmp_path / "disposable" / "unit"
    binary.parent.mkdir()
    for key in ("PATH", "BRIX_COVERAGE_COUNTERS", "GCOV_PREFIX", "GCOV_PREFIX_STRIP"):
        monkeypatch.setenv(key, environment[key])
    monkeypatch.setenv("CC", "gcc")
    success, message = _compile_and_run(binary, [str(source)])
    assert success == (exit_code == 0), message
    assert f"exited {exit_code}" in message
    shutil.rmtree(binary.parent)
    assert list(output.rglob("*.gcno"))
    assert list(output.rglob("*.gcda"))
