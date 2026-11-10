"""Standalone units must link the runtime owned by their real input objects."""
import os
import shutil
import subprocess

import pytest

from cmdscripts.compile_run import compile_binary, sanitizer_link_flags


def _object(tmp_path, flags=()):
    compiler = shutil.which(os.environ.get("CC", "cc"))
    if compiler is None:
        pytest.skip("native compiler unavailable")
    source = tmp_path / "fixture.c"
    source.write_text('const char marker[] = "__gcov_init";\n'
                      'int fixture_value(void) { return 7; }\n')
    obj = source.with_suffix(".o")
    subprocess.run([compiler, *flags, "-c", str(source), "-o", str(obj)],
                   check=True, capture_output=True, text=True)
    return obj


@pytest.mark.parametrize("archive", [False, True], ids=["object", "archive"])
def test_coverage_input_links_and_records_execution(tmp_path, archive):
    obj = _object(tmp_path, ["--coverage"])
    linked = obj
    if archive:
        linked = tmp_path / "fixture.a"
        subprocess.run(["ar", "rcs", str(linked), str(obj)], check=True)
    main = tmp_path / "main.c"
    main.write_text('int fixture_value(void);\n'
                    'int main(void) { return fixture_value() != 7; }\n')
    binary = tmp_path / "check"
    built = compile_binary(binary, [str(main), str(linked)])
    assert built.returncode == 0, built.stderr
    subprocess.run([str(binary)], check=True, timeout=10)
    assert obj.with_suffix(".gcda").stat().st_size > 0


def test_plain_object_data_does_not_select_an_instrumentation_runtime(tmp_path):
    obj = _object(tmp_path)
    assert sanitizer_link_flags([str(obj)]) == []


def test_missing_object_remains_a_build_error(tmp_path):
    missing = tmp_path / "missing.o"
    built = compile_binary(tmp_path / "check", [str(missing)])
    assert built.returncode != 0
    assert not (tmp_path / "check").exists()
