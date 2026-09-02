"""First-class collection, compilation, checks, and provenance for native tests."""

from __future__ import annotations

import dataclasses
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from brixtest import OutputExpectation, SpecError, expect_output, get_case, native_test
from brixtest.helper_bundle import build_helper_bundle
from brixtest.native import _NativeSpec, native_input_paths
from brixtest.native_runtime import (
    _build_argv,
    _checked_text,
    _instrumentation_flags,
    _language,
)


def _nested_pytest(tmp_path: Path, source: str, *extra: str):
    test_file = tmp_path / "test_native_generated.py"
    test_file.write_text(source)
    package = Path(__file__).resolve().parents[1] / "src"
    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith("BRIXTEST_")
    }
    environment.update({
        "PYTHONPATH": str(package),
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONPYCACHEPREFIX": str(tmp_path / "pycache"),
        "BRIXTEST_RUNS": str(tmp_path / "runs"),
    })
    return subprocess.run(
        [
            sys.executable, "-m", "pytest", str(test_file),
            "-p", "brixtest.pytest_plugin", "-q", *extra,
        ],
        cwd=tmp_path, env=environment, capture_output=True, text=True,
        timeout=90, check=False,
    )


def _write(tmp_path: Path, name: str, source: str) -> Path:
    path = tmp_path / "c" / name
    path.parent.mkdir(exist_ok=True)
    path.write_text(source)
    return path


def _compiler(language: str = "c") -> str | None:
    names = ("c++", "g++", "clang++") if language == "c++" else ("cc", "gcc", "clang")
    return next((value for name in names if (value := shutil.which(name))), None)


def _loopback_available() -> bool:
    try:
        handle = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return False
    handle.close()
    return True


def _tree_text(root: Path, pattern: str) -> str:
    return "\n".join(path.read_text() for path in root.rglob(pattern))


def test_output_expectation_is_immutable_and_composable():
    check = expect_output(
        "success", excludes=("FAIL",), regex=(r"[0-9]+ checks",),
        exact=None, strip=True,
    )
    assert check == OutputExpectation(
        ("success",), ("FAIL",), (r"[0-9]+ checks",), None, True,
    )
    assert isinstance(hash(check), int)
    with pytest.raises(dataclasses.FrozenInstanceError):
        check.strip = False


@pytest.mark.parametrize("operation,field", [
    (lambda: native_test("Bad", sources=("x.c",)), "native_test.name"),
    (lambda: native_test("bad", sources="x.c"), "native_test.sources"),
    (lambda: native_test("bad", sources=("x.c",), language="rust"), "native_test.language"),
    (lambda: native_test("bad", sources=("x.c",), standard="-std=c11"), "native_test.standard"),
    (lambda: native_test("bad", sources=("x.c",), args="one"), "native_test.args"),
    (lambda: native_test("bad", sources=("x.c",), resources="server"), "native_test.resources"),
    (lambda: native_test("bad", sources=("x.c",), output_limit=1), "native_test.output_limit"),
    (lambda: native_test("bad", sources=("x.c",), missing="ignore"), "native_test.missing"),
    (
        lambda: native_test("bad", sources=("x.c",), execute=False, stdout="PASS"),
        "native_test output",
    ),
    (lambda: expect_output(regex=("[",)), "output.regex"),
])
def test_native_author_errors_are_structured(operation, field):
    with pytest.raises(SpecError) as error:
        operation()
    assert error.value.field == field


def test_factory_returns_a_normal_managed_function_with_declaring_source(tmp_path):
    source = tmp_path / "unit.c"
    source.write_text("int main(void) { return 0; }\n")
    generated = native_test(
        "unit", sources=(source,), stdout=expect_output(exact=""),
        observe=[], keep="never",
    )
    definition = get_case(generated)
    assert generated.__name__ == "test_unit" and callable(generated)
    assert definition.source == Path(__file__).resolve()
    assert native_input_paths(generated) == (source.resolve(),)


def test_language_and_build_argv_cover_cxx_defines_objects_and_libraries(tmp_path):
    spec = _NativeSpec(
        "link", ("main.cc",), standard="c++17", include_dirs=("include",),
        defines={"FEATURE": 1, "FLAG": None}, objects=("built.o",),
        libraries=("crypto",), compile_args=("-O2",), link_args=("-pthread",),
    )
    argv = _build_argv(
        ("g++",), spec, (tmp_path / "main.cc",), (tmp_path / "built.o",),
        tmp_path / "program", ("-Ithird",), ("-lssl",),
        ("-fsanitize=address",), tmp_path,
    )
    assert _language(spec) == "c++"
    assert argv[:3] == ("g++", "-std=c++17", "-O2")
    assert ("-DFEATURE=1", "-DFLAG") == (argv[5], argv[6])
    assert argv[-4:] == ("-pthread", "-lssl", "-lcrypto", "-fsanitize=address")


def test_output_checks_report_each_supported_mismatch():
    check = expect_output(
        "wanted", excludes=("forbidden",), regex=(r"count=[0-9]+",),
        exact="wanted count=2", strip=True,
    )
    _checked_text(" wanted count=2 \n", check, "stdout")
    with pytest.raises(AssertionError) as error:
        _checked_text("forbidden count=nope", check, "stdout")
    detail = str(error.value)
    assert "expected exact" in detail and "missing substring" in detail
    assert "forbidden substring" in detail and "regular expression" in detail
    assert "captured stdout" in detail


def test_object_instrumentation_flags_are_inherited_once(tmp_path, monkeypatch):
    linked = tmp_path / "linked.o"
    linked.write_bytes(b"object")
    result = SimpleNamespace(
        returncode=0, stdout="__asan_report __ubsan_handle __gcov_init __asan_report",
        stderr="",
    )
    run = SimpleNamespace(command=lambda *args, **kwargs: result)
    monkeypatch.setattr("brixtest.native_runtime.shutil.which", lambda name: "/usr/bin/" + name)
    spec = _NativeSpec("instrumented", ("main.c",), objects=(linked,))
    assert _instrumentation_flags(run, spec, (linked,), tmp_path) == (
        "-fsanitize=address", "-fsanitize=undefined", "--coverage",
    )


def test_kubernetes_bundle_includes_explicit_native_build_inputs(tmp_path, monkeypatch):
    project = tmp_path / "project"
    tests = project / "tests"
    objects = project / "objs"
    tests.mkdir(parents=True)
    objects.mkdir()
    test_file = tests / "test_native.py"
    test_file.write_text("def test_native(): pass\n")
    linked = objects / "linked.o"
    linked.write_bytes(b"native-object")
    package_file = Path(__file__).resolve().parents[1] / "src" / "brixtest" / "__init__.py"
    monkeypatch.setattr(
        "brixtest.helper_bundle._runtime_files",
        lambda modules: {"opt/brixtest/python/brixtest/__init__.py": package_file},
    )
    monkeypatch.setattr("brixtest.helper_bundle._runtime_tools", lambda: {})
    bundle = build_helper_bundle(
        project, "tests/test_native.py::test_native", tmp_path / "out",
        project_inputs=(linked,),
    )
    import zipfile

    with zipfile.ZipFile(bundle.path) as archive:
        assert archive.read("workspace/objs/linked.o") == b"native-object"


def test_kubernetes_bundle_rejects_native_inputs_outside_pytest_root(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    test_file = project / "test_native.py"
    test_file.write_text("def test_native(): pass\n")
    external = tmp_path / "external.c"
    external.write_text("int main(void) { return 0; }\n")
    monkeypatch.setattr("brixtest.helper_bundle._runtime_files", lambda modules: {})
    monkeypatch.setattr("brixtest.helper_bundle._runtime_tools", lambda: {})
    with pytest.raises(SpecError, match="native helper input"):
        build_helper_bundle(
            project, "test_native.py::test_native", tmp_path / "out",
            project_inputs=(external,),
        )


@pytest.mark.skipif(_compiler() is None, reason="C compiler unavailable")
def test_two_native_declarations_are_independent_pytest_items(tmp_path):
    _write(
        tmp_path, "first.c",
        "#include <stdio.h>\nint main(void){puts(\"FIRST PASS\");return 0;}\n",
    )
    _write(
        tmp_path, "second.c",
        "#include <stdio.h>\nint main(void){fputs(\"expected error\\n\",stderr);return 7;}\n",
    )
    result = _nested_pytest(tmp_path, """
from brixtest import expect_output, native_test

test_first = native_test(
    "first", sources=("c/first.c",), stdout="FIRST PASS",
    observe=[], keep="always",
)
test_second = native_test(
    "second", sources=("c/second.c",), expected_exit_codes=(7,),
    stderr=expect_output("expected error", excludes=("segmentation fault",)),
    observe=[], keep="always",
)
""")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "2 passed" in result.stdout
    archived = _tree_text(tmp_path / "runs", "*.stdout.log")
    assert "FIRST PASS" in archived
    journals = _tree_text(tmp_path / "runs", "journal.jsonl")
    assert "native-first-build" in journals and "native-second-build" in journals
    assert "native.compile.duration" in journals and "native.run.duration" in journals


def test_native_items_collect_without_compiling_or_batching(tmp_path):
    result = _nested_pytest(tmp_path, """
from brixtest import native_test

test_alpha = native_test("alpha", sources=("missing-a.c",), observe=[])
test_beta = native_test("beta", sources=("missing-b.c",), observe=[])
""", "--collect-only")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "test_native_generated.py::test_alpha" in result.stdout
    assert "test_native_generated.py::test_beta" in result.stdout
    assert "2 tests collected" in result.stdout


@pytest.mark.skipif(_compiler() is None, reason="C compiler unavailable")
def test_native_runtime_supports_args_env_stdin_and_checked_stderr(tmp_path):
    _write(tmp_path, "inputs.c", r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char input[32] = {0};
    const char *mode = getenv("NATIVE_MODE");
    if (argc != 2 || !mode || !fgets(input, sizeof(input), stdin)) return 3;
    printf("arg=%s env=%s input=%s", argv[1], mode, input);
    fputs("checked stderr\n", stderr);
    return strcmp(argv[1], "value") == 0 ? 0 : 4;
}
''')
    result = _nested_pytest(tmp_path, """
from brixtest import expect_output, native_test

test_inputs = native_test(
    "inputs", sources=("c/inputs.c",), args=("value",),
    env={"NATIVE_MODE": "active"}, input="payload\\n",
    stdout=expect_output("arg=value", "env=active", "input=payload"),
    stderr=expect_output(exact="checked stderr", strip=True),
    observe=[], keep="never",
)
""")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 passed" in result.stdout


@pytest.mark.skipif(_compiler() is None, reason="C compiler unavailable")
def test_native_declaration_retains_pytest_parametrization(tmp_path):
    _write(tmp_path, "parameter.c", r'''
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    printf("mode=%s PASS\n", argv[1]);
    return strcmp(argv[1], "read") == 0 || strcmp(argv[1], "write") == 0 ? 0 : 3;
}
''')
    result = _nested_pytest(tmp_path, """
import pytest
from brixtest import native_test, param

test_modes = native_test(
    "modes", sources=("c/parameter.c",), args=(param("mode"),),
    stdout="PASS", observe=(), keep="never",
)
test_modes = pytest.mark.parametrize("mode", ("read", "write"))(test_modes)
""")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "2 passed" in result.stdout


@pytest.mark.skipif(_compiler("c++") is None, reason="C++ compiler unavailable")
def test_native_runtime_auto_selects_cpp(tmp_path):
    _write(tmp_path, "hello.cc", "#include <iostream>\nint main(){std::cout << \"CXX PASS\\n\";}\n")
    result = _nested_pytest(tmp_path, """
from brixtest import native_test
test_cpp = native_test(
    "cpp", sources=("c/hello.cc",), standard="c++17",
    stdout="CXX PASS", observe=[], keep="never",
)
""")
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(
    _compiler() is None or not _loopback_available(),
    reason="C compiler or loopback sockets unavailable",
)
def test_native_program_consumes_a_managed_server_reference(tmp_path):
    _write(tmp_path, "http.c", r'''
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int handle;
    struct sockaddr_in address;
    char response[4096];
    ssize_t received;
    const char request[] = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
    if (argc != 3) return 2;
    handle = socket(AF_INET, SOCK_STREAM, 0);
    if (handle < 0) return 3;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)atoi(argv[2]));
    if (inet_pton(AF_INET, argv[1], &address.sin_addr) != 1) return 4;
    if (connect(handle, (struct sockaddr *)&address, sizeof(address)) != 0) return 5;
    if (send(handle, request, sizeof(request) - 1, 0) < 0) return 6;
    received = recv(handle, response, sizeof(response) - 1, 0);
    close(handle);
    if (received <= 0) return 7;
    response[received] = '\0';
    if (strstr(response, "200 OK") == NULL) return 8;
    puts("managed HTTP server PASS");
    return 0;
}
''')
    result = _nested_pytest(tmp_path, """
import sys
from brixtest import native_test, server

origin = server(
    "origin",
    command=(sys.executable, "-u", "-m", "http.server", "{port}",
             "--bind", "127.0.0.1"),
)
test_http = native_test(
    "http", sources=("c/http.c",), resources=(origin,),
    args=(origin.host, origin.port()), stdout="managed HTTP server PASS",
    observe=(), keep="never",
)
""")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 passed" in result.stdout


@pytest.mark.skipif(_compiler() is None, reason="C compiler unavailable")
@pytest.mark.parametrize("kind,source,expected", [
    ("compile", "int main(void) { this is invalid; }", "failed to compile"),
    (
        "output", "#include <stdio.h>\nint main(void){puts(\"actual\");return 0;}",
        "missing substring",
    ),
])
def test_native_failures_have_direct_phase_diagnostics(tmp_path, kind, source, expected):
    _write(tmp_path, "failure.c", source + "\n")
    result = _nested_pytest(tmp_path, """
from brixtest import native_test
test_failure = native_test(
    "failure", sources=("c/failure.c",), stdout="wanted",
    observe=[], keep="always",
)
""")
    assert result.returncode != 0
    combined = result.stdout + result.stderr
    assert expected in combined and "test_failure" in combined
    if kind == "compile":
        journals = "\n".join(
            path.read_text() for path in (tmp_path / "runs").rglob("journal.jsonl")
        )
        assert "Failed native compiler and input provenance" in journals


def test_missing_native_prerequisite_is_a_normal_pytest_skip(tmp_path):
    _write(tmp_path, "valid.c", "int main(void){return 0;}\n")
    result = _nested_pytest(tmp_path, """
from brixtest import native_test
test_missing = native_test(
    "missing", sources=("c/valid.c",),
    required_files=("definitely-not-present.o",), observe=[], keep="never",
)
""")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 skipped" in result.stdout


def test_native_only_modules_receive_the_managed_module_safety_policy(tmp_path):
    _write(tmp_path, "valid.c", "int main(void){return 0;}\n")
    result = _nested_pytest(tmp_path, """
import subprocess
from brixtest import native_test

subprocess.run(["true"])
test_native = native_test("safe", sources=("c/valid.c",), observe=[])
""", "--collect-only")
    assert result.returncode != 0
    assert "module-level call subprocess.run()" in result.stdout + result.stderr
