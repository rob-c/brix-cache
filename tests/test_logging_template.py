"""Shared diagnostic contracts: success, errors and hostile input boundaries."""
import io
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def native_logger(tmp_path_factory):
    binary = tmp_path_factory.mktemp("logging") / "logging-test"
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-I", str(ROOT), str(ROOT / "tests/c/logging_template_test.c"),
                    "-o", str(binary)], check=True, capture_output=True, text=True)
    return binary


def native_record(binary, mode):
    result = subprocess.run([str(binary), mode], check=True,
                            capture_output=True, text=True)
    assert result.stdout == ""
    return result.stderr


def test_native_success(native_logger):
    record = native_record(native_logger, "success")
    assert 'level=INFO service=brix role=client' in record
    assert 'event="main" message="download completed bytes=42" truncated=0' in record


def test_native_error_preserves_errno(native_logger):
    record = native_record(native_logger, "error")
    assert 'level=ERROR service=brix role=tool' in record
    assert 'message="open failed:' in record


def test_native_hostile_input_cannot_forge_record(native_logger):
    record = native_record(native_logger, "hostile")
    assert len(record.splitlines()) == 1
    assert '\\x0d\\x0a' in record and '\\x22\\x5c\\x1b' in record
    assert '\x1b' not in record


def test_native_truncation_remains_complete(native_logger):
    record = native_record(native_logger, "long")
    assert record.endswith('" truncated=1\n')
    assert len(record.splitlines()) == 1


def test_native_escape_limits_and_source(native_logger):
    assert native_record(native_logger, "escape") == ""


def tool_logger():
    # conftest prioritises tests/tools; load the repository module explicitly.
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "brix_logging_support", ROOT / "tools/logging_support.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.diagnostic


@pytest.mark.parametrize("level", ["DEBUG", "INFO", "WARN", "ERROR", "CRIT", "FATAL"])
def test_python_levels_and_output_stream(level):
    stream = io.StringIO()
    tool_logger()(level, "tools/check.py", "main", "ready", file=stream)
    assert f"level={level} service=brix role=tool" in stream.getvalue()
    assert 'message="ready" truncated=0' in stream.getvalue()


def test_python_hostile_fields_and_truncation():
    stream = io.StringIO()
    tool_logger()("ERROR", 'src\n"', "event\r", '\n\x1b"' + "x" * 2048,
                  file=stream)
    record = stream.getvalue()
    assert len(record.splitlines()) == 1
    assert '\\n' in record and '\\u001b' in record
    assert record.endswith("truncated=1\n")


def test_python_rejects_invalid_severity():
    stream = io.StringIO()
    with pytest.raises(ValueError):
        tool_logger()("INFO\nforged", "source", "event", "message", file=stream)
    assert stream.getvalue() == ""


def test_logging_guard_accepts_repository():
    result = subprocess.run(["python3", str(ROOT / "tools/ci/check_logging_template.py")],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_server_filter_preserves_lazy_arguments():
    body = (ROOT / "src/core/compat/log_event.h").read_text()
    macro = body.split("#define BRIX_LOG(level", 1)[1].split("#define BRIX_CONF_LOG", 1)[0]
    assert macro.index("log_level >= (level)") < macro.index("__VA_ARGS__")
    assert "#if (NGX_DEBUG)" in body
    assert "#define BRIX_LOG_DEBUG(category, log, error, ...) do { } while (0)" in body
