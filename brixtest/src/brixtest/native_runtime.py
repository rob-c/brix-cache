"""Runtime compiler and output-check machinery for declarative native tests."""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import shutil
from pathlib import Path
from typing import Mapping, Sequence

import pytest

from brixtest.native import OutputExpectation, _expectation, _NativeSpec

_CXX_SUFFIXES = frozenset({".cc", ".cpp", ".cxx", ".c++", ".cp", ".C"})
_INSTRUMENTATION = (
    ("__asan_", "-fsanitize=address"),
    ("__ubsan", "-fsanitize=undefined"),
    ("__tsan_", "-fsanitize=thread"),
    ("__gcov_", "--coverage"),
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _cwd(run, spec: _NativeSpec) -> Path:
    root = Path(run._manager.source_root)
    selected = Path(_render(run, spec.cwd or ".", "native_test.cwd"))
    return (selected if selected.is_absolute() else root / selected).resolve()


def _render(run, value: object, label: str) -> str:
    return run._manager._render_value(value, label=label)


def _path(run, value: object, cwd: Path, label: str) -> Path:
    selected = Path(_render(run, value, label))
    return (selected if selected.is_absolute() else cwd / selected).resolve()


def _language(spec: _NativeSpec, sources: Sequence[Path] = ()) -> str:
    if spec.language != "auto":
        return spec.language
    selected = sources or tuple(Path(str(value)) for value in spec.sources)
    return "c++" if any(path.suffix in _CXX_SUFFIXES for path in selected) else "c"


def _compiler_candidates(language: str) -> tuple[str, ...]:
    return ("c++", "g++", "clang++") if language == "c++" else ("cc", "gcc", "clang")


def _environment_compiler(language: str) -> tuple[str, ...]:
    value = os.environ.get("CXX" if language == "c++" else "CC", "")
    return tuple(shlex.split(value)) if value else ()


def _available_compiler(run, spec: _NativeSpec, language: str) -> tuple[str, ...]:
    selected = tuple(spec.compiler or ()) or _environment_compiler(language)
    if selected:
        rendered = tuple(
            _render(run, part, "native_test.compiler") for part in selected
        )
        return rendered if shutil.which(rendered[0]) else ()
    return _first_compiler(_compiler_candidates(language))


def _first_compiler(candidates: Sequence[str]) -> tuple[str, ...]:
    for name in candidates:
        found = shutil.which(name)
        if found:
            return (found,)
    return ()


def _unavailable(spec: _NativeSpec, detail: str) -> None:
    if spec.missing == "skip":
        pytest.skip(detail)
    raise AssertionError(detail)


def _required_sources(run, spec: _NativeSpec, cwd: Path) -> tuple[Path, ...]:
    sources = tuple(
        _path(run, value, cwd, "native_test.sources") for value in spec.sources
    )
    missing_sources = [str(path) for path in sources if not path.is_file()]
    if missing_sources:
        raise AssertionError("native test sources are missing: %s" % ", ".join(missing_sources))
    return sources


def _required_objects(run, spec: _NativeSpec, cwd: Path) -> tuple[Path, ...]:
    objects = tuple(
        _path(run, value, cwd, "native_test.objects") for value in spec.objects
    )
    required = tuple(
        _path(run, value, cwd, "native_test.required_files")
        for value in spec.required_files
    )
    missing = _missing_regular_files(objects) + _missing_paths(required)
    if missing:
        _unavailable(spec, "native test prerequisites are missing: %s" % ", ".join(missing))
    return objects


def _missing_regular_files(paths: Sequence[Path]) -> list[str]:
    return [str(path) for path in paths if not path.is_file()]


def _missing_paths(paths: Sequence[Path]) -> list[str]:
    return [str(path) for path in paths if not path.exists()]


def _require_commands(spec: _NativeSpec) -> None:
    commands = [name for name in spec.required_commands if shutil.which(name) is None]
    if commands:
        _unavailable(spec, "native test commands are unavailable: %s" % ", ".join(commands))


def _require_inputs(
    run, spec: _NativeSpec, cwd: Path,
) -> tuple[tuple[Path, ...], tuple[Path, ...], tuple[Path, ...]]:
    sources = _required_sources(run, spec, cwd)
    objects = _required_objects(run, spec, cwd)
    includes = tuple(
        _path(run, value, cwd, "native_test.include_dirs")
        for value in spec.include_dirs
    )
    _require_commands(spec)
    return sources, objects, includes


def _pkg_flags(run, spec: _NativeSpec, cwd: Path, mode: str) -> tuple[str, ...]:
    if not spec.pkg_config:
        return ()
    if shutil.which("pkg-config") is None:
        _unavailable(spec, "pkg-config is unavailable")
    result = run.command(
        "pkg-config", mode, *spec.pkg_config, check=False,
        cwd=cwd, timeout=min(spec.compile_timeout, 30.0),
        env=spec.compile_env, output_limit=spec.output_limit,
    )
    if result.returncode != 0:
        _unavailable(
            spec, "pkg-config %s failed for %s:\n%s" % (
                mode, ", ".join(spec.pkg_config), _result_output(result),
            ),
        )
    return tuple(shlex.split(result.stdout))


def _define_flags(values: Mapping[str, object]) -> tuple[str, ...]:
    return tuple(
        "-D%s" % name if value is None else "-D%s=%s" % (
            name, int(value) if isinstance(value, bool) else value,
        )
        for name, value in values.items()
    )


def _instrumentation_flags(
    run, spec: _NativeSpec, objects: Sequence[Path], cwd: Path,
) -> tuple[str, ...]:
    symbols = _instrumentation_symbols(run, spec, objects, cwd)
    return tuple(flag for symbol, flag in _INSTRUMENTATION if symbol in symbols)


def _instrumentation_symbols(run, spec, objects, cwd) -> str:
    if not spec.inherit_instrumentation:
        return ""
    if not objects:
        return ""
    if shutil.which("nm") is None:
        return ""
    result = run.command(
        "nm", *objects, check=False, cwd=cwd, timeout=min(spec.compile_timeout, 30.0),
        env=spec.compile_env, output_limit=spec.output_limit,
    )
    if result.returncode != 0:
        return ""
    return result.stdout + result.stderr


def _build_argv(
    compiler: Sequence[str], spec: _NativeSpec, sources: Sequence[Path],
    objects: Sequence[Path], output: Path, cflags: Sequence[str],
    libs: Sequence[str], instrumentation: Sequence[str], includes: Sequence[Path],
) -> tuple[object, ...]:
    standard = ("-std=%s" % spec.standard,) if spec.standard else ()
    include_flags = tuple(part for path in includes for part in ("-I", str(path)))
    libraries = tuple("-l%s" % name for name in spec.libraries)
    return (
        *compiler, *standard, *spec.compile_args, *include_flags,
        *_define_flags(spec.defines), *cflags, *map(str, sources), *map(str, objects),
        "-o", str(output), *spec.link_args, *libs, *libraries, *instrumentation,
    )


def _result_output(result) -> str:
    return "stdout:\n%s\nstderr:\n%s" % (result.stdout, result.stderr)


def _compile(run, spec: _NativeSpec, cwd: Path, output: Path):
    sources, objects, includes = _require_inputs(run, spec, cwd)
    language = _language(spec, sources)
    compiler = _available_compiler(run, spec, language)
    if not compiler:
        _unavailable(spec, "no %s compiler is available" % language)
    cflags = _pkg_flags(run, spec, cwd, "--cflags")
    libs = _pkg_flags(run, spec, cwd, "--libs")
    inherited = _instrumentation_flags(run, spec, objects, cwd)
    argv = _build_argv(
        compiler, spec, sources, objects, output, cflags, libs, inherited, includes,
    )
    result = run.command(
        *argv, check=False, cwd=cwd, env=spec.compile_env,
        timeout=spec.compile_timeout, output_limit=spec.output_limit,
    )
    return result, sources, objects, inherited


def _selected_text(value: str, strip: bool) -> str:
    return value.strip() if strip else value


def _exact_error(value: str, expectation: OutputExpectation) -> str:
    if expectation.exact is None or value == expectation.exact:
        return ""
    return "expected exact %r" % expectation.exact


def _missing_substrings(value: str, expected: Sequence[str]) -> list[str]:
    return ["missing substring %r" % item for item in expected if item not in value]


def _forbidden_substrings(value: str, excluded: Sequence[str]) -> list[str]:
    return ["forbidden substring %r" % item for item in excluded if item in value]


def _missing_patterns(value: str, patterns: Sequence[str]) -> list[str]:
    return [
        "regular expression %r did not match" % item
        for item in patterns if re.search(item, value) is None
    ]


def _checked_text(value: str, expectation: OutputExpectation, stream: str) -> None:
    selected = _selected_text(value, expectation.strip)
    errors = []
    exact = _exact_error(selected, expectation)
    if exact:
        errors.append(exact)
    errors.extend(_missing_substrings(selected, expectation.contains))
    errors.extend(_forbidden_substrings(selected, expectation.excludes))
    errors.extend(_missing_patterns(selected, expectation.regex))
    if errors:
        raise AssertionError(
            "native %s check failed: %s\n--- captured %s ---\n%s" % (
                stream, "; ".join(errors), stream, value,
            )
        )


def _check_output(value: str, expectation, stream: str) -> None:
    selected = _expectation(expectation, "native_test.%s" % stream)
    if selected is not None:
        _checked_text(value, selected, stream)


def _run(run, spec: _NativeSpec, binary: Path, cwd: Path):
    result = run.command(
        binary, *spec.args, check=False, cwd=cwd, input=spec.input, env=spec.env,
        timeout=spec.timeout, expected_exit_codes=tuple(spec.expected_exit_codes),
        output_limit=spec.output_limit,
    )
    return result


def _check_run(spec: _NativeSpec, result) -> None:
    if result.returncode not in spec.expected_exit_codes:
        raise AssertionError(
            "native test %s exited %d; expected %s\n%s" % (
                spec.name, result.returncode, tuple(spec.expected_exit_codes),
                _result_output(result),
            )
        )
    _check_output(result.stdout, spec.stdout, "stdout")
    _check_output(result.stderr, spec.stderr, "stderr")


def _manifest(spec, compiler_result, run_result, sources, objects, inherited, binary):
    binary_record = None
    if binary.is_file():
        binary_record = {
            "path": str(binary), "size": binary.stat().st_size,
            "sha256": _sha256(binary),
        }
    return {
        "schema": 1, "name": spec.name,
        "language": _language(spec, sources), "compile_argv": list(compiler_result.argv),
        "compile_returncode": compiler_result.returncode,
        "compile_seconds": compiler_result.elapsed_seconds,
        "run_argv": list(run_result.argv) if run_result is not None else [],
        "run_returncode": run_result.returncode if run_result is not None else None,
        "run_seconds": run_result.elapsed_seconds if run_result is not None else None,
        "sources": [{"path": str(path), "sha256": _sha256(path)} for path in sources],
        "objects": [{"path": str(path), "sha256": _sha256(path)} for path in objects],
        "binary": binary_record,
        "inherited_instrumentation": list(inherited),
    }


def execute_native(run, spec: _NativeSpec) -> None:
    """Compile, optionally execute, verify, measure, and archive one native test."""
    cwd = _cwd(run, spec)
    if not cwd.is_dir():
        raise AssertionError("native test working directory does not exist: %s" % cwd)
    work = Path(run.workspace) / "native" / spec.name
    work.mkdir(parents=True, exist_ok=False)
    binary = work / "test-program"
    compiled, sources, objects, inherited = _compile(run, spec, cwd, binary)
    run.metrics.observe("native.compile.duration", compiled.elapsed_seconds, unit="s")
    if compiled.returncode != 0:
        run.attach_json(
            "native-%s-build" % spec.name,
            _manifest(spec, compiled, None, sources, objects, inherited, binary),
            description="Failed native compiler and input provenance",
        )
        raise AssertionError(
            "native test %s failed to compile (exit %d)\ncommand: %s\n%s" % (
                spec.name, compiled.returncode, shlex.join(compiled.argv),
                _result_output(compiled),
            )
        )
    result = _run(run, spec, binary, cwd) if spec.execute else None
    if result is not None:
        run.metrics.observe("native.run.duration", result.elapsed_seconds, unit="s")
    run.metrics.gauge("native.binary.bytes", binary.stat().st_size, unit="bytes")
    run.attach(binary, name="native-%s-binary" % spec.name, media_type="application/x-executable")
    run.attach_json(
        "native-%s-build" % spec.name,
        _manifest(spec, compiled, result, sources, objects, inherited, binary),
        description="Native compiler, source, object, binary, and execution provenance",
    )
    if result is not None:
        _check_run(spec, result)


__all__ = ["execute_native"]
