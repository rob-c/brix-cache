"""Declarative, independently collected C and C++ pytest cases."""

from __future__ import annotations

import dataclasses
import inspect
import re
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence, Union

from brixtest._design_cases import case, get_case
from brixtest._design_inputs import Binary, _name, _string_mapping
from brixtest.errors import SpecError
from brixtest.evidence.collectors import CollectorSpec
from brixtest.isolation import Isolation
from brixtest.resources import Reference
from brixtest.util.immutable import freeze_mapping

_LANGUAGES = ("auto", "c", "c++")
_MISSING_POLICIES = ("skip", "fail")
_DEFINE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_STANDARD = re.compile(r"^[A-Za-z0-9+_.-]+$")

PathValue = Union[str, Path, Reference]
BuildArg = Union[str, Path, Reference]
CompilerPart = Union[str, Path, Reference, Binary]
CompilerValue = Optional[Union[CompilerPart, Sequence[CompilerPart]]]
OutputValue = Optional[Union[str, "OutputExpectation"]]


def _sequence(value: object, field: str) -> tuple:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise SpecError(field, value, "must be a sequence")
    return tuple(value)


def _text_item(value: object, field: str, *, paths: bool) -> None:
    expected, label = _text_contract(paths)
    if not isinstance(value, expected):
        raise SpecError(field, value, "must contain %s" % label)
    _text_content(value, field, label)


def _text_contract(paths: bool) -> tuple[tuple[type, ...], str]:
    return (
        ((str, Path, Reference), "paths or typed path references")
        if paths else ((str,), "non-empty NUL-free strings")
    )


def _text_content(value: object, field: str, label: str) -> None:
    if not str(value):
        raise SpecError(field, value, "must contain %s" % label)
    if "\0" in str(value):
        raise SpecError(field, value, "must contain %s" % label)


def _text_tuple(value: object, field: str, *, paths: bool = False) -> tuple:
    selected = _sequence(value, field)
    for item in selected:
        _text_item(item, field, paths=paths)
    return selected


def _positive(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise SpecError(field, value, "must be a number > 0")
    return float(value)


def _expected_codes(value: object) -> tuple[int, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise SpecError("native_test.expected_exit_codes", value, "must be an integer sequence")
    selected = tuple(value)
    if not selected or not all(isinstance(code, int) and not isinstance(code, bool)
                               for code in selected):
        raise SpecError(
            "native_test.expected_exit_codes", value,
            "must contain at least one integer",
        )
    return selected


def _defines(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise SpecError("native_test.defines", value, "must map preprocessor names to values")
    valid_values = (str, int, bool, Reference, type(None))
    valid = all(
        isinstance(name, str) and _DEFINE.fullmatch(name)
        and isinstance(item, valid_values) and "\0" not in str(item)
        for name, item in value.items()
    )
    if not valid:
        raise SpecError(
            "native_test.defines", value,
            "must map C identifiers to NUL-free strings, integers, booleans, or None",
        )
    return freeze_mapping(value)


def _compiler(value: object) -> Optional[tuple[CompilerPart, ...]]:
    if value is None:
        return None
    selected = _compiler_parts(value)
    _validate_compiler_parts(selected, value)
    return selected


def _compiler_parts(value: object) -> tuple:
    if isinstance(value, (str, Path, Reference, Binary)):
        return (value,)
    return _sequence(value, "native_test.compiler")


def _validate_compiler_parts(selected: tuple, original: object) -> None:
    if not selected or not all(isinstance(part, (str, Path, Reference, Binary))
                               for part in selected):
        raise SpecError(
            "native_test.compiler", original,
            "must be a command, captured binary, typed reference, or argv sequence",
        )
    if any(_invalid_compiler_part(part) for part in selected):
        raise SpecError("native_test.compiler", original, "must be shell-free argv")


def _invalid_compiler_part(value: CompilerPart) -> bool:
    text = str(value)
    if not text:
        return True
    return "\0" in text


def _arguments(value: object) -> tuple[object, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise SpecError("native_test.args", value, "must be an argv sequence")
    selected = tuple(value)
    if any("\0" in str(item) for item in selected):
        raise SpecError("native_test.args", value, "must be NUL-free")
    return selected


@dataclasses.dataclass(frozen=True)
class OutputExpectation:
    """Immutable exact, substring, exclusion, and regular-expression checks."""

    contains: Sequence[str] = ()
    excludes: Sequence[str] = ()
    regex: Sequence[str] = ()
    exact: Optional[str] = None
    strip: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "contains", _text_tuple(self.contains, "output.contains"))
        object.__setattr__(self, "excludes", _text_tuple(self.excludes, "output.excludes"))
        patterns = _text_tuple(self.regex, "output.regex")
        for pattern in patterns:
            _validate_pattern(pattern)
        object.__setattr__(self, "regex", patterns)
        if self.exact is not None and not isinstance(self.exact, str):
            raise SpecError("output.exact", self.exact, "must be text or None")
        if not isinstance(self.strip, bool):
            raise SpecError("output.strip", self.strip, "must be true or false")


def _validate_pattern(pattern: str) -> None:
    try:
        re.compile(pattern)
    except re.error as exc:
        raise SpecError("output.regex", pattern, "must compile: %s" % exc) from exc


def expect_output(
    *contains: str, excludes: Sequence[str] = (), regex: Sequence[str] = (),
    exact: Optional[str] = None, strip: bool = False,
) -> OutputExpectation:
    """Declare readable checks for one captured stdout or stderr stream."""
    return OutputExpectation(contains, excludes, regex, exact, strip)


@dataclasses.dataclass(frozen=True)
class _NativeSpec:
    name: str
    sources: Sequence[PathValue]
    language: str = "auto"
    compiler: Optional[Sequence[CompilerPart]] = None
    standard: Optional[str] = None
    include_dirs: Sequence[PathValue] = ()
    defines: Mapping[str, object] = dataclasses.field(default_factory=dict)
    objects: Sequence[PathValue] = ()
    libraries: Sequence[str] = ()
    compile_args: Sequence[BuildArg] = ("-Wall", "-Wextra", "-Werror")
    link_args: Sequence[BuildArg] = ()
    pkg_config: Sequence[str] = ()
    required_files: Sequence[PathValue] = ()
    required_commands: Sequence[str] = ()
    args: Sequence[object] = ()
    env: Mapping[str, object] = dataclasses.field(default_factory=dict)
    compile_env: Mapping[str, object] = dataclasses.field(default_factory=dict)
    cwd: Optional[PathValue] = None
    input: Optional[Union[str, bytes]] = None
    expected_exit_codes: Sequence[int] = (0,)
    stdout: OutputValue = None
    stderr: OutputValue = None
    compile_timeout: float = 120.0
    timeout: float = 60.0
    output_limit: int = 1 << 20
    inherit_instrumentation: bool = True
    missing: str = "skip"
    execute: bool = True

    def __post_init__(self) -> None:
        _name(self.name, "native_test.name")
        self._freeze_sequences()
        self._validate_policy()

    def _freeze_sequences(self) -> None:
        object.__setattr__(
            self, "sources", _text_tuple(self.sources, "native_test.sources", paths=True),
        )
        object.__setattr__(
            self, "include_dirs",
            _text_tuple(self.include_dirs, "native_test.include_dirs", paths=True),
        )
        object.__setattr__(
            self, "objects", _text_tuple(self.objects, "native_test.objects", paths=True),
        )
        for field in ("libraries", "pkg_config", "required_commands"):
            value = _text_tuple(getattr(self, field), "native_test.%s" % field)
            object.__setattr__(self, field, value)
        for field in ("compile_args", "link_args"):
            value = _text_tuple(
                getattr(self, field), "native_test.%s" % field, paths=True,
            )
            object.__setattr__(self, field, value)
        object.__setattr__(
            self, "required_files",
            _text_tuple(self.required_files, "native_test.required_files", paths=True),
        )
        object.__setattr__(self, "args", _arguments(self.args))
        object.__setattr__(self, "defines", _defines(self.defines))
        object.__setattr__(self, "env", _string_mapping(self.env, "native_test.env"))
        object.__setattr__(
            self, "compile_env", _string_mapping(self.compile_env, "native_test.compile_env"),
        )
        object.__setattr__(self, "compiler", _compiler(self.compiler))
        object.__setattr__(self, "expected_exit_codes", _expected_codes(self.expected_exit_codes))

    def _validate_policy(self) -> None:
        _validate_sources(self.sources)
        _validate_language(self.language)
        _validate_standard(self.standard)
        _validate_missing(self.missing)
        for field in ("inherit_instrumentation", "execute"):
            _validate_switch(getattr(self, field), "native_test.%s" % field)
        _validate_output_mode(self)
        object.__setattr__(
            self, "compile_timeout",
            _positive(self.compile_timeout, "native_test.compile_timeout"),
        )
        object.__setattr__(self, "timeout", _positive(self.timeout, "native_test.timeout"))
        _validate_output_limit(self.output_limit)
        _validate_cwd(self.cwd)
        _validate_input(self.input)
        _expectation(self.stdout, "native_test.stdout")
        _expectation(self.stderr, "native_test.stderr")


def _validate_sources(value: Sequence[PathValue]) -> None:
    if not value:
        raise SpecError("native_test.sources", value, "must contain at least one source")


def _validate_language(value: str) -> None:
    if value not in _LANGUAGES:
        raise SpecError("native_test.language", value, "must be auto, c, or c++")


def _validate_standard(value: Optional[str]) -> None:
    if value is None:
        return
    if not isinstance(value, str) or not _STANDARD.fullmatch(value):
        raise SpecError("native_test.standard", value, "must be a compiler standard name")


def _validate_missing(value: str) -> None:
    if value not in _MISSING_POLICIES:
        raise SpecError("native_test.missing", value, "must be skip or fail")


def _validate_switch(value: object, field: str) -> None:
    if not isinstance(value, bool):
        raise SpecError(field, value, "must be true or false")


def _validate_output_mode(spec: _NativeSpec) -> None:
    if not spec.execute and (spec.stdout is not None or spec.stderr is not None):
        raise SpecError("native_test output", (spec.stdout, spec.stderr), "requires execute=True")


def _validate_output_limit(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 256:
        raise SpecError("native_test.output_limit", value, "must be an integer >= 256")


def _validate_cwd(value: object) -> None:
    if value is not None and (not isinstance(value, (str, Path, Reference)) or not str(value)):
        raise SpecError("native_test.cwd", value, "must be a path, typed reference, or None")


def _validate_input(value: object) -> None:
    if value is not None and not isinstance(value, (str, bytes)):
        raise SpecError("native_test.input", value, "must be text, bytes, or None")


def _expectation(value: OutputValue, field: str) -> Optional[OutputExpectation]:
    if value is None or isinstance(value, OutputExpectation):
        return value
    if isinstance(value, str):
        return expect_output(value)
    raise SpecError(field, value, "must be text, expect_output(...), or None")


def _caller_source() -> Path:
    frame = inspect.currentframe()
    caller = frame.f_back.f_back if frame is not None and frame.f_back is not None else None
    if caller is None:
        raise RuntimeError("native_test cannot determine the declaring module")
    return Path(caller.f_code.co_filename).resolve()


def _native_function(
    spec: _NativeSpec, resources: Sequence[object], options: dict, source: Path,
) -> Callable:
    from brixtest.native_runtime import execute_native

    def invoke(run, **_parameters) -> None:
        execute_native(run, spec)

    invoke.__name__ = "test_%s" % spec.name.replace("-", "_")
    invoke.__doc__ = "Compile and run the independently collected %s native test." % spec.name
    invoke.__signature__ = _native_signature(spec)
    managed = case(*resources, **options)(invoke)
    definition = dataclasses.replace(get_case(managed), source=source)
    managed.__brixtest_case__ = definition
    managed.__brixtest_native__ = spec
    return managed


def _native_signature(spec: _NativeSpec) -> inspect.Signature:
    names = _parameter_names(spec)
    if "run" in names:
        raise SpecError("native_test parameter", "run", "is reserved for the Run fixture")
    parameters = [inspect.Parameter("run", inspect.Parameter.POSITIONAL_OR_KEYWORD)]
    parameters.extend(
        inspect.Parameter(name, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        for name in names
    )
    return inspect.Signature(parameters)


def _parameter_names(spec: _NativeSpec) -> tuple[str, ...]:
    values = (
        *spec.sources, *spec.include_dirs, *spec.objects, *spec.required_files,
        *(spec.compiler or ()), *spec.compile_args, *spec.link_args,
        *spec.defines.values(), *((spec.cwd,) if spec.cwd is not None else ()),
        *spec.args, *spec.env.values(), *spec.compile_env.values(),
    )
    return tuple(dict.fromkeys(
        item.name for item in values
        if isinstance(item, Reference) and item.kind == "parameter"
    ))


def _mapping(value: Optional[Mapping[str, object]]) -> Mapping[str, object]:
    return {} if value is None else value


def _case_timeout(spec: _NativeSpec, value: Optional[float]) -> float:
    if value is not None:
        return value
    runtime = spec.timeout if spec.execute else 0.0
    return spec.compile_timeout + runtime + 30.0


def _case_options(
    spec: _NativeSpec, observe: Optional[Sequence[CollectorSpec]], trials: int,
    warmup: int, case_timeout: Optional[float], backend: str,
    isolation: Optional[Isolation], keep: str,
) -> dict:
    options = dict(
        trials=trials, warmup=warmup, timeout=_case_timeout(spec, case_timeout),
        backend=backend, isolation=isolation, keep=keep,
    )
    if observe is not None:
        options["observe"] = observe
    return options


def native_test(
    name: str, *, sources: Sequence[PathValue], resources: Sequence[object] = (),
    language: str = "auto", compiler: CompilerValue = None,
    standard: Optional[str] = None, include_dirs: Sequence[PathValue] = (),
    defines: Optional[Mapping[str, object]] = None, objects: Sequence[PathValue] = (),
    libraries: Sequence[str] = (),
    compile_args: Sequence[BuildArg] = ("-Wall", "-Wextra", "-Werror"),
    link_args: Sequence[BuildArg] = (), pkg_config: Sequence[str] = (),
    required_files: Sequence[PathValue] = (), required_commands: Sequence[str] = (),
    args: Sequence[object] = (), env: Optional[Mapping[str, object]] = None,
    compile_env: Optional[Mapping[str, object]] = None, cwd: Optional[PathValue] = None,
    input: Optional[Union[str, bytes]] = None, expected_exit_codes: Sequence[int] = (0,),
    stdout: OutputValue = None, stderr: OutputValue = None,
    compile_timeout: float = 120.0, timeout: float = 60.0,
    output_limit: int = 1 << 20, inherit_instrumentation: bool = True,
    missing: str = "skip", execute: bool = True,
    observe: Optional[Sequence[CollectorSpec]] = None, trials: int = 1,
    warmup: int = 0, case_timeout: Optional[float] = None, backend: str = "auto",
    isolation: Optional[Isolation] = None, keep: str = "failed",
) -> Callable:
    """Create one ordinary, supervised pytest item for one C or C++ program."""
    if isinstance(resources, (str, bytes)) or not isinstance(resources, Sequence):
        raise SpecError("native_test.resources", resources, "must be a declaration sequence")
    spec = _NativeSpec(
        name, sources, language, compiler, standard, include_dirs,
        _mapping(defines), objects, libraries, compile_args,
        link_args, pkg_config, required_files, required_commands, args,
        _mapping(env), _mapping(compile_env),
        cwd, input, expected_exit_codes, stdout, stderr, compile_timeout, timeout,
        output_limit, inherit_instrumentation, missing, execute,
    )
    options = _case_options(
        spec, observe, trials, warmup, case_timeout, backend, isolation, keep,
    )
    return _native_function(spec, tuple(resources), options, _caller_source())


def native_input_paths(value: object) -> tuple[Path, ...]:
    """Return existing host inputs needed when launching an isolated helper."""
    spec = getattr(value, "__brixtest_native__", None)
    definition = getattr(value, "__brixtest_case__", None)
    if not isinstance(spec, _NativeSpec) or definition is None:
        return ()
    root = Path(definition.source).parent
    cwd = root if isinstance(spec.cwd, Reference) else _resolve_path(spec.cwd or ".", root)
    selected = (*spec.sources, *spec.include_dirs, *spec.objects, *spec.required_files)
    return _existing_paths(selected, cwd)


def _existing_paths(values: Sequence[PathValue], cwd: Path) -> tuple[Path, ...]:
    result = []
    for value in values:
        if isinstance(value, Reference):
            continue
        path = _resolve_path(value, cwd)
        if path.exists():
            result.append(path)
    return tuple(dict.fromkeys(result))


def _resolve_path(value: Union[str, Path], root: Path) -> Path:
    path = Path(value)
    return (path if path.is_absolute() else root / path).resolve()


__all__ = ["OutputExpectation", "expect_output", "native_test"]
