"""Named command-line clients loaded from a BriXTest project config.

Clients are argv vectors, never shell snippets.  A test asks for a client by
name and supplies only the operation-specific arguments; the configured
executable, environment, working directory, and deadline stay in one place.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Callable, Dict, Mapping, Optional, Sequence, Union

from brixtest.errors import SpecError
from brixtest.resources import Placement, Reference
from brixtest.runtime.commands import CommandResult, CommandRunner
from brixtest.runtime.executors import ToolExecutionContext, ToolExecutionRequest
from brixtest.util.configtext import render_cfg_strict
from brixtest.util.immutable import freeze_mapping

__all__ = ["ClientRegistry", "ClientSpec", "ConfiguredClient", "ConfiguredTool"]

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


def _client_identity(name: object, command: object) -> tuple[str, ...]:
    if not _valid_client_name(name):
        raise SpecError(
            "client name", name,
            "must be lowercase [a-z0-9_-], starting alphanumeric",
        )
    if not _valid_client_command(command):
        raise SpecError("client command", command, "must be a non-empty array of string arguments")
    return tuple(command)


def _valid_client_name(name: object) -> bool:
    return isinstance(name, str) and bool(name) and bool(_NAME_RE.match(name))


def _valid_client_command(command: object) -> bool:
    return not isinstance(command, (str, bytes)) and bool(command) \
        and all(isinstance(part, str) for part in command)


def _client_environment(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(
        isinstance(key, str) and isinstance(item, (str, Reference))
        for key, item in value.items()
    ):
        raise SpecError("client env", value, "must map strings to strings or typed references")
    return freeze_mapping(value)


def _client_io(spec: "ClientSpec") -> None:
    if not _valid_client_input(spec.input):
        raise SpecError("client input", spec.input, "must be text or None")
    if not _valid_output_limit(spec.output_limit):
        raise SpecError("client output limit", spec.output_limit, "must be an integer >= 1")
    if spec.mode not in ("capture", "stream", "pty"):
        raise SpecError("client mode", spec.mode, "must be capture, stream, or pty")
    if not _valid_encoding(spec.encoding):
        raise SpecError("client encoding", spec.encoding, "must be non-empty text")


def _valid_client_input(value: object) -> bool:
    return value is None or isinstance(value, str)


def _valid_output_limit(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 1


def _valid_encoding(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _client_execution(spec: "ClientSpec") -> tuple[int, ...]:
    if not _positive_timeout(spec.timeout):
        raise SpecError("client timeout", spec.timeout, "must be > 0")
    expected = tuple(spec.expected_exit_codes)
    if not expected or not all(_exit_code(value) for value in expected):
        raise SpecError("client expected exits", expected, "must contain integers")
    if not _nonnegative_integer(spec.retries):
        raise SpecError("client retries", spec.retries, "must be an integer >= 0")
    return expected


def _positive_timeout(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float)) and value > 0


def _exit_code(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _nonnegative_integer(value: object) -> bool:
    return _exit_code(value) and value >= 0


def _render_command(spec: "ClientSpec", values: Mapping[str, object]) -> tuple[str, ...]:
    return tuple(
        render_cfg_strict(part, values, template="client %s command" % spec.name)
        for part in spec.command
    )


def _render_environment(spec: "ClientSpec", values: Mapping[str, object]) -> dict[str, str]:
    return {
        key: render_cfg_strict(
            str(value), values, template="client %s env[%s]" % (spec.name, key),
        )
        for key, value in spec.env.items()
    }


def _render_working_directory(
    spec: "ClientSpec", values: Mapping[str, object],
) -> Optional[Path]:
    if not spec.cwd:
        return None
    return Path(render_cfg_strict(spec.cwd, values, template="client %s cwd" % spec.name))


def _client_placement(spec: "ClientSpec") -> tuple[str, ...]:
    if not isinstance(spec.placement, Placement):
        raise SpecError("client placement", spec.placement, "must be a Placement")
    if not isinstance(spec.image, str):
        raise SpecError("client image", spec.image, "must be text")
    redaction = tuple(spec.log_redact)
    if not all(isinstance(value, str) and value for value in redaction):
        raise SpecError("client log redaction", redaction, "must contain non-empty text")
    return redaction


@dataclasses.dataclass(frozen=True)
class ClientSpec:
    """Configuration shared by every invocation of one named client."""

    name: str
    command: Sequence[str]
    env: Mapping[str, object] = dataclasses.field(default_factory=dict)
    cwd: Optional[str] = None
    timeout: float = 30.0
    input: Optional[str] = None
    expected_exit_codes: Sequence[int] = (0,)
    output_limit: int = 1 << 20
    mode: str = "capture"
    retries: int = 0
    encoding: str = "utf-8"
    log_redact: Sequence[str] = ()
    placement: Placement = dataclasses.field(default_factory=Placement)
    image: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "command", _client_identity(self.name, self.command))
        object.__setattr__(self, "env", _client_environment(self.env))
        object.__setattr__(self, "expected_exit_codes", _client_execution(self))
        _client_io(self)
        object.__setattr__(self, "log_redact", _client_placement(self))


@dataclasses.dataclass(frozen=True)
class _RunOptions:
    cwd: Optional[Union[str, Path]]
    timeout: float
    input: Optional[str]
    expected: tuple[int, ...]
    output_limit: int
    mode: str
    retries: int
    encoding: str


ClientObserver = Callable[[str, float, Optional[int], str], None]
ClientResultObserver = Callable[[str, CommandResult], None]


class ConfiguredClient:
    """A bound client whose ``run`` method always executes without a shell."""

    def __init__(
        self, spec: ClientSpec, values: Mapping[str, object], *,
        observer: Optional[ClientObserver] = None,
        archive_dir: Optional[Path] = None,
        executor: Optional[object] = None,
        execution_context: Optional[ToolExecutionContext] = None,
        executor_metadata: Optional[Mapping[str, object]] = None,
        result_observer: Optional[ClientResultObserver] = None,
    ) -> None:
        self.spec = spec
        self._values = freeze_mapping(values)
        self._observer = observer
        self._result_observer = result_observer
        self._executor = executor
        self._execution_context = execution_context
        self._executor_metadata = _mapping_copy(executor_metadata)
        self._archive_dir = _optional_path(archive_dir)
        self._command = _render_command(spec, values)
        self._env = _render_environment(spec, values)
        self._cwd = _render_working_directory(spec, values)
        self._runner = CommandRunner(
            self._archive_dir, cwd=_working_path(self._cwd), observer=self._observe,
            redact=spec.log_redact,
        )
        if self._needs_local_executor():
            self._execution_context = dataclasses.replace(
                self._execution_context, local_execute=self._execute_local_request,
            )

    def _needs_local_executor(self) -> bool:
        if self._executor is None or self._execution_context is None:
            return False
        return self._execution_context.local_execute is None

    def _observe(self, elapsed: float, returncode: Optional[int], error: str) -> None:
        if self._observer is not None:
            self._observer(self.spec.name, elapsed, returncode, error)

    def _execute_local_request(self, request: ToolExecutionRequest) -> CommandResult:
        return self._runner.run(
            *request.argv, check=False, timeout=request.timeout, input=request.input,
            env=request.env, cwd=request.cwd,
            expected_exit_codes=request.expected_exit_codes,
            output_limit=request.output_limit, mode=request.mode,
            retries=request.retries, encoding=request.encoding,
        )

    @property
    def name(self) -> str:
        """The stable declaration name used by ``run.client(...)``."""
        return self.spec.name

    @property
    def command(self) -> tuple[str, ...]:
        """The fully rendered base argument vector, without per-call arguments."""
        return self._command

    @property
    def timeout(self) -> float:
        """The default deadline in seconds for each invocation."""
        return self.spec.timeout

    @property
    def cwd(self) -> Optional[Path]:
        """The rendered default working directory, if one was declared."""
        return self._cwd

    def as_dict(self) -> Dict[str, object]:
        """Return JSON-safe, secret-free client diagnostics."""
        return {
            "name": self.name, "command": list(self.command),
            "cwd": str(self.cwd) if self.cwd is not None else None,
            "timeout": self.timeout, "environment_names": sorted(self._env),
            "expected_exit_codes": list(self.spec.expected_exit_codes),
            "output_limit": self.spec.output_limit, "mode": self.spec.mode,
            "retries": self.spec.retries, "encoding": self.spec.encoding,
            "placement": self.spec.placement.backend,
        }

    def run(
        self,
        *args: object,
        check: bool = True,
        timeout: Optional[float] = None,
        input: Optional[str] = None,
        env: Optional[Mapping[str, object]] = None,
        cwd: Optional[Union[str, Path]] = None,
        expected_exit_codes: Optional[Sequence[int]] = None,
        output_limit: Optional[int] = None,
        mode: Optional[str] = None,
        retries: Optional[int] = None,
        encoding: Optional[str] = None,
    ) -> CommandResult:
        """Run the configured argv plus ``args`` and return a rich text result."""
        rendered_args = self._render_arguments(args)
        executor_name = self._executor_name()
        merged_env = self._merged_environment(executor_name, env)
        options = self._run_options(
            cwd, timeout, input, expected_exit_codes, output_limit, mode, retries, encoding,
        )
        result = self._execute(rendered_args, merged_env, options, executor_name)
        if self._result_observer is not None:
            self._result_observer(self.name, result)
        if check and result.returncode not in options.expected:
            raise subprocess.CalledProcessError(
                result.returncode, result.argv, output=result.stdout, stderr=result.stderr,
            )
        return result

    def _render_arguments(self, args: Sequence[object]) -> tuple[str, ...]:
        rendered = tuple(
            render_cfg_strict(
                str(arg), self._values, template="client %s argument" % self.spec.name,
            )
            for arg in args
        )
        if any(not arg or "\x00" in arg for arg in rendered):
            raise SpecError(
                "client %s args" % self.spec.name, rendered,
                "must contain non-empty, NUL-free argv entries",
            )
        return rendered

    def _executor_name(self) -> str:
        return "local" if self.spec.placement.backend == "inherit" else self.spec.placement.backend

    def _merged_environment(
        self, executor_name: str, env: Optional[Mapping[str, object]],
    ) -> Dict[str, str]:
        # Remote/container executors receive only explicitly declared values.
        # Besides making runs reproducible, this prevents ambient host secrets
        # from being serialized into a Pod manifest or container env file.
        merged_env = dict(os.environ) if executor_name == "local" else {}
        merged_env.update(self._env)
        if not env:
            return merged_env
        checked = _client_environment(env)
        merged_env.update({
                key: render_cfg_strict(
                    str(value), self._values,
                    template="client %s invocation env[%s]" % (self.spec.name, key),
                )
                for key, value in checked.items()
        })
        return merged_env

    def _run_options(
        self, cwd, timeout, input_value, expected, output_limit, mode, retries, encoding,
    ) -> _RunOptions:
        return _RunOptions(
            self._selected_cwd(cwd), _selected(timeout, self.spec.timeout),
            _selected(input_value, self.spec.input),
            tuple(_selected(expected, self.spec.expected_exit_codes)),
            _selected(output_limit, self.spec.output_limit),
            _selected(mode, self.spec.mode), _selected(retries, self.spec.retries),
            _selected(encoding, self.spec.encoding),
        )

    def _selected_cwd(self, cwd) -> Optional[Path]:
        if cwd is None:
            return self._cwd
        rendered = render_cfg_strict(
            str(cwd), self._values,
            template="client %s invocation cwd" % self.spec.name,
        )
        return Path(rendered)

    def _execute(
        self, args: tuple[str, ...], env: Mapping[str, str], options: _RunOptions,
        executor_name: str,
    ) -> CommandResult:
        if self._executor is None:
            return self._runner.run(
                *self._command, *args, check=False,
                timeout=options.timeout, input=options.input, env=env,
                cwd=options.cwd, expected_exit_codes=options.expected,
                output_limit=options.output_limit, mode=options.mode,
                retries=options.retries, encoding=options.encoding,
            )
        if self._execution_context is None:
            raise SpecError("client executor", self.name, "has no execution context")
        request = ToolExecutionRequest(
            name=self.name, argv=(*self._command, *args), env=env,
            cwd=Path(options.cwd) if options.cwd is not None else None,
            timeout=options.timeout, input=options.input,
            expected_exit_codes=options.expected, output_limit=options.output_limit,
            mode=options.mode, retries=options.retries,
            encoding=options.encoding, check=False,
            placement=self.spec.placement, image=self.spec.image,
            metadata=self._executor_metadata,
        )
        result = self._executor.execute(self._execution_context, request)
        if not isinstance(result, CommandResult):
            raise SpecError(
                "client executor result", type(result).__name__,
                "must return brixtest.CommandResult",
            )
        if executor_name != "local":
            self._observe(result.elapsed_seconds, result.returncode, "")
            self._archive_execution(result)
        return result

    def _archive_execution(self, result: CommandResult) -> None:
        """Archive output from non-local executors using the normal client layout."""
        if self._archive_dir is None:
            return
        self._archive_dir.mkdir(parents=True, exist_ok=True)
        sequence = len(tuple(self._archive_dir.glob("*.json"))) + 1
        stem = "%04d" % sequence
        stdout = result.stdout
        stderr = result.stderr
        for secret in self.spec.log_redact:
            stdout = stdout.replace(secret, "[REDACTED]")
            stderr = stderr.replace(secret, "[REDACTED]")
        (self._archive_dir / (stem + ".stdout.log")).write_text(stdout)
        (self._archive_dir / (stem + ".stderr.log")).write_text(stderr)
        (self._archive_dir / (stem + ".json")).write_text(
            json.dumps(result.as_dict(), indent=2, sort_keys=True) + "\n"
        )


class ConfiguredTool(ConfiguredClient):
    """Bound runtime value for a first-class :class:`brixtest.Tool`."""


def _selected(value, default):
    return default if value is None else value


def _mapping_copy(value) -> dict:
    return dict(value) if value is not None else {}


def _optional_path(value) -> Optional[Path]:
    return Path(value) if value else None


def _working_path(value: Optional[Path]) -> Path:
    return value if value is not None else Path.cwd()


class ClientRegistry:
    """Checked name-to-client lookup used by tests and project tooling."""

    def __init__(
        self,
        specs: Sequence[ClientSpec] = (),
        *,
        values: Optional[Mapping[str, object]] = None,
    ) -> None:
        self._clients: Dict[str, ConfiguredClient] = {}
        for spec in specs:
            if spec.name in self._clients:
                raise SpecError(
                    "client name", spec.name, "is declared more than once"
                )
            self._clients[spec.name] = ConfiguredClient(spec, values or {})

    def get(self, name: str) -> ConfiguredClient:
        try:
            return self._clients[name]
        except KeyError:
            raise SpecError(
                "client name", name,
                "not configured — known: %s" % (
                    ", ".join(self.names()) or "(none)"
                ),
            ) from None

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._clients))

    def __contains__(self, name: str) -> bool:
        return name in self._clients

    def __len__(self) -> int:
        return len(self._clients)
