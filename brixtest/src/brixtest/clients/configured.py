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
from brixtest.runtime.commands import CommandResult, CommandRunner
from brixtest.resources import Placement, Reference
from brixtest.runtime.executors import ToolExecutionContext, ToolExecutionRequest
from brixtest.util.immutable import freeze_mapping
from brixtest.util.configtext import render_cfg_strict

__all__ = ["ClientRegistry", "ClientSpec", "ConfiguredClient", "ConfiguredTool"]

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


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
        if not self.name or not _NAME_RE.match(self.name):
            raise SpecError(
                "client name", self.name,
                "must be lowercase [a-z0-9_-], starting alphanumeric",
            )
        if (
            isinstance(self.command, (str, bytes))
            or not self.command
            or not all(isinstance(part, str) for part in self.command)
        ):
            raise SpecError(
                "client command", self.command,
                "must be a non-empty array of string arguments",
            )
        if self.timeout <= 0:
            raise SpecError("client timeout", self.timeout, "must be > 0")
        if not all(isinstance(key, str) and isinstance(value, (str, Reference))
                   for key, value in self.env.items()):
            raise SpecError(
                "client env", self.env,
                "must map strings to strings or typed references",
            )
        object.__setattr__(self, "command", tuple(self.command))
        object.__setattr__(self, "env", freeze_mapping(self.env))
        if self.input is not None and not isinstance(self.input, str):
            raise SpecError("client input", self.input, "must be text or None")
        expected = tuple(self.expected_exit_codes)
        if not expected or not all(
            isinstance(value, int) and not isinstance(value, bool) for value in expected
        ):
            raise SpecError("client expected exits", expected, "must contain integers")
        object.__setattr__(self, "expected_exit_codes", expected)
        if isinstance(self.output_limit, bool) or not isinstance(self.output_limit, int) or self.output_limit < 1:
            raise SpecError("client output limit", self.output_limit, "must be an integer >= 1")
        if self.mode not in ("capture", "stream", "pty"):
            raise SpecError("client mode", self.mode, "must be capture, stream, or pty")
        if isinstance(self.retries, bool) or not isinstance(self.retries, int) or self.retries < 0:
            raise SpecError("client retries", self.retries, "must be an integer >= 0")
        if not isinstance(self.encoding, str) or not self.encoding:
            raise SpecError("client encoding", self.encoding, "must be non-empty text")
        if not isinstance(self.placement, Placement):
            raise SpecError("client placement", self.placement, "must be a Placement")
        if not isinstance(self.image, str):
            raise SpecError("client image", self.image, "must be text")
        redaction = tuple(self.log_redact)
        if not all(isinstance(value, str) and value for value in redaction):
            raise SpecError("client log redaction", redaction, "must contain non-empty text")
        object.__setattr__(self, "log_redact", redaction)


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
        self._executor_metadata = dict(executor_metadata or {})
        self._archive_dir = Path(archive_dir) if archive_dir else None
        self._command = tuple(
            render_cfg_strict(part, values, template="client %s command" % spec.name)
            for part in spec.command
        )
        self._env = {
            key: render_cfg_strict(
                str(value), values, template="client %s env[%s]" % (spec.name, key)
            )
            for key, value in spec.env.items()
        }
        self._cwd = (
            Path(render_cfg_strict(
                spec.cwd, values, template="client %s cwd" % spec.name
            ))
            if spec.cwd else None
        )
        self._runner = CommandRunner(
            Path(archive_dir) if archive_dir else None,
            cwd=self._cwd or Path.cwd(), observer=self._observe,
            redact=spec.log_redact,
        )
        if self._executor is not None and self._execution_context is not None \
                and self._execution_context.local_execute is None:
            self._execution_context = dataclasses.replace(
                self._execution_context, local_execute=self._execute_local_request,
            )

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
        rendered_args = tuple(
            render_cfg_strict(
                str(arg), self._values, template="client %s argument" % self.spec.name,
            )
            for arg in args
        )
        if any(not arg or "\x00" in arg for arg in rendered_args):
            raise SpecError(
                "client %s args" % self.spec.name, rendered_args,
                "must contain non-empty, NUL-free argv entries",
            )
        executor_name = (
            "local" if self.spec.placement.backend == "inherit"
            else self.spec.placement.backend
        )
        # Remote/container executors receive only explicitly declared values.
        # Besides making runs reproducible, this prevents ambient host secrets
        # from being serialized into a Pod manifest or container env file.
        merged_env = dict(os.environ) if executor_name == "local" else {}
        merged_env.update(self._env)
        if env:
            if not isinstance(env, Mapping) or not all(
                isinstance(key, str) and isinstance(value, (str, Reference))
                for key, value in env.items()
            ):
                raise SpecError(
                    "client environment", env,
                    "must map strings to strings or typed references",
                )
            merged_env.update({
                key: render_cfg_strict(
                    str(value), self._values,
                    template="client %s invocation env[%s]" % (self.spec.name, key),
                )
                for key, value in env.items()
            })
        selected_cwd = cwd or self._cwd
        if cwd is not None:
            selected_cwd = Path(render_cfg_strict(
                str(cwd), self._values,
                template="client %s invocation cwd" % self.spec.name,
            ))
        selected_expected = tuple(
            self.spec.expected_exit_codes
            if expected_exit_codes is None else expected_exit_codes
        )
        selected_timeout = self.spec.timeout if timeout is None else timeout
        selected_input = self.spec.input if input is None else input
        selected_limit = self.spec.output_limit if output_limit is None else output_limit
        selected_mode = self.spec.mode if mode is None else mode
        selected_retries = self.spec.retries if retries is None else retries
        selected_encoding = self.spec.encoding if encoding is None else encoding
        if self._executor is None:
            result = self._runner.run(
                *self._command, *rendered_args, check=False,
                timeout=selected_timeout, input=selected_input, env=merged_env,
                cwd=selected_cwd, expected_exit_codes=selected_expected,
                output_limit=selected_limit, mode=selected_mode,
                retries=selected_retries, encoding=selected_encoding,
            )
        else:
            if self._execution_context is None:
                raise SpecError("client executor", self.name, "has no execution context")
            request = ToolExecutionRequest(
                name=self.name, argv=(*self._command, *rendered_args), env=merged_env,
                cwd=Path(selected_cwd) if selected_cwd is not None else None,
                timeout=selected_timeout, input=selected_input,
                expected_exit_codes=selected_expected, output_limit=selected_limit,
                mode=selected_mode, retries=selected_retries,
                encoding=selected_encoding, check=False,
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
        if self._result_observer is not None:
            self._result_observer(self.name, result)
        if check and result.returncode not in selected_expected:
            raise subprocess.CalledProcessError(
                result.returncode, result.argv, output=result.stdout, stderr=result.stderr,
            )
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
