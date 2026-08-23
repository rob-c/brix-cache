"""User-facing facade over one managed BriXTest run."""

from __future__ import annotations

import warnings
from io import IOBase
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Union, overload

from brixtest.auth.models import AuthRecipe
from brixtest.auth.store import MaterializedAuth
from brixtest.clients.configured import ConfiguredClient, ConfiguredTool
from brixtest.credentials import Credential, MaterializedCredential
from brixtest.design import Artifact, Binary, Client, Server, Task, Tool, Volume
from brixtest.errors import SpecError
from brixtest.resources import Command, Reference
from brixtest.runtime.artifacts import MaterializedArtifact
from brixtest.runtime.binaries import CapturedBinary
from brixtest.runtime.commands import CommandResult
from brixtest.runtime.service import Service


def _resource_name(value: object, expected: type, field: str) -> str:
    if isinstance(value, expected):
        return value.name
    if not isinstance(value, str) or not value:
        raise SpecError(field, value, "must be a resource name or declaration")
    return value


def _run_renderer(manager):
    renderer = getattr(manager, "_render_value", None)
    if callable(renderer):
        return lambda value, label: renderer(value, label=label)
    return lambda value, label: str(value)


def _command_environment(env, render) -> dict[str, str]:
    if env is None:
        return {}
    if not isinstance(env, Mapping):
        raise SpecError("run.command env", env, "must map strings to strings or typed references")
    valid = all(
        isinstance(key, str) and isinstance(value, (str, Reference))
        for key, value in env.items()
    )
    if not valid:
        raise SpecError("run.command env", env, "must map strings to strings or typed references")
    return {
        key: render(value, "run.command env[%s]" % key) for key, value in env.items()
    }


def _legacy_tool_run(args, env, cwd, check: bool) -> bool:
    return bool(args) or env is not None or cwd is not None or not check


class Run:
    """The only fixture value a case needs: named resources and endpoints."""

    def __init__(self, manager: Any) -> None:
        self._manager = manager
        self.root = manager.root
        self.workspace = manager.workspace
        self.backend = manager.backend_name
        self.metrics = manager.metrics

    @property
    def servers(self) -> Mapping[str, Service]:
        """Snapshot of all server endpoints available to this test."""
        return dict(self._manager._services)

    @property
    def clients(self) -> Mapping[str, ConfiguredClient]:
        """Snapshot of all configured clients available to this test."""
        return dict(self._manager._clients)

    @property
    def tools(self) -> Mapping[str, ConfiguredTool]:
        """Snapshot containing only first-class named tool declarations."""
        return {
            name: value for name, value in self._manager._clients.items()
            if isinstance(value, ConfiguredTool)
        }

    @property
    def artifacts(self) -> Mapping[str, MaterializedArtifact]:
        """Snapshot of all materialized input artifacts."""
        return dict(self._manager.artifact_store._items)

    @property
    def binaries(self) -> Mapping[str, CapturedBinary]:
        """Snapshot of immutable executable captures used by this test."""
        return dict(self._manager.binary_store._captured)

    @property
    def credentials(self) -> Mapping[str, MaterializedCredential]:
        """Snapshot of credentials exposed to the test helper."""
        return dict(self._manager.security.credentials._items)

    @property
    def auth_stacks(self) -> Mapping[str, MaterializedAuth]:
        """Snapshot of materialized authentication stacks."""
        return dict(self._manager.security.auth._items)

    @property
    def volumes(self) -> Mapping[str, Path]:
        """Snapshot of realized volume paths keyed by declaration name."""
        return {
            name: item.path for name, item in self._manager._managed.volumes._items.items()
        }

    @property
    def tasks(self) -> Mapping[str, CommandResult]:
        """Snapshot of completed managed task results."""
        return {
            name: item.result for name, item in self._manager._managed.tasks.items()
        }

    def as_dict(self) -> Dict[str, object]:
        """Return a secret-free, JSON-safe catalogue of this run's resources."""
        return {
            "root": str(self.root), "workspace": str(self.workspace),
            "backend": self.backend,
            "servers": {name: value.as_dict() for name, value in sorted(self.servers.items())},
            "clients": {name: value.as_dict() for name, value in sorted(self.clients.items())},
            "tools": {name: value.as_dict() for name, value in sorted(self.tools.items())},
            "artifacts": sorted(self.artifacts), "binaries": sorted(self.binaries),
            "credentials": sorted(self.credentials), "auth": sorted(self.auth_stacks),
            "volumes": {name: str(path) for name, path in sorted(self.volumes.items())},
            "tasks": {
                name: record.as_dict()
                for name, record in sorted(self._manager._managed.tasks.items())
            },
        }

    def command(
        self, *argv: object, check: bool = True, timeout: Optional[float] = None,
        input: Optional[str] = None, env: Optional[Mapping[str, object]] = None,
        cwd: Optional[Union[str, Path]] = None,
        encoding: str = "utf-8", expected_exit_codes: tuple[int, ...] = (0,),
        output_limit: int = 1 << 20, mode: str = "capture", retries: int = 0,
    ) -> CommandResult:
        """Run shell-free argv with captured UTF-8 stdout/stderr and durable logs."""
        render = _run_renderer(self._manager)
        rendered_argv = tuple(render(value, "run.command argv") for value in argv)
        rendered_env = _command_environment(env, render)
        return self._manager.commands.run(
            *rendered_argv, check=check, timeout=timeout, input=input,
            env=rendered_env or None, cwd=cwd,
            encoding=encoding, expected_exit_codes=expected_exit_codes,
            output_limit=output_limit, mode=mode, retries=retries,
        )

    def execute(
        self, declaration: Command, *args: object, check: bool = True,
        env: Optional[Mapping[str, object]] = None,
        cwd: Optional[Union[str, Path]] = None,
    ) -> CommandResult:
        """Execute one reusable :class:`Execution` with explicit semantics."""
        if not isinstance(declaration, Command):
            raise SpecError(
                "run.execute", declaration, "must be an Execution declaration",
            )
        merged_env = dict(declaration.env)
        merged_env.update(env or {})
        selected_cwd: Optional[Union[str, Path]] = cwd
        if selected_cwd is None and declaration.cwd:
            selected_cwd = self.workspace / declaration.cwd
        return self.command(
            *declaration.argv, *args, check=check, timeout=declaration.timeout,
            input=declaration.input, env=merged_env, cwd=selected_cwd,
            encoding=declaration.encoding,
            expected_exit_codes=tuple(declaration.expected_exit_codes),
            output_limit=declaration.output_limit, mode=declaration.mode,
            retries=declaration.retries,
        )

    @overload
    def tool(self, declaration: Tool) -> ConfiguredTool: ...

    @overload
    def tool(self, declaration: Client) -> ConfiguredClient: ...

    @overload
    def tool(
        self, declaration: str,
    ) -> Union[ConfiguredTool, ConfiguredClient]: ...

    @overload
    def tool(
        self, declaration: Command, *args: object, check: bool = True,
        env: Optional[Mapping[str, object]] = None,
        cwd: Optional[Union[str, Path]] = None,
    ) -> CommandResult: ...

    def tool(
        self, declaration: Union[str, Tool, Command, Client], *args: object,
        check: bool = True, env: Optional[Mapping[str, object]] = None,
        cwd: Optional[Union[str, Path]] = None,
    ) -> Union[ConfiguredTool, ConfiguredClient, CommandResult]:
        """Resolve a named Tool; legacy invocation forms remain temporarily supported."""
        if isinstance(declaration, Command):
            warnings.warn(
                "run.tool(Execution) is deprecated; use run.execute(Execution)",
                DeprecationWarning, stacklevel=2,
            )
            return self.execute(declaration, *args, check=check, env=env, cwd=cwd)
        bound = self._bound_tool(declaration)
        if _legacy_tool_run(args, env, cwd, check):
            warnings.warn(
                "run.tool(tool, *args) is deprecated; use run.tool(tool).run(*args)",
                DeprecationWarning, stacklevel=2,
            )
            return bound.run(*args, check=check, env=env, cwd=cwd)
        if not isinstance(bound, ConfiguredTool):
            warnings.warn(
                "run.tool(Client) is a compatibility path; declare it with tool()",
                DeprecationWarning, stacklevel=2,
            )
        return bound

    def _bound_tool(self, declaration):
        if isinstance(declaration, str):
            return self._manager.client(declaration)
        if isinstance(declaration, Client):
            return self._manager.client(declaration.name)
        raise SpecError(
            "run.tool", declaration, "must be a tool name or Tool declaration",
        )

    def server(self, value: Union[str, Server]) -> Service:
        """Resolve a running service from its name or server declaration."""
        return self._manager.service(_resource_name(value, Server, "run.server"))

    @overload
    def client(self, value: Tool) -> ConfiguredTool: ...

    @overload
    def client(self, value: Union[str, Client]) -> ConfiguredClient: ...

    def client(self, value: Union[str, Client]) -> ConfiguredClient:
        """Resolve a bound client from its name or client declaration."""
        return self._manager.client(_resource_name(value, Client, "run.client"))

    def artifact(self, value: Union[str, Artifact]) -> MaterializedArtifact:
        """Resolve a captured input from its name or artifact declaration."""
        return self._manager.artifact_store.get(
            _resource_name(value, Artifact, "run.artifact")
        )

    def artifact_text(
        self, value: Union[str, Artifact], *, encoding: str = "utf-8",
        errors: str = "strict",
    ) -> str:
        """Read and decode a named input artifact."""
        return self.artifact(value).read_text(encoding=encoding, errors=errors)

    def artifact_bytes(self, value: Union[str, Artifact]) -> bytes:
        """Read a named input artifact as bytes."""
        return self.artifact(value).read_bytes()

    def artifact_json(
        self, value: Union[str, Artifact], *, encoding: str = "utf-8",
    ) -> object:
        """Decode a materialized input artifact as JSON."""
        return self.artifact(value).read_json(encoding=encoding)

    def artifact_file(self, value: Union[str, Artifact]) -> Path:
        """Compatibility alias for ``artifact_path``."""
        return self.artifact(value).path

    def artifact_path(self, value: Union[str, Artifact]) -> Path:
        """Return the materialized artifact path (preferred explicit spelling)."""
        return self.artifact(value).path

    def open_artifact(
        self, value: Union[str, Artifact], mode: str = "rb", *,
        encoding: Optional[str] = None,
    ) -> IOBase:
        """Open a materialized artifact without manually resolving its path."""
        return self.artifact(value).open(mode, encoding=encoding)

    def binary(self, value: Union[str, Binary]) -> CapturedBinary:
        """Resolve an immutable executable capture by name or declaration."""
        return self._manager.binary_store.get(
            _resource_name(value, Binary, "run.binary")
        )

    def volume(self, value: Union[str, Volume]) -> Path:
        """Resolve a declared volume to its backend-local path."""
        name = _resource_name(value, Volume, "run.volume")
        return self._manager._managed.volumes.get(name).path

    def task(self, value: Union[str, Task]) -> CommandResult:
        """Resolve one completed managed task result."""
        name = _resource_name(value, Task, "run.task")
        try:
            return self._manager._managed.tasks[name].result
        except KeyError:
            raise SpecError(
                "run.task", name,
                "not completed — known: %s" % ", ".join(sorted(self.tasks)),
            ) from None

    def task_output(self, value: Union[str, Task], name: str) -> Path:
        """Resolve a checksum-verified declared task output path."""
        task_name = _resource_name(value, Task, "run.task_output")
        try:
            return self._manager._managed.tasks[task_name].outputs[name].path
        except KeyError:
            known = self._manager._managed.tasks.get(task_name)
            outputs = sorted(known.outputs) if known is not None else ()
            raise SpecError(
                "run.task_output", "%s.%s" % (task_name, name),
                "not available — known outputs: %s" % ", ".join(outputs),
            ) from None

    def credential(self, value: Union[str, Credential]) -> MaterializedCredential:
        """Resolve a role-approved credential by name or declaration."""
        return self._manager.security.credential(
            _resource_name(value, Credential, "run.credential")
        )

    def auth(self, value: Union[str, AuthRecipe]) -> MaterializedAuth:
        """Resolve a materialized authentication stack by name or declaration."""
        return self._manager.security.auth_stack(
            _resource_name(value, AuthRecipe, "run.auth")
        )

    def resolve(self, hostname: str) -> str:
        """Resolve a hostname declared in this case without consulting global DNS."""
        if not isinstance(hostname, str) or not hostname:
            raise SpecError("run.resolve", hostname, "must be a non-empty hostname")
        return self._manager.security.resolve(hostname)

    def reverse(self, address: str) -> str:
        """Resolve a reverse-enabled test address to its declared hostname."""
        if not isinstance(address, str) or not address:
            raise SpecError("run.reverse", address, "must be a non-empty address")
        return self._manager.security.reverse(address)

    def attach(
        self, path: Union[str, Path], **metadata: object,
    ) -> Mapping[str, object]:
        """Archive a file produced inside this run and return its manifest row."""
        return self._manager.evidence.attach(path, **metadata)

    def attach_text(
        self, name: str, text: str, **metadata: object,
    ) -> Mapping[str, object]:
        """Archive generated text as content-addressed output evidence."""
        return self._manager.evidence.attach_text(name, text, **metadata)

    def attach_json(
        self, name: str, value: object, **metadata: object,
    ) -> Mapping[str, object]:
        """Archive a JSON-compatible value as content-addressed evidence."""
        return self._manager.evidence.attach_json(name, value, **metadata)

    def step(self, name: str, **attributes: object) -> object:
        """Create a correlated timing span around a meaningful test action."""
        return self._manager.evidence.spans.span(name, **attributes)
