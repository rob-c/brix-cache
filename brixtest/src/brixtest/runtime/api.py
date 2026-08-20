"""Small user-facing runtime values kept separate from orchestration internals."""

from __future__ import annotations

import dataclasses
import re
import socket
import time
import warnings
from io import IOBase
from pathlib import Path
from typing import Any, Dict, Iterator, Mapping, Optional, Sequence, Union, overload

from brixtest.auth.models import AuthRecipe
from brixtest.auth.store import MaterializedAuth
from brixtest.clients.configured import ConfiguredClient, ConfiguredTool
from brixtest.credentials import Credential, MaterializedCredential
from brixtest.design import Artifact, Binary, Client, Server, Tool
from brixtest.errors import SpecError
from brixtest.runtime.artifacts import MaterializedArtifact
from brixtest.runtime.binaries import CapturedBinary
from brixtest.runtime.commands import CommandResult
from brixtest.resources import Command, Reference
from brixtest.util.immutable import freeze_mapping

__all__ = ["Run", "Service"]

_URL_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")


def _resource_name(value: object, expected: type, field: str) -> str:
    if isinstance(value, expected):
        return value.name
    if not isinstance(value, str) or not value:
        raise SpecError(field, value, "must be a resource name or declaration")
    return value


@dataclasses.dataclass(frozen=True)
class Service:
    """Backend-neutral address and diagnostics for one running server."""

    name: str
    host: str
    ports: Mapping[str, int]
    config: Path
    log: Path
    workdir: Path
    instance_id: str = ""
    scope: str = "case"
    started_at: float = 0.0
    pool_id: str = ""
    config_filename: str = ""
    config_sha256: str = ""
    config_source_sha256: str = ""
    config_declared_sha256: str = ""
    config_artifact: Mapping[str, object] = dataclasses.field(default_factory=dict)
    configs: Mapping[str, Path] = dataclasses.field(default_factory=dict)
    schemes: Mapping[str, str] = dataclasses.field(default_factory=dict)
    protocols: Mapping[str, str] = dataclasses.field(default_factory=dict)
    metadata: Mapping[str, object] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise SpecError("service.name", self.name, "must be non-empty text")
        if not isinstance(self.host, str) or not self.host:
            raise SpecError("service.host", self.host, "must be non-empty text")
        if not isinstance(self.ports, Mapping) or not self.ports:
            raise SpecError("service.ports", self.ports, "must map roles to TCP ports")
        normalized: Dict[str, int] = {}
        for role, port in self.ports.items():
            if not isinstance(role, str) or not role:
                raise SpecError("service port role", role, "must be non-empty text")
            if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
                raise SpecError("service port %s" % role, port, "must be a TCP port")
            normalized[role] = port
        if not isinstance(self.config_artifact, Mapping):
            raise SpecError(
                "service.config_artifact", self.config_artifact, "must be a mapping",
            )
        for field in ("config", "log", "workdir"):
            value = getattr(self, field)
            if not isinstance(value, (str, Path)) or not str(value):
                raise SpecError("service.%s" % field, value, "must be a file-system path")
        if not isinstance(self.scope, str) or not self.scope:
            raise SpecError("service.scope", self.scope, "must be non-empty text")
        if (
            isinstance(self.started_at, bool)
            or not isinstance(self.started_at, (int, float))
            or self.started_at < 0
        ):
            raise SpecError("service.started_at", self.started_at, "must be a number >= 0")
        object.__setattr__(self, "ports", freeze_mapping(normalized))
        object.__setattr__(self, "config", Path(self.config))
        object.__setattr__(self, "log", Path(self.log))
        object.__setattr__(self, "workdir", Path(self.workdir))
        object.__setattr__(self, "config_artifact", freeze_mapping(self.config_artifact))
        if not isinstance(self.configs, Mapping) or not all(
            isinstance(name, str) and isinstance(path, (str, Path))
            for name, path in self.configs.items()
        ):
            raise SpecError("service.configs", self.configs, "must map destinations to paths")
        object.__setattr__(
            self, "configs", freeze_mapping({name: Path(path) for name, path in self.configs.items()})
        )
        if not isinstance(self.schemes, Mapping) or not all(
            isinstance(name, str) and isinstance(scheme, str)
            and (not scheme or _URL_SCHEME.fullmatch(scheme) is not None)
            for name, scheme in self.schemes.items()
        ):
            raise SpecError(
                "service.schemes", self.schemes,
                "must map endpoint roles to valid URI schemes",
            )
        object.__setattr__(self, "schemes", freeze_mapping(self.schemes))
        if not isinstance(self.protocols, Mapping) or not all(
            isinstance(name, str) and protocol in ("tcp", "udp")
            for name, protocol in self.protocols.items()
        ):
            raise SpecError(
                "service.protocols", self.protocols,
                "must map endpoint roles to tcp or udp",
            )
        object.__setattr__(self, "protocols", freeze_mapping(self.protocols))
        if not isinstance(self.metadata, Mapping):
            raise SpecError("service.metadata", self.metadata, "must be a mapping")
        object.__setattr__(self, "metadata", freeze_mapping(self.metadata))

    def port(self, role: str = "primary") -> int:
        """Return one named TCP port, listing valid roles on lookup failure."""
        if not isinstance(role, str) or not role:
            raise SpecError("port role", role, "must be non-empty text")
        try:
            return self.ports[role]
        except KeyError:
            raise SpecError(
                "port role", role,
                "%r declares: %s" % (self.name, ", ".join(sorted(self.ports))),
            ) from None

    def address(self, role: str = "primary") -> tuple[str, int]:
        """Return the backend-neutral ``(host, port)`` endpoint for a role."""
        return self.host, self.port(role)

    def endpoint(self, role: str = "primary") -> Mapping[str, object]:
        """Return the named endpoint as an immutable address record."""
        return freeze_mapping({
            "role": role, "host": self.host, "port": self.port(role),
            "scheme": self.schemes.get(role, ""),
            "protocol": self.protocols.get(role, "tcp"),
        })

    def url(self, scheme: str = "", *, role: str = "primary", path: str = "/") -> str:
        """Build a URL for a named endpoint role with IPv6-safe host syntax."""
        if not isinstance(scheme, str) or (
            scheme and _URL_SCHEME.fullmatch(scheme) is None
        ):
            raise SpecError("service URL scheme", scheme, "must be a valid URI scheme")
        if not isinstance(path, str):
            raise SpecError("service URL path", path, "must be text")
        if not path.startswith("/"):
            path = "/" + path
        host = "[%s]" % self.host if ":" in self.host and not self.host.startswith("[") else self.host
        selected_scheme = scheme or self.schemes.get(role, "") or "http"
        return "%s://%s:%d%s" % (selected_scheme, host, self.port(role), path)

    def read_config(
        self, destination: str = "", *, encoding: str = "utf-8", errors: str = "strict",
    ) -> str:
        """Read the exact captured config used to launch this instance."""
        path = self.config
        if destination:
            try:
                path = self.configs[destination]
            except KeyError:
                raise SpecError(
                    "service config", destination,
                    "known: %s" % ", ".join(sorted(self.configs)),
                ) from None
        return path.read_text(encoding=encoding, errors=errors)

    def read_log(self, *, encoding: str = "utf-8", errors: str = "replace") -> str:
        """Read the server log accumulated so far."""
        return self.log.read_text(encoding=encoding, errors=errors)

    def tail_log(
        self, lines: int = 40, *, encoding: str = "utf-8", errors: str = "replace",
    ) -> str:
        """Return a bounded diagnostic tail from the correlated server log."""
        if isinstance(lines, bool) or not isinstance(lines, int) or lines < 0:
            raise SpecError("service log lines", lines, "must be an integer >= 0")
        if lines == 0:
            return ""
        return "\n".join(
            self.read_log(encoding=encoding, errors=errors).splitlines()[-lines:]
        )

    def follow_log(
        self, *, timeout: float = 5.0, interval: float = 0.1,
        encoding: str = "utf-8", errors: str = "replace",
    ) -> Iterator[str]:
        """Yield newly appended log lines for a strictly bounded duration."""
        for field, value in (("timeout", timeout), ("interval", interval)):
            if (
                isinstance(value, bool) or not isinstance(value, (int, float))
                or value <= 0
            ):
                raise SpecError("service log %s" % field, value, "must be > 0")
        cursor = self.log.stat().st_size if self.log.exists() else 0
        deadline = time.monotonic() + timeout
        pending = ""
        while time.monotonic() < deadline:
            try:
                with self.log.open("r", encoding=encoding, errors=errors) as handle:
                    handle.seek(cursor)
                    chunk = handle.read()
                    cursor = handle.tell()
            except OSError:
                chunk = ""
            if chunk:
                pending += chunk
                rows = pending.splitlines(keepends=True)
                pending = ""
                if rows and not rows[-1].endswith(("\n", "\r")):
                    pending = rows.pop()
                for row in rows:
                    yield row.rstrip("\r\n")
            time.sleep(min(interval, max(0.0, deadline - time.monotonic())))
        if pending:
            yield pending

    def is_ready(self, role: str = "primary", *, timeout: float = 0.2) -> bool:
        """Return whether a TCP endpoint accepts a connection within ``timeout``."""
        if self.protocols.get(role, "tcp") != "tcp":
            raise SpecError("service readiness role", role, "must name a TCP endpoint")
        if (
            isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or timeout <= 0
        ):
            raise SpecError("service readiness timeout", timeout, "must be > 0")
        try:
            with socket.create_connection(self.address(role), timeout=timeout):
                return True
        except OSError:
            return False

    def wait_ready(
        self, role: str = "primary", *, timeout: float = 10.0,
        interval: float = 0.1,
    ) -> "Service":
        """Wait for readiness with a deadline and return this service."""
        if (
            isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or timeout <= 0
        ):
            raise SpecError("service readiness timeout", timeout, "must be > 0")
        if (
            isinstance(interval, bool) or not isinstance(interval, (int, float))
            or interval <= 0
        ):
            raise SpecError("service readiness interval", interval, "must be > 0")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.is_ready(role, timeout=min(interval, 0.5)):
                return self
            time.sleep(min(interval, max(0.0, deadline - time.monotonic())))
        raise TimeoutError(
            "%s endpoint %s did not become ready within %.3fs"
            % (self.name, role, timeout)
        )

    def _control(self, operation: str):
        controller = getattr(self, "_controller", None)
        method = getattr(controller, "_service_%s" % operation, None)
        if not callable(method):
            raise SpecError(
                "service control", self.name,
                "%s is unavailable for a detached Service value" % operation,
            )
        return method

    def signal(self, signal_name: str = "TERM") -> None:
        """Send a validated signal through the owning backend."""
        if signal_name not in ("TERM", "INT", "QUIT", "KILL", "HUP", "USR1", "USR2"):
            raise SpecError("service signal", signal_name, "has an unknown signal name")
        self._control("signal")(self.name, signal_name)

    def restart(self) -> "Service":
        """Restart from the captured immutable plan and return the new value."""
        return self._control("restart")(self.name)

    def wait(self, *, timeout: float = 0.0) -> Optional[int]:
        """Wait at most ``timeout`` seconds for a local/container server exit."""
        return self._control("wait")(self.name, timeout)

    def command(
        self, *argv: object, timeout: float = 30.0, check: bool = True,
    ) -> CommandResult:
        """Run a bounded shell-free diagnostic command in this environment."""
        return self._control("command")(
            self.name, argv, timeout=timeout, check=check,
        )

    def as_dict(self) -> Dict[str, object]:
        """Return a JSON-safe endpoint and provenance record."""
        return {
            "name": self.name, "host": self.host, "ports": dict(self.ports),
            "config": str(self.config), "log": str(self.log),
            "workdir": str(self.workdir), "instance_id": self.instance_id,
            "scope": self.scope, "started_at": self.started_at,
            "pool_id": self.pool_id, "config_filename": self.config_filename,
            "config_sha256": self.config_sha256,
            "config_source_sha256": self.config_source_sha256,
            "config_declared_sha256": self.config_declared_sha256,
            "config_artifact": dict(self.config_artifact),
            "configs": {name: str(path) for name, path in self.configs.items()},
            "schemes": dict(self.schemes), "protocols": dict(self.protocols),
            "metadata": dict(self.metadata),
        }


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
        }

    def command(
        self, *argv: object, check: bool = True, timeout: Optional[float] = None,
        input: Optional[str] = None, env: Optional[Mapping[str, object]] = None,
        cwd: Optional[Union[str, Path]] = None,
        encoding: str = "utf-8", expected_exit_codes: tuple[int, ...] = (0,),
        output_limit: int = 1 << 20, mode: str = "capture", retries: int = 0,
    ) -> CommandResult:
        """Run shell-free argv with captured UTF-8 stdout/stderr and durable logs."""
        renderer = getattr(self._manager, "_render_value", None)
        render = (
            (lambda value, label: renderer(value, label=label))
            if callable(renderer) else (lambda value, label: str(value))
        )
        rendered_argv = tuple(render(value, "run.command argv") for value in argv)
        if env is not None and (
            not isinstance(env, Mapping) or not all(
                isinstance(key, str) and isinstance(value, (str, Reference))
                for key, value in env.items()
            )
        ):
            raise SpecError(
                "run.command env", env,
                "must map strings to strings or typed references",
            )
        rendered_env = {
            key: render(value, "run.command env[%s]" % key)
            for key, value in (env or {}).items()
        }
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
        if isinstance(declaration, str):
            bound = self._manager.client(declaration)
        elif isinstance(declaration, Client):
            bound = self._manager.client(declaration.name)
        else:
            raise SpecError(
                "run.tool", declaration, "must be a tool name or Tool declaration",
            )
        if args or env is not None or cwd is not None or not check:
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
