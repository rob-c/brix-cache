"""User-facing view of one running server."""

from __future__ import annotations

import dataclasses
import re
import socket
import time
from pathlib import Path
from typing import Dict, Iterator, Mapping, Optional

from brixtest.errors import SpecError
from brixtest.runtime.commands import CommandResult
from brixtest.runtime.filesystem import ServiceFilesystem
from brixtest.util.immutable import freeze_mapping

_URL_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")

def _service_ports(value: object) -> Mapping[str, int]:
    if not isinstance(value, Mapping) or not value:
        raise SpecError("service.ports", value, "must map roles to TCP ports")
    normalized: Dict[str, int] = {}
    for role, port in value.items():
        _validate_service_role(role)
        _validate_service_port(role, port)
        normalized[role] = port
    return freeze_mapping(normalized)


def _validate_service_role(role: object) -> None:
    if not isinstance(role, str) or not role:
        raise SpecError("service port role", role, "must be non-empty text")


def _validate_service_port(role: str, port: object) -> None:
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        raise SpecError("service port %s" % role, port, "must be a TCP port")


def _service_paths(value: "Service") -> None:
    for field in ("config", "log", "workdir"):
        selected = getattr(value, field)
        if not isinstance(selected, (str, Path)) or not str(selected):
            raise SpecError("service.%s" % field, selected, "must be a file-system path")
        object.__setattr__(value, field, Path(selected))


def _service_configs(value: object) -> Mapping[str, Path]:
    if not isinstance(value, Mapping):
        raise SpecError("service.configs", value, "must map destinations to paths")
    if not all(
        isinstance(name, str) and isinstance(path, (str, Path))
        for name, path in value.items()
    ):
        raise SpecError("service.configs", value, "must map destinations to paths")
    return freeze_mapping({name: Path(path) for name, path in value.items()})


def _service_schemes(value: object) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise SpecError("service.schemes", value, "must map endpoint roles to valid URI schemes")
    valid = all(
        isinstance(name, str) and isinstance(scheme, str)
        and (not scheme or _URL_SCHEME.fullmatch(scheme) is not None)
        for name, scheme in value.items()
    )
    if not valid:
        raise SpecError("service.schemes", value, "must map endpoint roles to valid URI schemes")
    return freeze_mapping(value)


def _service_protocols(value: object) -> Mapping[str, str]:
    valid = isinstance(value, Mapping) and all(
        isinstance(name, str) and protocol in ("tcp", "udp")
        for name, protocol in value.items()
    )
    if not valid:
        raise SpecError("service.protocols", value, "must map endpoint roles to tcp or udp")
    return freeze_mapping(value)


def _service_hosts(value: object) -> Mapping[str, str]:
    valid = isinstance(value, Mapping) and all(
        isinstance(role, str) and role and isinstance(host, str) and host
        and "\x00" not in host for role, host in value.items()
    )
    if not valid:
        raise SpecError("service.hosts", value, "must map endpoint roles to host names")
    return freeze_mapping(value)


def _non_empty_text(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _valid_started_at(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, (int, float)) and value >= 0


def _log_chunk(path: Path, cursor: int, encoding: str, errors: str) -> tuple[str, int]:
    try:
        with path.open("r", encoding=encoding, errors=errors) as handle:
            handle.seek(cursor)
            return handle.read(), handle.tell()
    except OSError:
        return "", cursor


def _complete_log_lines(value: str) -> tuple[list[str], str]:
    rows = value.splitlines(keepends=True)
    pending = ""
    if rows and not rows[-1].endswith(("\n", "\r")):
        pending = rows.pop()
    return [row.rstrip("\r\n") for row in rows], pending


def _positive_number(field: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise SpecError(field, value, "must be > 0")


def _url_scheme(value: object) -> str:
    if not isinstance(value, str) or (value and _URL_SCHEME.fullmatch(value) is None):
        raise SpecError("service URL scheme", value, "must be a valid URI scheme")
    return value


def _url_path(value: object) -> str:
    if not isinstance(value, str):
        raise SpecError("service URL path", value, "must be text")
    return value if value.startswith("/") else "/" + value


def _url_host(value: str) -> str:
    if ":" in value and not value.startswith("["):
        return "[%s]" % value
    return value


def _pending_log_rows(pending: str) -> tuple[str, ...]:
    return (pending,) if pending else ()



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
    hosts: Mapping[str, str] = dataclasses.field(default_factory=dict)
    metadata: Mapping[str, object] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if not _non_empty_text(self.name):
            raise SpecError("service.name", self.name, "must be non-empty text")
        if not _non_empty_text(self.host):
            raise SpecError("service.host", self.host, "must be non-empty text")
        if not _non_empty_text(self.scope):
            raise SpecError("service.scope", self.scope, "must be non-empty text")
        if not _valid_started_at(self.started_at):
            raise SpecError("service.started_at", self.started_at, "must be a number >= 0")
        if not isinstance(self.config_artifact, Mapping):
            raise SpecError(
                "service.config_artifact", self.config_artifact, "must be a mapping",
            )
        if not isinstance(self.metadata, Mapping):
            raise SpecError("service.metadata", self.metadata, "must be a mapping")
        object.__setattr__(self, "ports", _service_ports(self.ports))
        _service_paths(self)
        object.__setattr__(self, "config_artifact", freeze_mapping(self.config_artifact))
        object.__setattr__(self, "configs", _service_configs(self.configs))
        object.__setattr__(self, "schemes", _service_schemes(self.schemes))
        object.__setattr__(self, "protocols", _service_protocols(self.protocols))
        object.__setattr__(self, "hosts", _service_hosts(self.hosts))
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
        return self.hosts.get(role, self.host), self.port(role)

    def endpoint(self, role: str = "primary") -> Mapping[str, object]:
        """Return the named endpoint as an immutable address record."""
        return freeze_mapping({
            "role": role, "host": self.hosts.get(role, self.host),
            "port": self.port(role),
            "scheme": self.schemes.get(role, ""),
            "protocol": self.protocols.get(role, "tcp"),
        })

    def url(self, scheme: str = "", *, role: str = "primary", path: str = "/") -> str:
        """Build a URL for a named endpoint role with IPv6-safe host syntax."""
        selected_scheme = _url_scheme(scheme) or self.schemes.get(role, "") or "http"
        return "%s://%s:%d%s" % (
            selected_scheme, _url_host(self.hosts.get(role, self.host)),
            self.port(role), _url_path(path),
        )

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
            _positive_number("service log %s" % field, value)
        cursor = self.log.stat().st_size if self.log.exists() else 0
        deadline = time.monotonic() + timeout
        pending = ""
        while time.monotonic() < deadline:
            chunk, cursor = _log_chunk(self.log, cursor, encoding, errors)
            rows, pending = _complete_log_lines(pending + chunk)
            yield from rows
            time.sleep(min(interval, max(0.0, deadline - time.monotonic())))
        yield from _pending_log_rows(pending)

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
        _positive_number("service readiness timeout", timeout)
        _positive_number("service readiness interval", interval)
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

    @property
    def fs(self) -> ServiceFilesystem:
        """Return confined binary-safe filesystem operations for this service."""
        return self._control("filesystem")(self.name)

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
            "hosts": dict(self.hosts),
            "metadata": dict(self.metadata),
        }
