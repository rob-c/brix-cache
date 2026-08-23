"""Validation primitives for immutable resource declarations."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Mapping, Sequence

from brixtest.errors import SpecError
from brixtest.util.immutable import freeze_mapping

_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")
_PROTOCOLS = ("tcp", "udp")
_COMMAND_MODES = ("capture", "stream", "pty")


def argv(value: Sequence[object], field: str, *, empty: bool = False) -> tuple[object, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise SpecError(field, value, "must be an argv sequence, not shell text")
    result = tuple(value)
    _require_argv_items(result, value, field, empty)
    return result


def _require_argv_items(
    result: tuple[object, ...], original: object, field: str, empty: bool,
) -> None:
    if not empty and not result:
        raise SpecError(field, original, "must contain at least one argv item")
    for part in result:
        _validate_argv_part(part, original, field)


def _validate_argv_part(part: object, original: object, field: str) -> None:
    if isinstance(part, bytes) or not str(part) or "\x00" in str(part):
        raise SpecError(field, original, "argv entries must be non-empty and NUL-free")


def relative(value: str, field: str, *, allow_empty: bool = True) -> str:
    if not isinstance(value, str) or "\x00" in value:
        raise SpecError(field, value, "must be NUL-free text")
    if not value and allow_empty:
        return value
    _require_confined_path(value, field)
    return value


def _require_confined_path(value: str, field: str) -> None:
    path = PurePosixPath(value)
    if path.is_absolute() or value in ("", ".") or ".." in path.parts:
        raise SpecError(field, value, "must be a confined relative path")


def command_policy(output_limit: object, mode: object, retries: object) -> None:
    _validate_output_limit(output_limit)
    _validate_command_mode(mode)
    _validate_retries(retries)


def _validate_output_limit(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise SpecError("command.output_limit", value, "must be an integer >= 1")


def _validate_command_mode(value: object) -> None:
    if value not in _COMMAND_MODES:
        raise SpecError("command.mode", value, "must be capture, stream, or pty")


def _validate_retries(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SpecError("command.retries", value, "must be an integer >= 0")


def endpoint_contract(
    protocol: object, port: object, scheme: object, metadata: object,
) -> Mapping[str, object]:
    _validate_protocol(protocol)
    _validate_port(port)
    _validate_scheme(scheme)
    if not isinstance(metadata, Mapping):
        raise SpecError("endpoint.metadata", metadata, "must be a mapping")
    return freeze_mapping(metadata)


def _validate_protocol(value: object) -> None:
    if value not in _PROTOCOLS:
        raise SpecError("endpoint.protocol", value, "must be tcp or udp")


def _validate_port(value: object) -> None:
    if value is None:
        return
    valid = isinstance(value, int) and not isinstance(value, bool) and 0 < value < 65536
    if not valid:
        raise SpecError("endpoint.port", value, "must be a port from 1 to 65535 or None")


def _validate_scheme(value: object) -> None:
    valid = isinstance(value, str) and (not value or _SCHEME.fullmatch(value) is not None)
    if not valid:
        raise SpecError("endpoint.scheme", value, "must be a valid URI scheme")


def probe_contract(
    kind: str, path: object, command: Sequence[object],
    statuses: Sequence[int], pattern: object,
) -> tuple[tuple[object, ...], tuple[int, ...]]:
    _validate_probe_path(path)
    selected = argv(command, "probe.command", empty=True)
    _validate_exec_command(kind, selected)
    checked_statuses = _probe_statuses(statuses)
    if not isinstance(pattern, str):
        raise SpecError("probe.pattern", pattern, "must be text")
    return selected, checked_statuses


def _validate_probe_path(value: object) -> None:
    if not isinstance(value, str) or not value.startswith("/"):
        raise SpecError("probe.path", value, "must start with /")


def _validate_exec_command(kind: str, selected: tuple[object, ...]) -> None:
    if kind == "exec" and not selected:
        raise SpecError("probe.command", selected, "is required for an exec probe")


def _probe_statuses(values: Sequence[int]) -> tuple[int, ...]:
    statuses = tuple(values)
    if not statuses or not all(_http_status(value) for value in statuses):
        raise SpecError(
            "probe.statuses", statuses,
            "must contain HTTP statuses from 100 to 599",
        )
    return statuses


def _http_status(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 100 <= value <= 599
