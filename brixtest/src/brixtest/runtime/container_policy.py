"""Shared safety policy for Docker-compatible runtime argument extensions."""

from __future__ import annotations

import re
from typing import Sequence

from brixtest.errors import SpecError

_UNSAFE = {
    "--add-host", "--cap-add", "--cap-drop", "--cgroup-parent", "--cgroupns",
    "--cidfile", "--detach", "--device", "--device-cgroup-rule", "--entrypoint",
    "--env", "--env-file", "--expose", "--group-add", "--hostname", "--ipc",
    "--mount", "--name", "--network", "--pid", "--privileged", "--publish",
    "--restart", "--rm", "--rootfs", "--runtime", "--security-opt", "--tmpfs",
    "--user", "--userns", "--uts", "--volume", "--workdir",
    "-d", "-e", "-h", "-p", "-u", "-v", "-w",
}
_NETWORK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _unsafe_runtime_arg(item: str) -> bool:
    if item in _UNSAFE:
        return True
    if any(item.startswith(prefix + "=") for prefix in _UNSAFE):
        return True
    short = ("-d", "-e", "-h", "-p", "-u", "-v", "-w")
    return any(item.startswith(prefix) and len(item) > len(prefix) for prefix in short)


def validate_runtime_args(value: object, field: str) -> tuple[str, ...]:
    """Return safe argv values or reject options that bypass declarations."""
    selected = _runtime_arguments(value, field)
    _validate_argument_values(selected, value, field)
    _reject_unsafe_arguments(selected, field)
    return selected


def _runtime_arguments(value: object, field: str) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise SpecError(field, value, "must be an argv sequence")
    return tuple(str(item) for item in value)


def _validate_argument_values(
    selected: Sequence[str], original: object, field: str,
) -> None:
    if not all(item and "\x00" not in item for item in selected):
        raise SpecError(field, original, "must contain non-empty NUL-free argv values")


def _reject_unsafe_arguments(selected: Sequence[str], field: str) -> None:
    unsafe = [item for item in selected if _unsafe_runtime_arg(item)]
    if unsafe:
        raise SpecError(
            field, unsafe,
            "cannot override privilege, namespace, mount, or environment boundaries",
        )


def validate_network(value: object, field: str, *, host_only: bool = False) -> str:
    """Validate a declared network without permitting namespace attachment syntax."""
    if not isinstance(value, str) or _NETWORK.fullmatch(value) is None:
        raise SpecError(
            field, value,
            "must be host, none, bridge, or a simple named container network",
        )
    if host_only and value != "host":
        raise SpecError(
            field, value,
            "must be host so allocated loopback ports remain supervised and reachable",
        )
    return value


__all__ = ["validate_network", "validate_runtime_args"]
