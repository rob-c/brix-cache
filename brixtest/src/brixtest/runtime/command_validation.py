"""Validation for shell-free command requests and captured results."""

from __future__ import annotations

import math
import os
from typing import Mapping, Optional, Sequence, Union

from brixtest.errors import SpecError


def result_argv(value: object) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)):
        raise SpecError("command result argv", value, "must be non-empty, NUL-free text")
    argv = tuple(value)
    valid = bool(argv) and all(_valid_argv_part(part) for part in argv)
    if not valid:
        raise SpecError("command result argv", value, "must be non-empty, NUL-free text")
    return argv


def _valid_argv_part(part: object) -> bool:
    return isinstance(part, str) and bool(part) and "\x00" not in part


def result_elapsed(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SpecError("command result elapsed_seconds", value, "must be a finite number >= 0")
    elapsed = float(value)
    if not math.isfinite(elapsed) or elapsed < 0:
        raise SpecError("command result elapsed_seconds", value, "must be a finite number >= 0")
    return elapsed


def validate_result(value: object) -> tuple[tuple[str, ...], float]:
    argv = result_argv(value.argv)
    _validate_returncode(value.returncode)
    _validate_output(value.stdout, value.stderr)
    elapsed = result_elapsed(value.elapsed_seconds)
    _validate_attempts(value.attempts)
    _validate_truncation(value.stdout_truncated, value.stderr_truncated)
    return argv, elapsed


def _validate_returncode(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SpecError("command result returncode", value, "must be an integer")


def _validate_output(stdout: object, stderr: object) -> None:
    if not isinstance(stdout, str) or not isinstance(stderr, str):
        raise SpecError("command result output", type(stdout).__name__, "must be text")


def _validate_attempts(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise SpecError("command result attempts", value, "must be an integer >= 1")


def _validate_truncation(stdout: object, stderr: object) -> None:
    if not isinstance(stdout, bool) or not isinstance(stderr, bool):
        raise SpecError("command result truncation", stdout, "flags must be boolean")


def command_environment(value: Optional[Mapping[str, str]]) -> Mapping[str, str]:
    valid = value is None or (
        isinstance(value, Mapping)
        and all(_environment_item(key, item) for key, item in value.items())
    )
    if not valid:
        raise SpecError("run.command env", value, "must map strings to strings")
    environment = dict(os.environ)
    environment.update(dict(value or {}))
    return environment


def _environment_item(key: object, value: object) -> bool:
    return isinstance(key, str) and isinstance(value, str)


def command_expected(
    input_value: Optional[Union[str, bytes]], encoding: str,
    expected_exit_codes: Sequence[int],
) -> tuple[int, ...]:
    _validate_input(input_value)
    _validate_encoding(encoding)
    expected = tuple(expected_exit_codes)
    if not expected or not all(_exit_code(value) for value in expected):
        raise SpecError("run.command expected_exit_codes", expected, "must contain integers")
    return expected


def _validate_input(value: object) -> None:
    if value is not None and not isinstance(value, (str, bytes)):
        raise SpecError("run.command input", type(value).__name__, "must be text or bytes")


def _validate_encoding(value: object) -> None:
    if not isinstance(value, str) or not value:
        raise SpecError("run.command encoding", value, "must be non-empty text")


def _exit_code(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def validate_command_limits(
    timeout: Optional[float], output_limit: int, mode: str, retries: int,
) -> None:
    _validate_timeout(timeout)
    _validate_output_limit(output_limit)
    _validate_mode(mode)
    _validate_retries(retries)


def _validate_timeout(value: Optional[float]) -> None:
    if value is None:
        return
    valid = not isinstance(value, bool) and isinstance(value, (int, float)) and value > 0
    if not valid:
        raise SpecError("run.command timeout", value, "must be > 0")


def _validate_output_limit(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise SpecError("run.command output_limit", value, "must be an integer >= 1")


def _validate_mode(value: object) -> None:
    if value not in ("capture", "stream", "pty"):
        raise SpecError("run.command mode", value, "must be capture, stream, or pty")


def _validate_retries(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SpecError("run.command retries", value, "must be an integer >= 0")
