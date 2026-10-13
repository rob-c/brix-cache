"""Result shaping helpers for object-linked C unit runners."""

from __future__ import annotations

from cmdscripts.compile_run import result


def missing_objects(spec) -> list[str]:
    """Return every required object that is absent from the active build."""
    return [str(path) for path in spec.required if not path.is_file()]


def compile_failure(name, completed) -> list[tuple[bool, str]]:
    """Convert a failed compiler invocation into the command result contract."""
    detail = (completed.stderr or completed.stdout)[-3000:]
    return [result(False, f"compile {name} failed: {detail}")]


def run_result(completed, name) -> list[tuple[bool, str]]:
    """Convert a completed unit binary into the command result contract."""
    detail = (completed.stderr or completed.stdout)[-3000:]
    return [result(completed.returncode == 0,
                   f"{name} exited {completed.returncode}: {detail}")]
