"""Executable black-box obligations for current runtime extension seams."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

from brixtest.runtime.api import Run
from brixtest.runtime.commands import CommandResult
from brixtest.runtime.launchers import ServerLaunchPlan


def check_case_backend_contract(
    backend: object, declaration: object, context: object,
) -> list[str]:
    """Exercise the complete v1 case-backend lifecycle on a disposable context."""
    validation = _operation_error("validate", lambda: backend.validate(declaration))
    if validation:
        return validation
    violations = _typed_operation(
        "plan", lambda: backend.plan(context), Mapping, "must return a mapping",
    )
    violations.extend(_operation_error("prepare", lambda: backend.prepare(context)))
    violations.extend(_typed_operation(
        "start", lambda: backend.start(context), Run, "must return brixtest.Run",
    ))
    violations.extend(_operation_error("stop", lambda: backend.stop(context)))
    violations.extend(_typed_operation(
        "collect", lambda: backend.collect(context), Mapping, "must return a mapping",
    ))
    return violations


def _operation_error(label: str, operation) -> list[str]:
    try:
        operation()
    except Exception as exc:
        return ["%s: %s" % (label, exc)]
    return []


def _typed_operation(
    label: str, operation, expected: object, message: str,
) -> list[str]:
    try:
        value = operation()
    except Exception as exc:
        return ["%s: %s" % (label, exc)]
    if not isinstance(value, expected):
        return ["%s: %s" % (label, message)]
    return []


def check_executor_contract(
    executor: object, declaration: object, context: object, request: object,
) -> list[str]:
    """Validate and execute one harmless request through an executor extension."""
    violations = []
    try:
        executor.validate(declaration)
    except Exception as exc:
        return ["validate: %s" % exc]
    try:
        result = executor.execute(context, request)
        if not isinstance(result, CommandResult):
            violations.append("execute: must return brixtest.CommandResult")
    except Exception as exc:
        violations.append("execute: %s" % exc)
    return violations


def check_provider_contract(
    provider: object, declaration: object, destination: Path, context: object,
) -> list[str]:
    """Validate and materialize a provider into a disposable confined path."""
    violations = []
    try:
        provider.validate(declaration)
    except Exception as exc:
        return ["validate: %s" % exc]
    try:
        result = provider.materialize(declaration, destination, context)
        selected = _provider_result(result, destination)
        violations.extend(_provider_path_violations(selected, destination, context))
    except Exception as exc:
        violations.append("materialize: %s" % exc)
    return violations


def _provider_result(result: object, destination: Path) -> Path:
    if isinstance(result, bytes):
        destination.write_bytes(result)
    elif isinstance(result, str):
        destination.write_text(result)
    return Path(result) if isinstance(result, Path) else destination


def _provider_path_violations(selected: Path, destination: Path, context: object) -> list[str]:
    violations = []
    root = Path(getattr(context, "root", destination.parent)).resolve()
    candidate = selected if selected.is_absolute() else root / selected
    try:
        candidate.resolve().relative_to(root)
    except ValueError:
        violations.append("materialize: result escaped its confined root")
    if candidate.is_symlink() or not candidate.is_file():
        violations.append("materialize: must create or return a regular file")
    return violations


def check_launcher_contract(
    launcher: object, declaration: object, context: object, request: object,
) -> list[str]:
    """Validate, prepare, and clean up one disposable server launch plan."""
    violations = []
    try:
        launcher.validate(declaration)
    except Exception as exc:
        return ["validate: %s" % exc]
    plan = None
    try:
        plan = launcher.prepare(context, request)
        if not isinstance(plan, ServerLaunchPlan):
            violations.append("prepare: must return brixtest.ServerLaunchPlan")
        else:
            root = Path(getattr(context, "root", plan.cwd)).resolve()
            try:
                plan.cwd.resolve().relative_to(root)
            except ValueError:
                violations.append("prepare: plan cwd escaped its confined run root")
    except Exception as exc:
        violations.append("prepare: %s" % exc)
    if plan is not None:
        try:
            launcher.cleanup(context, plan)
        except Exception as exc:
            violations.append("cleanup: %s" % exc)
    return violations


__all__ = [
    "check_case_backend_contract", "check_executor_contract", "check_launcher_contract",
    "check_provider_contract",
]
