"""The BriXTest error taxonomy (design contract C1).

One base, ``BriXTestError``; every exception carries the structured
fields its handler needs, and every message names the subject, the
rule that was violated, and — where one exists — the next command to
run.  A bare ``RuntimeError`` with a string is not an acceptable
failure anywhere in this package.
"""

from __future__ import annotations

from typing import Mapping, Optional, Sequence, Tuple

__all__ = [
    "BrixTestError",
    "BriXTestError",
    "SpecError",
    "RegistrationError",
    "UnknownKindError",
    "StartError",
    "QuiescenceError",
    "ReadinessTimeout",
    "GateViolation",
    "FleetDiedError",
    "ConservationError",
    "LaneOwnershipError",
    "PortCollisionError",
    "PrepStepError",
    "PluginActivationError",
    "WorkerTimeout",
    "WorkerCrash",
    "TemplateError",
    "BackendError",
    "ArtifactNotFound",
    "LogWaitTimeout",
    "WaitTimeout",
    "PortExhaustedError",
    "RunStoreError",
    "CaseRunError",
    "HelperProcessError",
]


class BriXTestError(Exception):
    """Base of the taxonomy; ``details()`` exposes the structured fields."""

    def __init__(self, message: str = "") -> None:
        super().__init__(message)

    def details(self) -> Mapping[str, object]:
        """Return structured, non-private diagnostic fields for reporting."""
        return {
            key: value
            for key, value in vars(self).items()
            if not key.startswith("_")
        }


# Original spelling retained for compatibility with code written before 0.7.
BrixTestError = BriXTestError


class SpecError(BrixTestError):
    """A declaration or API value violated its documented contract."""
    def __init__(self, field: str, value: object, rule: str) -> None:
        self.field = field
        self.value = value
        self.rule = rule
        super().__init__(f"spec field {field}={value!r}: {rule}")


class RegistrationError(BrixTestError):
    def __init__(self, spec: str, conflict: str, what: str):
        self.spec = spec
        self.conflict = conflict
        self.what = what
        super().__init__(
            f"cannot register {spec!r}: {what} conflicts with {conflict!r}"
        )


class UnknownKindError(BrixTestError):
    def __init__(self, kind: str, known: Sequence[str]):
        self.kind = kind
        self.known = tuple(known)
        super().__init__(
            f"unknown kind {kind!r}; registered kinds: {', '.join(self.known) or '(none)'}"
        )


class StartError(BrixTestError):
    def __init__(
        self,
        spec: str,
        phase: str,
        *,
        command: Optional[Sequence[str]] = None,
        returncode: Optional[int] = None,
        log_tail: str = "",
    ):
        self.spec = spec
        self.phase = phase
        self.command = tuple(command) if command else None
        self.returncode = returncode
        self.log_tail = log_tail
        message = f"{spec}: start failed in phase {phase!r}"
        if command:
            message += f" (command: {' '.join(command)}, rc={returncode})"
        if log_tail:
            message += f"\n--- log tail ---\n{log_tail}"
        super().__init__(message)


class QuiescenceError(BrixTestError):
    def __init__(self, survivors: Sequence[Tuple[str, int, int]]):
        self.survivors = tuple(survivors)
        listed = ", ".join(
            f"{name} (port {port}, pid {pid})" for name, port, pid in self.survivors
        )
        super().__init__(
            f"fleet did not go quiescent; survivors: {listed} — "
            "try: brixtest lane status"
        )


class ReadinessTimeout(BrixTestError):
    def __init__(self, spec: str, probe: str, elapsed: float, log_tail: str = ""):
        self.spec = spec
        self.probe = probe
        self.elapsed = elapsed
        self.log_tail = log_tail
        message = (
            f"{spec}: {probe} unanswered after {elapsed:.1f}s"
            " — try: brixtest lane status"
        )
        if log_tail:
            message += f"\n--- log tail ---\n{log_tail}"
        super().__init__(message)


class GateViolation(BrixTestError):
    def __init__(self, test_id: str, undeclared: Sequence[str], channel_hint: str):
        self.test_id = test_id
        self.undeclared = tuple(undeclared)
        self.channel_hint = channel_hint
        super().__init__(
            f"{test_id} uses undeclared server(s): {', '.join(self.undeclared)} — "
            f"{channel_hint}"
        )


class FleetDiedError(BrixTestError):
    def __init__(self, dead_specs: Sequence[str], culprit_test: str, diag_path: str):
        self.dead_specs = tuple(dead_specs)
        self.culprit_test = culprit_test
        self.diag_path = diag_path
        super().__init__(
            f"fleet server(s) died: {', '.join(self.dead_specs)} "
            f"(first confirmed during {culprit_test or 'an unknown test'}); "
            f"see {diag_path}"
        )


class ConservationError(BrixTestError):
    def __init__(self, delta: Mapping[str, object]):
        self.delta = dict(delta)
        super().__init__(f"process conservation violated: {self.delta}")


class LaneOwnershipError(BrixTestError):
    def __init__(self, path: str, owner: Optional[Mapping[str, object]]):
        self.path = path
        self.owner = dict(owner) if owner else None
        who = (
            f"pid {owner.get('pid')} session {owner.get('session')}"
            if owner
            else "an unrecorded owner"
        )
        super().__init__(
            f"refusing to touch {path}: lane is owned by {who} — "
            "try: brixtest lane status"
        )


class PortCollisionError(BrixTestError):
    def __init__(self, port: int, holder_spec: str, foreign_pid: int):
        self.port = port
        self.holder_spec = holder_spec
        self.foreign_pid = foreign_pid
        super().__init__(
            f"port {port} (owned by spec {holder_spec!r}) is held by "
            f"foreign pid {foreign_pid}; choose a non-overlapping port base. "
            "The foreign listener was not modified."
        )


class PrepStepError(BrixTestError):
    def __init__(self, step: str, cause: str):
        self.step = step
        self.cause = cause
        super().__init__(f"prep step {step!r} failed: {cause}")


class PluginActivationError(BrixTestError):
    def __init__(self, registration_paths: Sequence[str]):
        self.registration_paths = tuple(registration_paths)
        super().__init__(
            "brixtest plugin activated more than once via: "
            + ", ".join(self.registration_paths)
        )


class WorkerTimeout(BrixTestError):
    def __init__(self, deadline: float, request_op: str):
        self.deadline = deadline
        self.request_op = request_op
        super().__init__(
            f"client worker did not answer {request_op!r} within {deadline:.1f}s; "
            "the worker was killed"
        )


class WorkerCrash(BrixTestError):
    def __init__(self, returncode: Optional[int], stderr_tail: str):
        self.returncode = returncode
        self.stderr_tail = stderr_tail
        message = f"client worker exited (rc={returncode})"
        if stderr_tail:
            message += f"\n--- stderr tail ---\n{stderr_tail}"
        super().__init__(message)


class TemplateError(BrixTestError):
    """A strict config template retained unresolved placeholders."""
    def __init__(self, template: str, missing_keys: Sequence[str]) -> None:
        self.template = template
        self.missing_keys = tuple(sorted(missing_keys))
        super().__init__(
            f"template {template}: unresolved placeholder(s): "
            + ", ".join(self.missing_keys)
        )


class BackendError(BrixTestError):
    def __init__(self, backend: str, cause: str):
        self.backend = backend
        self.cause = cause
        super().__init__(f"backend {backend!r}: {cause}")


class ArtifactNotFound(BrixTestError):
    def __init__(self, name: str, known: Sequence[str], catalog_path: str):
        self.name = name
        self.known = tuple(sorted(known))
        self.catalog_path = catalog_path
        super().__init__(
            f"artifact {name!r} is not in the catalog ({catalog_path}); "
            f"published names: {', '.join(self.known) or '(none)'} — "
            "try: brixtest artifacts list"
        )


class LogWaitTimeout(BrixTestError):
    def __init__(self, instance: str, pattern: str, waited: float, log_tail: str = ""):
        self.instance = instance
        self.pattern = pattern
        self.waited = waited
        self.log_tail = log_tail
        message = (
            f"{instance}: log never matched {pattern!r} within {waited:.1f}s — "
            f"try: brixtest logs {instance} --tail 40"
        )
        if log_tail:
            message += f"\n--- log tail ---\n{log_tail}"
        super().__init__(message)


class WaitTimeout(BrixTestError):
    def __init__(self, what: str, waited: float, last_state: str = ""):
        self.what = what
        self.waited = waited
        self.last_state = last_state
        message = f"gave up waiting for {what} after {waited:.1f}s"
        if last_state:
            message += f" (last observed: {last_state})"
        super().__init__(message)


class PortExhaustedError(BrixTestError):
    def __init__(self, block_start: int, block_end: int, in_use: int):
        self.block_start = block_start
        self.block_end = block_end
        self.in_use = in_use
        super().__init__(
            f"dynamic port block {block_start}-{block_end} is exhausted "
            f"({in_use} ports in use) — release test-scoped servers or "
            "widen the lane's port_span"
        )


class RunStoreError(BrixTestError):
    def __init__(self, db_path: str, cause: str):
        self.db_path = db_path
        self.cause = cause
        super().__init__(f"run store {db_path}: {cause}")


class CaseRunError(BrixTestError):
    """A managed case failed during setup, execution, or teardown."""
    def __init__(self, nodeid: str, phase: str, cause: str) -> None:
        self.nodeid = nodeid
        self.phase = phase
        self.cause = cause
        super().__init__(f"{nodeid}: case {phase} failed: {cause}")


class HelperProcessError(BrixTestError):
    """The isolated pytest helper timed out or exited unexpectedly."""
    def __init__(
        self, nodeid: str, *, timeout: float = 0.0, returncode: Optional[int] = None,
        output: str = "", run_path: str = "",
    ) -> None:
        self.nodeid = nodeid
        self.timeout = timeout
        self.returncode = returncode
        self.output = output
        self.run_path = run_path
        if timeout:
            cause = "helper exceeded %.1fs and was terminated" % timeout
        else:
            cause = "helper exited with status %s" % returncode
        if run_path:
            cause += "; retained run: %s" % run_path
        super().__init__(f"{nodeid}: {cause}")
