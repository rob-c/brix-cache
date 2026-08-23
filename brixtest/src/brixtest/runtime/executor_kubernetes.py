"""Kubernetes implementation of the tool-executor contract."""

from __future__ import annotations

import dataclasses
import json
import subprocess
import sys
import time
from typing import Mapping, Optional, Sequence

from brixtest.errors import SpecError
from brixtest.resources import Placement
from brixtest.runtime.commands import CommandResult
from brixtest.runtime.executor_support import (
    DIGEST_IMAGE,
    bounded,
    declared_image,
    kubectl,
    pod_name,
    tool_pod,
)
from brixtest.runtime.executors import ToolExecutionContext, ToolExecutionRequest

_DIGEST_IMAGE = DIGEST_IMAGE
_bounded = bounded
_declared_image = declared_image
_kubectl = kubectl
_pod_name = pod_name
_tool_pod = tool_pod


class _KubernetesToolExecutor:
    brixtest_api_version = 1
    brixtest_capabilities = (
        "capture", "credentials", "mounts", "resources", "retries", "service-dns",
    )

    def validate(self, declaration: object) -> None:
        placement = getattr(declaration, "placement", Placement())
        image = _declared_image(declaration)
        if _DIGEST_IMAGE.fullmatch(image) is None:
            raise SpecError(
                "client %s placement.image" % getattr(declaration, "name", "?"),
                image, "Kubernetes tool images must be digest pinned",
            )
        if getattr(declaration, "mode", "capture") == "pty":
            raise SpecError(
                "client %s mode" % getattr(declaration, "name", "?"), "pty",
                "Kubernetes tools support capture or stream mode",
            )
        if placement.namespace and not isinstance(placement.namespace, str):
            raise SpecError("client placement.namespace", placement.namespace, "must be text")
        if placement.resources.pids is not None:
            raise SpecError(
                "client %s placement.resources.pids" % getattr(declaration, "name", "?"),
                placement.resources.pids,
                "Kubernetes has no portable per-container PID limit; use an executor extension",
            )
        if placement.options or placement.allow_mutable_image:
            raise SpecError(
                "client %s placement" % getattr(declaration, "name", "?"), placement,
                "Kubernetes does not consume container runtime options or mutable images",
            )

    def execute(
        self, context: ToolExecutionContext, request: ToolExecutionRequest,
    ) -> CommandResult:
        _validate_execution_request(context, request)
        kubectl = _kubectl_argv(context)
        result = self._execute_attempts(kubectl, context, request)
        _publish_stream(request, result)
        _check_result(request, result)
        return result

    def _execute_attempts(
        self, kubectl: Sequence[str], context: ToolExecutionContext,
        request: ToolExecutionRequest,
    ) -> CommandResult:
        started = time.perf_counter()
        attempts = 0
        result: Optional[CommandResult] = None
        while attempts <= request.retries:
            attempts += 1
            result = self._attempt(kubectl, context, request, attempts, started)
            if result.returncode in request.expected_exit_codes:
                break
        assert result is not None
        return dataclasses.replace(result, attempts=attempts)

    def _attempt(
        self, kubectl: Sequence[str], context: ToolExecutionContext,
        request: ToolExecutionRequest, attempt: int, started: float,
    ) -> CommandResult:
        pod_name = _pod_name(request.name, attempt)
        manifest = _tool_pod(pod_name, context.namespace, request)
        apply = _kubectl(
            kubectl, "apply", "-f", "-", input_text=json.dumps(manifest) + "\n",
            timeout=min(30.0, request.timeout),
        )
        if apply.returncode:
            self._delete_pod(kubectl, context.namespace, pod_name)
            return CommandResult(
                tuple(request.argv), apply.returncode, apply.stdout, apply.stderr,
                time.perf_counter() - started,
            )
        return self._collect_pod_result(kubectl, context, request, pod_name, started)

    def _collect_pod_result(self, kubectl, context, request, pod_name, started):
        try:
            returncode, stderr = self._wait_pod(kubectl, context, request, pod_name)
            logs = _kubectl(
                kubectl, "-n", context.namespace, "logs", "pod/%s" % pod_name,
                timeout=min(30.0, request.timeout),
                output_limit=request.output_limit,
            )
            stdout = logs.stdout
            if logs.returncode and not stderr:
                stderr = logs.stderr
        finally:
            self._delete_pod(kubectl, context.namespace, pod_name)
        stdout, stdout_truncated = _bounded(stdout, request.output_limit)
        stderr, stderr_truncated = _bounded(stderr, request.output_limit)
        return CommandResult(
            tuple(request.argv), returncode, stdout, stderr,
            time.perf_counter() - started, stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        )

    @staticmethod
    def _delete_pod(kubectl: Sequence[str], namespace: str, pod_name: str) -> None:
        _kubectl(
            kubectl, "-n", namespace, "delete", "pod", pod_name,
            "--wait=false", "--ignore-not-found=true", timeout=15.0,
        )

    def _wait_pod(self, kubectl, context, request, pod_name) -> tuple[int, str]:
        deadline = time.monotonic() + request.timeout
        while time.monotonic() < deadline:
            state = _kubectl(
                kubectl, "-n", context.namespace, "get", "pod", pod_name,
                "-o", "json", timeout=min(10.0, request.timeout),
            )
            if state.returncode:
                return 1, state.stderr
            status = self._pod_status(state.stdout)
            phase = status.get("phase", "")
            if phase in ("Succeeded", "Failed"):
                return self._pod_exit_code(status, phase), ""
            time.sleep(0.1)
        return 124, "Kubernetes tool exceeded %.3fs" % request.timeout

    @staticmethod
    def _pod_status(value: str) -> Mapping[str, object]:
        try:
            payload = json.loads(value)
        except ValueError:
            return {}
        status = payload.get("status", {}) if isinstance(payload, Mapping) else {}
        return status if isinstance(status, Mapping) else {}

    @staticmethod
    def _pod_exit_code(status: Mapping[str, object], phase: str) -> int:
        rows = status.get("containerStatuses", [])
        if not isinstance(rows, list) or not rows or not isinstance(rows[0], Mapping):
            return 0 if phase == "Succeeded" else 1
        terminated = rows[0].get("state", {}).get("terminated", {})
        return int(terminated.get("exitCode", 0 if phase == "Succeeded" else 1))


def _validate_execution_request(
    context: ToolExecutionContext, request: ToolExecutionRequest,
) -> None:
    if _DIGEST_IMAGE.fullmatch(request.image) is None:
        raise SpecError(
            "Kubernetes tool image", request.image,
            "must be digest pinned",
        )
    if not context.namespace:
        raise SpecError(
            "Kubernetes tool executor", request.name,
            "requires a Kubernetes case backend namespace",
        )
    if request.input is not None:
        raise SpecError(
            "Kubernetes tool input", request.name,
            "stdin transport is not supported; mount a declared artifact instead",
        )


def _kubectl_argv(context: ToolExecutionContext) -> list[str]:
    argv = [str(context.metadata.get("kubectl", "kubectl"))]
    selected_context = str(context.metadata.get("kubectl_context", ""))
    if selected_context:
        argv.extend(("--context", selected_context))
    return argv


def _publish_stream(request: ToolExecutionRequest, result: CommandResult) -> None:
    if request.mode == "stream":
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)


def _check_result(request: ToolExecutionRequest, result: CommandResult) -> None:
    if request.check and result.returncode not in request.expected_exit_codes:
        raise subprocess.CalledProcessError(
            result.returncode, result.argv, output=result.stdout, stderr=result.stderr,
        )
