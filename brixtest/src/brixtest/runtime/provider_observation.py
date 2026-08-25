"""Structured evidence for Kubernetes provider objects and their workloads."""

from __future__ import annotations

import json
import re
from typing import Mapping, Sequence

from brixtest.errors import CaseRunError, SpecError
from brixtest.runtime.kubernetes_observation import container_records

_SELECTOR = re.compile(r"^[A-Za-z0-9./_-]+=[A-Za-z0-9._-]+(?:,[A-Za-z0-9./_-]+=[A-Za-z0-9._-]+)*$")


def _json_result(backend, *argv: str) -> tuple[object, str]:
    try:
        return json.loads(backend._run(*argv, timeout=15.0).stdout), ""
    except (CaseRunError, TypeError, ValueError) as exc:
        return {}, str(exc)


def _text_result(backend, *argv: str) -> tuple[str, str]:
    try:
        return backend._run(*argv, timeout=15.0).stdout, ""
    except CaseRunError as exc:
        return "", str(exc)


def _container_log(backend, namespace: str, record, previous: bool) -> tuple[str, str]:
    argv = [
        "-n", namespace, "logs", "pod/%s" % record["pod"],
        "-c", str(record["container"]), "--timestamps=true",
        "--limit-bytes=4194304",
    ]
    if previous:
        argv.append("--previous=true")
    return _text_result(backend, *argv)


def _safe(value: object) -> str:
    return "".join(
        char if char.isalnum() or char in ".-_" else "_" for char in str(value)
    )


def _attach_log(backend, owner: str, record, text: str, previous: bool) -> Mapping[str, object]:
    suffix = "-previous" if previous else ""
    name = "provider-%s-%s-%s%s.log" % (
        _safe(owner), _safe(record["pod"]), _safe(record["container"]), suffix,
    )
    return backend.owner.evidence.attach_text(
        name, text, role="provider-log",
        description="provider-managed Kubernetes container log",
    )


def _logs(backend, namespace: str, owner: str, records) -> tuple[list, list]:
    attached, errors = [], []
    for record in records:
        text, error = _container_log(backend, namespace, record, False)
        if error:
            errors.append(error)
        else:
            attached.append(_attach_log(backend, owner, record, text, False))
        if int(record.get("restart_count", 0)):
            previous, previous_error = _container_log(backend, namespace, record, True)
            if previous_error:
                errors.append(previous_error)
            else:
                attached.append(_attach_log(backend, owner, record, previous, True))
    return attached, errors


def _workload_evidence(backend, namespace: str, owner: str, selector: str) -> dict:
    if _SELECTOR.fullmatch(selector) is None:
        raise SpecError("provider pod selector", selector, "must be an exact label selector")
    pods, pod_error = _json_result(
        backend, "-n", namespace, "get", "pods", "-l", selector, "-o", "json",
    )
    records = container_records(pods)
    logs, log_errors = _logs(backend, namespace, owner, records)
    metrics, metrics_error = _text_result(
        backend, "-n", namespace, "top", "pods", "-l", selector,
        "--containers", "--no-headers",
    )
    return {
        "selector": selector, "containers": list(records), "logs": logs,
        "metrics": metrics,
        "errors": [item for item in (pod_error, metrics_error, *log_errors) if item],
    }


def provider_observation(
    backend, identity: Mapping[str, str], resource: Mapping[str, object],
    pod_selector: str = "",
) -> Mapping[str, object]:
    """Collect object status, UID-scoped events, and optional Pod diagnostics."""
    namespace = identity["namespace"]
    events, event_error = _json_result(
        backend, "-n", namespace, "get", "events", "--field-selector",
        "involvedObject.uid=%s" % identity["uid"], "-o", "json",
    )
    result = {
        "identity": dict(identity), "object": dict(resource), "events": events,
        "errors": [event_error] if event_error else [],
    }
    if pod_selector:
        result["workloads"] = _workload_evidence(
            backend, namespace, identity["owner"], pod_selector,
        )
    return result


__all__ = ["provider_observation"]
