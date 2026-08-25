"""Translate Kubernetes Pod status into public replica records."""

from __future__ import annotations

from typing import Mapping, Sequence

from brixtest.errors import SpecError
from brixtest.runtime.replica import Replica


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: object) -> Sequence[object]:
    return value if isinstance(value, (tuple, list)) else ()


def _container_statuses(status: Mapping[str, object]) -> list[Mapping[str, object]]:
    return [
        _mapping(item) for item in _sequence(status.get("containerStatuses"))
    ]


def _container_metadata(statuses: Sequence[Mapping[str, object]]) -> tuple[dict, ...]:
    return tuple({
        "name": str(item.get("name", "")),
        "image": str(item.get("image", "")),
        "image_id": str(item.get("imageID", "")),
        "container_id": str(item.get("containerID", "")),
        "ready": item.get("ready") is True,
        "restart_count": int(item.get("restartCount", 0) or 0),
    } for item in statuses)


def _is_live(item: object) -> bool:
    metadata = _mapping(_mapping(item).get("metadata"))
    return not metadata.get("deletionTimestamp")


def _live_items(payload: object) -> tuple[Mapping[str, object], ...]:
    root = _mapping(payload)
    result = []
    for item in _sequence(root.get("items")):
        if _is_live(item):
            result.append(_mapping(item))
    return tuple(result)


def _require_availability(replicas: Sequence[Replica], expected: int) -> None:
    ready = sum(item.ready for item in replicas)
    if len(replicas) >= expected and ready >= expected:
        return
    raise SpecError(
        "Kubernetes replicas", {"expected": expected, "found": len(replicas), "ready": ready},
        "rollout must expose every desired ready Pod",
    )


def _replica(item: Mapping[str, object], ports: Mapping[str, int]) -> Replica:
    metadata = _mapping(item.get("metadata"))
    status = _mapping(item.get("status"))
    spec = _mapping(item.get("spec"))
    statuses = _container_statuses(status)
    name = str(metadata.get("name", ""))
    host = str(status.get("podIP", ""))
    return Replica(
        name=name, uid=str(metadata.get("uid", "")), host=host, ports=ports,
        phase=str(status.get("phase", "unknown")),
        ready=bool(statuses) and all(row.get("ready") is True for row in statuses),
        restarts=sum(int(row.get("restartCount", 0) or 0) for row in statuses),
        started_at=str(status.get("startTime", "")),
        metadata={
            "node": str(spec.get("nodeName", "")),
            "qos_class": str(status.get("qosClass", "")),
            "reason": str(status.get("reason", "")),
            "containers": _container_metadata(statuses),
        },
    )


def replicas_from_pod_list(
    payload: object, ports: Mapping[str, int], *, expected: int,
) -> tuple[Replica, ...]:
    """Parse live, non-terminating Pods and require the desired ready count."""
    replicas = tuple(_replica(item, ports) for item in _live_items(payload))
    _require_availability(replicas, expected)
    return replicas
