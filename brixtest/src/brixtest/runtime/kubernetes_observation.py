"""Structured Kubernetes status, logs, events, and resource observations."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Mapping, Sequence

from brixtest.errors import CaseRunError


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: object) -> Sequence[object]:
    return value if isinstance(value, (tuple, list)) else ()


def _state(value: object) -> dict[str, object]:
    states = _mapping(value)
    for phase in ("terminated", "running", "waiting"):
        detail = _mapping(states.get(phase))
        if detail:
            return {
                "state": phase,
                "reason": str(detail.get("reason", "")),
                "exit_code": int(detail.get("exitCode", 0) or 0),
                "signal": int(detail.get("signal", 0) or 0),
                "started_at": str(detail.get("startedAt", "")),
                "finished_at": str(detail.get("finishedAt", "")),
            }
    return {
        "state": "unknown", "reason": "", "exit_code": 0, "signal": 0,
        "started_at": "", "finished_at": "",
    }


def _container(pod: Mapping[str, object], value: object) -> dict[str, object]:
    metadata = _mapping(pod.get("metadata"))
    status = _mapping(value)
    return {
        "pod": str(metadata.get("name", "")),
        "pod_uid": str(metadata.get("uid", "")),
        "container": str(status.get("name", "")),
        "image": str(status.get("image", "")),
        "image_id": str(status.get("imageID", "")),
        "container_id": str(status.get("containerID", "")),
        "ready": status.get("ready") is True,
        "restart_count": int(status.get("restartCount", 0) or 0),
        **_state(status.get("state")),
    }


def container_records(payload: object) -> tuple[dict[str, object], ...]:
    """Return stable secret-free status records from a PodList payload."""
    root = _mapping(payload)
    result = []
    for item in _sequence(root.get("items")):
        pod = _mapping(item)
        status = _mapping(pod.get("status"))
        values = _sequence(status.get("containerStatuses"))
        result.extend(_container(pod, value) for value in values)
    return tuple(sorted(result, key=lambda row: (str(row["pod"]), str(row["container"]))))


def _safe_component(value: str) -> str:
    return "".join(char if char.isalnum() or char in ".-_" else "_" for char in value)


def _log_name(record: Mapping[str, object], suffix: str = "") -> str:
    base = "%s.%s" % (record["pod"], record["container"])
    return _safe_component(base + suffix) + ".log"


def _json_file(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


class KubernetesObserver:
    """Capture bounded diagnostics for server Pods before namespace teardown."""

    def __init__(self, backend) -> None:
        self.backend = backend
        self.owner = backend.owner
        self.target = self._server_target("")

    def _server_target(self, name: str):
        resolver = getattr(self.backend, "_server_target", None)
        if resolver is not None:
            return resolver(name)
        return SimpleNamespace(
            namespace=self.backend.namespace,
            context=getattr(self.backend, "context", ""),
        )

    def _run(self, *args: str, timeout: float = 10.0):
        options = {"timeout": timeout}
        if self.target.context:
            options["context"] = self.target.context
        return self.backend._run(*args, **options)

    def _pod_list(self, server: str) -> object:
        result = self._run(
            "-n", self.target.namespace, "get", "pods", "-l",
            self.backend._workload_selector(server), "-o", "json",
        )
        return json.loads(result.stdout)

    def _log(self, record: Mapping[str, object], *, previous: bool = False) -> str:
        args = [
            "-n", self.target.namespace, "logs", "pod/%s" % record["pod"],
            "-c", str(record["container"]), "--timestamps=true",
        ]
        if previous:
            args.append("--previous=true")
        return self._run(*args).stdout

    def _write_log(
        self, directory: Path, record: Mapping[str, object], *, previous: bool = False,
    ) -> Path:
        suffix = ".previous" if previous else ""
        path = directory / _log_name(record, suffix)
        path.write_text(self._log(record, previous=previous))
        return path

    def _record_log(self, server: str, record: Mapping[str, object], path: Path) -> None:
        self.owner.evidence.event("kubernetes-container-log", {
            "server": server, "pod": record["pod"],
            "pod_uid": record["pod_uid"], "container": record["container"],
            "path": str(path), "previous": ".previous.log" in path.name,
        })

    def _collect_logs(
        self, server: str, directory: Path, records: Sequence[Mapping[str, object]],
    ) -> tuple[list[str], list[str]]:
        combined = []
        errors = []
        for record in records:
            try:
                path = self._write_log(directory, record)
                self._record_log(server, record, path)
                combined.append("== %s/%s ==\n%s" % (
                    record["pod"], record["container"], path.read_text(),
                ))
            except CaseRunError as exc:
                errors.append(str(exc))
            self._collect_previous(server, directory, record)
        return combined, errors

    def _collect_previous(
        self, server: str, directory: Path, record: Mapping[str, object],
    ) -> None:
        if not int(record.get("restart_count", 0)):
            return
        try:
            path = self._write_log(directory, record, previous=True)
            self._record_log(server, record, path)
        except CaseRunError as exc:
            self.owner.evidence.event("kubernetes-previous-log-unavailable", {
                "server": server, "pod": record["pod"],
                "container": record["container"], "error": str(exc),
            })

    def _optional_json(self, directory: Path, name: str, *args: str) -> None:
        try:
            result = self._run(*args)
            _json_file(directory / name, json.loads(result.stdout))
        except (CaseRunError, TypeError, ValueError) as exc:
            self.owner.evidence.event("kubernetes-observation-unavailable", {
                "name": name, "error": str(exc),
            })

    def _optional_metrics(self, directory: Path, server: str) -> None:
        try:
            result = self._run(
                "-n", self.target.namespace, "top", "pods", "-l",
                self.backend._workload_selector(server),
                "--containers", "--no-headers", timeout=15.0,
            )
            (directory / "resource-metrics.log").write_text(result.stdout)
            self.owner.evidence.event("kubernetes-resource-metrics", {
                "server": server, "text": result.stdout,
            })
        except CaseRunError as exc:
            self.owner.evidence.event("kubernetes-resource-metrics-unavailable", {
                "server": server, "error": str(exc),
            })

    def collect(self, server, log_dir: Path) -> tuple[str, ...]:
        """Capture one server's per-container and aggregate diagnostics."""
        self.target = self._server_target(server.name)
        directory = log_dir / server.name
        directory.mkdir(parents=True, exist_ok=True)
        try:
            records = self._server_container_records(server.name)
        except (CaseRunError, TypeError, ValueError) as exc:
            return (str(exc),)
        _json_file(directory / "container-status.json", records)
        self._record_container_statuses(server.name, records)
        combined, errors = self._collect_logs(server.name, directory, records)
        aggregate = log_dir / (server.name + ".log")
        aggregate.write_text("\n".join(combined))
        self._apply_server_log_policy(directory, aggregate, server.logs)
        self._optional_json(
            directory, "events.json", "-n", self.target.namespace, "get", "events",
            "--field-selector", "involvedObject.kind=Pod", "-o", "json",
        )
        self._optional_metrics(directory, server.name)
        return tuple(errors)

    def _server_container_records(self, name: str) -> tuple[dict, ...]:
        records = container_records(self._pod_list(name))
        container = self.backend._container_name(name)
        if container == "server":
            return records
        return tuple(record for record in records if record["container"] == container)

    def _record_container_statuses(self, name: str, records) -> None:
        for record in records:
            self.owner.evidence.event("kubernetes-container-status", {
                "server": name, **record,
            })

    def _apply_server_log_policy(self, directory: Path, aggregate: Path, policy) -> None:
        for path in (*directory.glob("*.log"), aggregate):
            self.owner._apply_log_policy(path, policy)
