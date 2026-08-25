"""Kubernetes per-container evidence collection contracts."""

import json
import subprocess
from types import SimpleNamespace

from brixtest import server
from brixtest.errors import CaseRunError
from brixtest.runtime.kubernetes_observation import (
    KubernetesObserver,
    container_records,
)


def _pod_payload():
    return {"items": [{
        "metadata": {"name": "origin-a", "uid": "pod-uid-a"},
        "spec": {
            "nodeName": "minikube",
            "containers": [{"env": [{"name": "SECRET", "value": "do-not-archive"}]}],
        },
        "status": {"containerStatuses": [{
            "name": "origin", "ready": False, "restartCount": 1,
            "image": "registry.test/origin@sha256:" + "a" * 64,
            "imageID": "sha256:" + "b" * 64,
            "containerID": "containerd://" + "c" * 64,
            "state": {"terminated": {
                "reason": "Error", "exitCode": 7, "signal": 0,
                "startedAt": "2026-08-23T00:00:00Z",
                "finishedAt": "2026-08-23T00:00:01Z",
            }},
        }]},
    }]}


class _Evidence:
    def __init__(self):
        self.events = []

    def event(self, name, value):
        self.events.append((name, value))


class _Backend:
    namespace = "brixtest-unit"

    def __init__(self, tmp_path):
        self.evidence = _Evidence()
        self.owner = SimpleNamespace(
            evidence=self.evidence,
            _apply_log_policy=lambda path, policy: None,
        )
        self.calls = []
        self.tmp_path = tmp_path
        self.payload = _pod_payload()

    @staticmethod
    def _workload_selector(name):
        return "app.kubernetes.io/name=%s" % name

    @staticmethod
    def _container_name(_name):
        return "origin"

    def _run(self, *args, timeout=10.0):
        self.calls.append((args, timeout))
        if "get" in args and "pods" in args:
            output = json.dumps(self.payload)
        elif "logs" in args and "--previous=true" in args:
            output = "2026-08-23 previous crash\n"
        elif "logs" in args:
            output = "2026-08-23 current output\n"
        elif "events" in args:
            output = json.dumps({"items": [{"reason": "BackOff"}]})
        else:
            output = "origin-a origin 1m 5Mi\n"
        return subprocess.CompletedProcess(args, 0, output, "")


def test_container_status_records_exclude_pod_spec_and_secret_environment():
    records = container_records(_pod_payload())
    assert records[0]["exit_code"] == 7
    assert records[0]["state"] == "terminated"
    assert records[0]["restart_count"] == 1
    assert "do-not-archive" not in json.dumps(records)


def test_observer_archives_per_container_previous_status_events_and_metrics(tmp_path):
    backend = _Backend(tmp_path)
    declaration = server(
        "origin", command=("/server",),
        image="registry.test/origin@sha256:" + "a" * 64,
    )
    errors = KubernetesObserver(backend).collect(declaration, tmp_path / "logs")
    assert errors == ()
    _assert_observation_files(tmp_path)
    _assert_observation_events(backend.evidence.events)


def _assert_observation_files(tmp_path):
    directory = tmp_path / "logs" / "origin"
    assert (directory / "origin-a.origin.log").read_text().endswith("current output\n")
    assert (directory / "origin-a.origin.previous.log").is_file()
    assert json.loads((directory / "container-status.json").read_text())[0][
        "container_id"
    ].startswith("containerd://")
    assert json.loads((directory / "events.json").read_text())["items"][0][
        "reason"
    ] == "BackOff"
    assert (directory / "resource-metrics.log").read_text().startswith("origin-a")
    aggregate = (tmp_path / "logs" / "origin.log").read_text()
    assert "origin-a/origin" in aggregate and "current output" in aggregate


def _assert_observation_events(events):
    event_names = [name for name, value in events]
    assert "kubernetes-container-status" in event_names
    assert event_names.count("kubernetes-container-log") == 2
    assert "kubernetes-resource-metrics" in event_names


def test_observer_returns_pod_discovery_failure_without_creating_fake_logs(tmp_path):
    backend = _Backend(tmp_path)

    def fail(*args, **kwargs):
        raise CaseRunError("node", "kubernetes", "pod query failed")

    backend._run = fail
    declaration = server("origin", command=("/server",))
    errors = KubernetesObserver(backend).collect(declaration, tmp_path / "logs")
    assert len(errors) == 1 and "pod query failed" in errors[0]
    assert not (tmp_path / "logs" / "origin.log").exists()


def test_grouped_sidecar_observation_archives_only_the_requested_container(tmp_path):
    backend = _Backend(tmp_path)
    payload = _pod_payload()
    statuses = payload["items"][0]["status"]["containerStatuses"]
    statuses.append({**statuses[0], "name": "monitor", "restartCount": 0})
    backend.payload = payload
    backend._workload_selector = lambda _name: "brixtest.io/group=stack"
    backend._container_name = lambda _name: "monitor"
    declaration = server("monitor", command=("/monitor",))
    assert KubernetesObserver(backend).collect(declaration, tmp_path / "logs") == ()
    records = json.loads(
        (tmp_path / "logs" / "monitor" / "container-status.json").read_text()
    )
    assert [item["container"] for item in records] == ["monitor"]
    assert "brixtest.io/group=stack" in str(backend.calls[0])
