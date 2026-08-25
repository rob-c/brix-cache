"""Contracts for backend-neutral service replica inspection."""

import json

import pytest

from brixtest import Replica, Service, SpecError
from brixtest.runtime.kubernetes_replicas import replicas_from_pod_list


def _pod(name, uid, address, *, ready=True, restarts=0, deleting=False):
    metadata = {"name": name, "uid": uid}
    if deleting:
        metadata["deletionTimestamp"] = "2026-08-23T00:00:00Z"
    return {
        "metadata": metadata,
        "spec": {"nodeName": "minikube"},
        "status": {
            "podIP": address, "phase": "Running",
            "startTime": "2026-08-23T00:00:00Z", "qosClass": "Burstable",
            "containerStatuses": [{
                "name": "origin", "ready": ready, "restartCount": restarts,
                "image": "example.invalid/origin@sha256:" + "a" * 64,
                "imageID": "sha256:" + "b" * 64,
                "containerID": "containerd://" + "c" * 64,
            }],
        },
    }


def test_replica_exposes_immutable_direct_endpoints_and_json_record():
    replica = Replica(
        "origin-a", "10.244.0.4", {"primary": 8080, "admin": 8081},
        uid="pod-a", phase="Running", ready=True, restarts=2,
        metadata={"containers": [{"name": "origin"}]},
    )
    assert replica.address("admin") == ("10.244.0.4", 8081)
    assert replica.endpoint() == {
        "role": "primary", "host": "10.244.0.4", "port": 8080,
    }
    assert json.loads(json.dumps(replica.as_dict()))["restarts"] == 2
    with pytest.raises(TypeError, match="immutable"):
        replica.metadata["containers"][0]["name"] = "changed"


def test_replica_rejects_invalid_identity_ports_and_status():
    with pytest.raises(SpecError, match="replica.host"):
        Replica("origin", "", {"primary": 8080})
    with pytest.raises(SpecError, match="replica.ports"):
        Replica("origin", "127.0.0.1", {"primary": 0})
    with pytest.raises(SpecError, match="replica.restarts"):
        Replica("origin", "127.0.0.1", {"primary": 8080}, restarts=-1)


def test_kubernetes_pod_list_becomes_ordered_replica_records():
    payload = {"items": [
        _pod("origin-a", "uid-a", "10.244.0.4", restarts=1),
        _pod("origin-b", "uid-b", "10.244.0.5"),
        _pod("origin-old", "uid-old", "10.244.0.3", deleting=True),
    ]}
    replicas = replicas_from_pod_list(
        payload, {"primary": 8080, "http": 8080}, expected=2,
    )
    assert [item.name for item in replicas] == ["origin-a", "origin-b"]
    assert [item.uid for item in replicas] == ["uid-a", "uid-b"]
    assert replicas[0].metadata["node"] == "minikube"
    assert replicas[0].metadata["containers"][0]["image_id"].startswith("sha256:")


def test_kubernetes_replica_discovery_requires_desired_ready_pods():
    payload = {"items": [_pod("origin-a", "uid-a", "10.244.0.4", ready=False)]}
    with pytest.raises(SpecError, match="every desired ready Pod"):
        replicas_from_pod_list(payload, {"primary": 8080}, expected=1)


def test_service_accepts_archived_replica_mappings(tmp_path):
    service = Service(
        "origin", "127.0.0.1", {"primary": 45123},
        tmp_path / "config", tmp_path / "server.log", tmp_path,
        replicas=({
            "name": "origin-a", "host": "10.244.0.4",
            "ports": {"primary": 8080}, "uid": "pod-a", "ready": True,
        },),
    )
    assert isinstance(service.replicas[0], Replica)
    assert service.as_dict()["replicas"][0]["uid"] == "pod-a"


def test_service_rejects_malformed_archived_replica(tmp_path):
    with pytest.raises(SpecError, match="invalid replica record"):
        Service(
            "origin", "127.0.0.1", {"primary": 45123},
            tmp_path / "config", tmp_path / "server.log", tmp_path,
            replicas=({"name": "missing-host"},),
        )
