"""Persistent storage, rollout, rescheduling, and content snapshot contracts."""

from brixtest import Placement, endpoint, mount, server, volume
from brixtest.metrics import MetricRecorder
from brixtest.runtime.kubernetes_manifests import server_resources
from brixtest.runtime.kubernetes_replicas import replicas_from_pod_list
from brixtest.runtime.manager_operations import CaseManagerOperationsMixin
from brixtest.runtime.replica import Replica
from brixtest.runtime.service import Service

_IMAGE = "registry.test/server@sha256:" + "a" * 64


def _pod(uid: str):
    return {"items": [{
        "metadata": {"name": "origin-0", "uid": uid},
        "spec": {"nodeName": "minikube"},
        "status": {
            "phase": "Running", "podIP": "10.244.0.9",
            "containerStatuses": [{
                "name": "server", "ready": True, "restartCount": 0,
            }],
        },
    }]}


def test_rescheduled_replica_changes_uid_but_keeps_service_ports():
    ports = {"primary": 18000}
    before = replicas_from_pod_list(_pod("uid-before"), ports, expected=1)
    after = replicas_from_pod_list(_pod("uid-after"), ports, expected=1)
    assert before[0].uid != after[0].uid
    assert before[0].ports == after[0].ports == ports


def _kind_rows(documents, kind):
    return [row for row in documents if row["kind"] == kind]


def test_stateful_rerender_preserves_claim_and_headless_identity():
    data = volume("data", kind="persistent", access="read-write-many")
    attached = mount(data, "data", read_only=False)
    origin = server(
        "origin", command=("/server",), image=_IMAGE,
        placement=Placement(backend="kubernetes"),
        endpoints=(endpoint("primary"),), mounts=(attached,),
    )
    arguments = dict(
        namespace="case", command=("/server",), env={},
        ports={"primary": 18000}, config_text="",
        managed_volumes=((attached, data),),
    )
    first = server_resources(origin, **arguments)
    second = server_resources(origin, **arguments)
    claims = _kind_rows(first, "PersistentVolumeClaim")
    stateful = _kind_rows(first, "StatefulSet")[0]
    assert first == second
    assert claims[0]["metadata"]["name"] == "managed-data"
    assert stateful["spec"]["serviceName"] == "origin-headless"


class _Kubernetes:
    def __init__(self):
        self.restarted = []

    def restart(self, name):
        self.restarted.append(name)

    @staticmethod
    def refreshed_replicas(_name):
        return (Replica(
            "origin-0", "127.0.0.1", {"primary": 18000}, uid="uid-after",
            ready=True,
        ),)


class _Manager(CaseManagerOperationsMixin):
    def __init__(self, service):
        self._backend = None
        self._kubernetes = _Kubernetes()
        self._services = {service.name: service}
        self.metrics = MetricRecorder()


def _service(tmp_path):
    config = tmp_path / "origin.conf"
    log = tmp_path / "origin.log"
    config.write_text("ready\n")
    log.write_text("")
    return Service(
        "origin", "127.0.0.1", {"primary": 18000}, config, log, tmp_path,
        replicas=(Replica(
            "origin-0", "127.0.0.1", {"primary": 18000},
            uid="uid-before", ready=True,
        ),),
    )


def test_service_restart_refreshes_public_replica_identity(tmp_path):
    manager = _Manager(_service(tmp_path))
    restarted = manager._service_restart("origin")
    assert manager._kubernetes.restarted == ["origin"]
    assert restarted.replicas[0].uid == "uid-after"
    assert manager._services["origin"] is restarted
