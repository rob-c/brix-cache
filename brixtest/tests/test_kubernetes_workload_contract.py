"""Typed lifecycle, stateful workload, and provenance rendering contracts."""

import json
from types import SimpleNamespace

import pytest

from brixtest import (
    CaseManager, Lifecycle, Placement, case, endpoint, mount, server, task, volume,
)
from brixtest.errors import SpecError
from brixtest.fleet.registry import InstanceSpec
from brixtest.runtime.kubernetes_documents import KubernetesDocumentMixin
from brixtest.runtime.kubernetes_groups import compile_grouped_resources
from brixtest.runtime.kubernetes_manifests import server_resources

_IMAGE = "registry.test/server@sha256:" + "a" * 64


def _server(*, lifecycle=None, mounts=()):
    return server(
        "origin", command=("/server",), image=_IMAGE,
        endpoints=(endpoint("primary"),), mounts=mounts,
        lifecycle=Lifecycle() if lifecycle is None else lifecycle,
    )


def _documents(origin, ports=None, **values):
    return server_resources(
        origin, namespace="case", command=("/server",), env={},
        ports={"primary": 18000} if ports is None else ports,
        config_text="", **values,
    )


def _kind_documents(documents, kind):
    return [row for row in documents if row["kind"] == kind]


def _document_named(documents, name):
    return next(row for row in documents if row["metadata"]["name"] == name)


def _document_names(documents):
    return {row["metadata"]["name"] for row in documents}


def test_shutdown_command_renders_as_shell_free_prestop_exec():
    origin = _server(lifecycle=Lifecycle(shutdown_command=("/ctl", "stop", "{config}")))
    documents = _documents(origin, shutdown_command=("/ctl", "stop", "/config/server"))
    deployment = next(row for row in documents if row["kind"] == "Deployment")
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    assert container["lifecycle"] == {
        "preStop": {"exec": {"command": ["/ctl", "stop", "/config/server"]}},
    }


def test_persistent_mount_selects_statefulset_and_preserves_service_endpoint():
    data = volume("data", kind="persistent", access="read-write-many")
    attached = mount(data, "data", read_only=False)
    documents = _documents(
        _server(mounts=(attached,)), managed_volumes=((attached, data),),
    )
    stateful = _kind_documents(documents, "StatefulSet")[0]
    services = _kind_documents(documents, "Service")
    assert stateful["spec"]["serviceName"] == "origin-headless"
    assert _document_names(services) == {"origin", "origin-headless"}
    assert _document_named(services, "origin-headless")["spec"]["clusterIP"] == "None"


class _Evidence:
    def __init__(self):
        self.rows = []

    def event(self, name, value):
        self.rows.append((name, value))


class _Owner:
    def __init__(self):
        self.evidence = _Evidence()


class _Backend(KubernetesDocumentMixin):
    namespace = "case-instance"

    def __init__(self):
        self.owner = _Owner()
        self._workload_kinds = {"origin": "statefulset"}
        self.calls = []

    def _run(self, *args, **kwargs):
        self.calls.append((args, kwargs))


def test_every_applied_document_gets_graph_and_instance_provenance():
    backend = _Backend()
    backend._apply([{
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": "origin", "labels": {"brixtest.io/workload": "origin"}},
    }])
    payload = json.loads(backend.calls[0][1]["input_text"])
    labels = payload["metadata"]["labels"]
    assert labels["brixtest.io/graph-node"] == "server.origin"
    assert labels["brixtest.io/test-instance"] == "case-instance"
    event = backend.owner.evidence.rows[0][1]
    assert (event["graph_node"], event["test_instance"]) == (
        "server.origin", "case-instance",
    )


def test_stateful_controls_target_the_realized_workload_kind():
    backend = _Backend()
    backend.restart("origin")
    assert backend.calls[0][0][-1] == "statefulset/origin"
    assert backend.calls[1][0][4] == "statefulset/origin"


class _GroupBackend:
    def __init__(self, servers, tasks=()):
        definition = SimpleNamespace(servers=servers, tasks=tasks, binaries=())
        self.owner = SimpleNamespace(
            definition=definition,
            _managed=SimpleNamespace(_completed=set()),
        )
        self._workload_kinds = {item.name: "deployment" for item in servers}
        self._task_secure_secret = ""
        self._task_secure_items = ()

    @staticmethod
    def _render_task_command(declaration):
        return tuple(str(item) for item in declaration.command)

    @staticmethod
    def _render_task_environment(declaration):
        return dict(declaration.env)

    @staticmethod
    def _task_identity(_declaration):
        return None


def _group_member(name, group="stack"):
    return server(
        name, command=("/%s" % name,), image=_IMAGE,
        placement=Placement(backend="kubernetes", group=group),
        endpoints=(endpoint("primary"),),
    )


def _group_container_names(workload):
    containers = workload["spec"]["template"]["spec"]["containers"]
    return {item["name"] for item in containers}


def _group_services_use_selector(documents, selector):
    services = [row for row in documents if row["kind"] == "Service"]
    return all(item["spec"]["selector"] == selector for item in services)


def _group_resources(members):
    return {
        item.name: _documents(item, {"primary": 18000 + index})
        for index, item in enumerate(members)
    }


def _group_specs(members):
    return [
        InstanceSpec(item.name, "kubernetes", ports={"primary": 18000 + index})
        for index, item in enumerate(members)
    ]


def _deployment(documents):
    return next(row for row in documents if row["kind"] == "Deployment")


def test_grouped_servers_compile_to_one_multicontainer_workload():
    members = (_group_member("origin"), _group_member("monitor"))
    backend = _GroupBackend(members)
    grouped, launches = compile_grouped_resources(
        backend, members, _group_resources(members), _group_specs(members),
    )
    workload = _deployment(grouped["origin"])
    assert _group_container_names(workload) == {
        "origin", "monitor", "brixtest-filesystem",
    }
    assert _group_services_use_selector(
        grouped["origin"], {"brixtest.io/group": "stack"},
    )
    assert set(grouped) == {"origin"} and [item.name for item in launches] == ["origin"]
    assert backend._workload_names == {"origin": "stack", "monitor": "stack"}


def test_grouped_init_task_becomes_an_ordered_init_container():
    member = _group_member("origin")
    initializer = task(
        "seed", command=("/seed",), phase="init",
        placement=Placement(
            backend="kubernetes", group="stack", image=_IMAGE,
        ),
    )
    backend = _GroupBackend((member,), (initializer,))
    grouped, _launches = compile_grouped_resources(
        backend, (member,), {"origin": _documents(member)},
        [InstanceSpec("origin", "kubernetes", ports={"primary": 18000})],
    )
    workload = next(row for row in grouped["origin"] if row["kind"] == "Deployment")
    init = workload["spec"]["template"]["spec"]["initContainers"]
    assert [(item["name"], item["command"]) for item in init] == [
        ("init-seed", ["/seed"]),
    ]
    assert not any(row["kind"] == "Job" for row in grouped["origin"])


def test_incompatible_group_is_rejected_before_creating_a_run_root(tmp_path):
    members = (
        _group_member("origin"),
        server(
            "monitor", command=("/monitor",), image=_IMAGE, replicas=2,
            placement=Placement(backend="kubernetes", group="stack"),
        ),
    )

    @case(*members, backend="kubernetes", observe=())
    def declared(run):
        pass

    root = tmp_path / "rejected"
    with pytest.raises(SpecError, match="same replicas"):
        CaseManager(declared.__brixtest_case__, "unit::bad-group", root=root)
    assert not root.exists()


def test_group_internal_startup_order_is_rejected_as_unrepresentable(tmp_path):
    origin = _group_member("origin")
    monitor = server(
        "monitor", command=("/monitor",), image=_IMAGE, depends_on=(origin,),
        placement=Placement(backend="kubernetes", group="stack"),
    )

    @case(origin, monitor, backend="kubernetes", observe=())
    def declared(run):
        pass

    with pytest.raises(SpecError, match="start together"):
        CaseManager(
            declared.__brixtest_case__, "unit::ordered-group",
            root=tmp_path / "rejected",
        )
