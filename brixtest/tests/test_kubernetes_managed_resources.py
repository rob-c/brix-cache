"""Kubernetes rendering and lifecycle contracts for managed resources."""

import subprocess

import pytest

from brixtest import (
    Lifecycle,
    Placement,
    ResourceLimits,
    case,
    endpoint,
    identity,
    mount,
    server,
    task,
    volume,
)
from brixtest.errors import SpecError
from brixtest.planning import compile_case, validate_capabilities
from brixtest.pytest_runtime import _cleanup_timed_out_kubernetes
from brixtest.runtime.kubernetes import KubernetesCaseManager
from brixtest.runtime.kubernetes_manifests import server_resources
from brixtest.runtime.kubernetes_ownership import read_ownership, write_ownership
from brixtest.runtime.kubernetes_tasks import task_resources
from brixtest.runtime.manager import CaseManager


def _definition(*resources, **options):
    @case(*resources, observe=(), **options)
    def declared(run):
        return None

    return declared.__brixtest_case__


def _by(rows, key, value):
    return next(row for row in rows if row[key] == value)


def _nss_config(documents):
    return next(
        document for document in documents
        if document["kind"] == "ConfigMap" and document["metadata"]["name"].endswith("-nss")
    )


def _nss_mount_paths(container):
    return {
        item["mountPath"] for item in container["volumeMounts"]
        if item["name"] == "identity-nss"
    }


def _kubernetes_server(*, mounts=(), replicas=1):
    return server(
        "origin", command=("/server",), mounts=mounts, replicas=replicas,
        image="registry.test/server@sha256:" + "a" * 64,
        endpoints=(endpoint("primary"),),
    )


def _documents_by_kind(documents):
    return {document["kind"]: document for document in documents}


def _mount_paths(container):
    return {row["mountPath"] for row in container["volumeMounts"]}


def test_kubernetes_renders_replicas_and_managed_persistent_volume():
    data = volume(
        "data", kind="persistent", size=8 << 20,
        access="read-write-many", options={"storage_class": "standard"},
    )
    mounted = mount(data, "data", read_only=False)
    origin = _kubernetes_server(mounts=(mounted,), replicas=3)
    documents = server_resources(
        origin, namespace="case", command=("/server",), env={},
        ports={"primary": 18000}, config_text="",
        managed_volumes=((mounted, data),),
    )
    by_kind = _documents_by_kind(documents)
    assert by_kind["StatefulSet"]["spec"]["replicas"] == 3
    assert by_kind["StatefulSet"]["spec"]["serviceName"] == "origin-headless"
    claim = by_kind["PersistentVolumeClaim"]
    assert claim["spec"]["accessModes"] == ["ReadWriteMany"]
    assert claim["spec"]["resources"]["requests"]["storage"] == str(8 << 20)
    assert claim["spec"]["storageClassName"] == "standard"
    container = by_kind["StatefulSet"]["spec"]["template"]["spec"]["containers"][0]
    assert "/brixtest/mounts/data" in _mount_paths(container)


def test_kubernetes_tmp_volume_quota_uses_empty_dir_size_limit():
    scratch = volume("scratch", size=4096)
    mounted = mount(scratch, "scratch", read_only=False)
    documents = server_resources(
        _kubernetes_server(mounts=(mounted,)), namespace="case",
        command=("/server",), env={}, ports={"primary": 18000}, config_text="",
        managed_volumes=((mounted, scratch),),
    )
    deployment = _by(documents, "kind", "Deployment")
    volumes = deployment["spec"]["template"]["spec"]["volumes"]
    selected = _by(volumes, "name", "managed-scratch")
    assert selected["emptyDir"]["sizeLimit"] == "4096"


def test_kubernetes_rejects_relative_host_volume_path():
    host = volume("host", kind="host", source="relative")
    mounted = mount(host, "host", read_only=False)
    with pytest.raises(SpecError, match="absolute node path"):
        server_resources(
            _kubernetes_server(mounts=(mounted,)), namespace="case",
            command=("/server",), env={}, ports={"primary": 18000},
            config_text="", managed_volumes=((mounted, host),),
        )


def test_kubernetes_device_volume_uses_typed_host_device_and_propagation():
    fuse = volume("fuse", kind="device", source="/dev/fuse")
    mounted = mount(
        fuse, "fuse", read_only=False, propagation="host-to-container",
    )
    documents = server_resources(
        _kubernetes_server(mounts=(mounted,)), namespace="case",
        command=("/server",), env={}, ports={"primary": 18000},
        config_text="", managed_volumes=((mounted, fuse),),
    )
    deployment = _by(documents, "kind", "Deployment")
    pod = deployment["spec"]["template"]["spec"]
    assert _by(pod["volumes"], "name", "managed-fuse") == {
        "name": "managed-fuse",
        "hostPath": {"path": "/dev/fuse", "type": "CharDevice"},
    }
    assert _by(pod["containers"][0]["volumeMounts"], "name", "managed-fuse") == {
        "name": "managed-fuse", "mountPath": "/brixtest/mounts/fuse",
        "readOnly": False, "mountPropagation": "HostToContainer",
    }


def test_kubernetes_rejects_relative_device_volume_path():
    device = volume("fuse", kind="device", source="relative-device")
    mounted = mount(device, "fuse")
    with pytest.raises(SpecError, match="absolute node path"):
        server_resources(
            _kubernetes_server(mounts=(mounted,)), namespace="case",
            command=("/server",), env={}, ports={"primary": 18000},
            config_text="", managed_volumes=((mounted, device),),
        )


def test_kubernetes_rejects_unknown_volume_options_before_mutation(tmp_path):
    scratch = volume("scratch", options={"storage_class": "ignored"})
    root = tmp_path / "run"
    with pytest.raises(SpecError, match="known for this Kubernetes volume: none"):
        CaseManager(
            _definition(scratch, backend="kubernetes"),
            "kubernetes::volume-options", root=root,
        )
    assert not root.exists()


def test_kubernetes_identity_renders_service_account_rbac_and_posix_context():
    runner = identity(
        "runner", uid=1001, gid=1002, groups=(1003,),
        capabilities=("net-bind-service",),
        permissions={"pods": ("get", "list"), "apps:deployments": ("get",)},
    )
    origin = server(
        "origin", command=("/server",),
        image="registry.test/server@sha256:" + "a" * 64,
        placement=Placement(identity=runner),
    )
    documents = server_resources(
        origin, namespace="case", command=("/server",), env={},
        ports={"primary": 18000}, config_text="", identity=runner,
    )
    assert _by(documents, "kind", "ServiceAccount")["metadata"]["name"] == "brixtest-runner"
    assert _by(documents, "kind", "RoleBinding")["roleRef"]["name"] == "brixtest-runner-role"
    assert _by(documents, "kind", "Role")["rules"] == [
        {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["get"]},
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]},
    ]
    pod = _by(documents, "kind", "Deployment")["spec"]["template"]["spec"]
    assert pod["serviceAccountName"] == "brixtest-runner"
    assert pod["securityContext"] == {
        "runAsUser": 1001, "runAsGroup": 1002, "supplementalGroups": [1003],
    }
    security = pod["containers"][0]["securityContext"]
    assert security["capabilities"]["add"] == ["NET_BIND_SERVICE"]
    nss = _nss_config(documents)
    assert "brixtest_runner:x:1001:1002:" in nss["data"]["passwd"]
    assert _nss_mount_paths(pod["containers"][0]) == {"/etc/passwd", "/etc/group"}


def test_kubernetes_user_namespace_fails_during_capability_planning():
    runner = identity("runner", user_namespace=True, uid_map=((0, 100000, 65536),))
    origin = server(
        "origin", command=("/server",), placement=Placement(identity=runner),
        image="registry.test/server@sha256:" + "a" * 64,
    )
    graph = compile_case(_definition(runner, origin, backend="kubernetes"))
    with pytest.raises(SpecError, match="identity.userns"):
        validate_capabilities(graph.nodes)


def test_kubernetes_declared_network_policy_limits_egress_to_dependencies():
    database = server(
        "database", command=("/database",),
        image="registry.test/database@sha256:" + "b" * 64,
        endpoints=(endpoint("db", port=15432),),
    )
    origin = server(
        "origin", command=("/server",), depends_on=(database,),
        image="registry.test/server@sha256:" + "a" * 64,
    )
    peers = {
        "origin": (origin, {"primary": 18000}),
        "database": (database, {"db": 15432, "primary": 15432}),
    }
    documents = server_resources(
        origin, namespace="case", command=("/server",), env={},
        ports={"primary": 18000}, config_text="", peers=peers,
        render_network_policy=True,
    )
    policy = next(row for row in documents if row["kind"] == "NetworkPolicy")
    dependency = policy["spec"]["egress"][0]
    assert dependency["to"][0]["podSelector"]["matchLabels"] == {
        "app.kubernetes.io/name": "database",
    }
    assert dependency["ports"] == [{"port": 15432, "protocol": "TCP"}]


def test_kubernetes_network_ingress_is_derived_from_endpoint_exposure():
    origin = server(
        "origin", command=("/server",),
        image="registry.test/server@sha256:" + "a" * 64,
        endpoints=(
            endpoint("private", port=18000, exposure="case"),
            endpoint("public", port=18001, exposure="external"),
        ),
    )
    documents = server_resources(
        origin, namespace="case", command=("/server",), env={},
        ports={"private": 18000, "public": 18001, "primary": 18000},
        config_text="", render_network_policy=True,
    )
    ingress = next(row for row in documents if row["kind"] == "NetworkPolicy")["spec"]["ingress"]
    assert ingress[0]["from"][0]["podSelector"]["matchLabels"] == {
        "brixtest.io/case": "case",
    }
    assert "from" not in ingress[1]


def test_kubernetes_isolated_network_policy_is_default_deny():
    origin = server(
        "origin", command=("/server",),
        image="registry.test/server@sha256:" + "a" * 64,
        placement=Placement(network_policy="isolated"),
    )
    documents = server_resources(
        origin, namespace="case", command=("/server",), env={},
        ports={"primary": 18000}, config_text="", render_network_policy=True,
    )
    policy = next(row for row in documents if row["kind"] == "NetworkPolicy")
    assert policy["spec"]["ingress"] == []
    assert policy["spec"]["egress"] == []


def test_kubernetes_teardown_refuses_replaced_namespace(tmp_path):
    owner = type("Owner", (), {
        "definition": _definition(), "root": tmp_path / "run",
        "nodeid": "kubernetes::ownership", "kubernetes_context": "",
    })()
    backend = object.__new__(KubernetesCaseManager)
    backend.owner = owner
    backend.namespace = "brixtest-unit"
    backend._namespace_created = True
    backend._namespace_uid = "owned-uid"
    backend._forwards = {}
    backend._run = lambda *args, **kwargs: subprocess.CompletedProcess(
        args, 0, '{"metadata":{"uid":"replacement-uid"}}', "",
    )
    errors = backend._delete_namespace()
    assert errors and "refusing to delete" in errors[0]
    assert backend._namespace_created is True


def test_timeout_cleanup_deletes_only_the_recorded_namespace_uid(tmp_path, monkeypatch):
    run_root = tmp_path / "run"
    write_ownership(run_root, "brixtest-owned", "owned-uid")
    calls = []

    def execute(argv, **kwargs):
        calls.append(tuple(argv))
        return subprocess.CompletedProcess(
            argv, 0, '{"metadata":{"uid":"replacement-uid"}}', "",
        )

    monkeypatch.setattr("brixtest.pytest_runtime.subprocess.run", execute)
    definition = _definition(backend="kubernetes")
    _cleanup_timed_out_kubernetes(definition, run_root)
    assert len(calls) == 1 and "get" in calls[0]
    assert read_ownership(run_root)["uid"] == "owned-uid"


def test_kubernetes_task_renders_bounded_non_retrying_job():
    runner = identity("runner", permissions={"pods": ("get",)})
    prepare = task(
        "prepare", command=("/bin/prepare",), timeout=12,
        placement=Placement(
            backend="kubernetes", identity=runner,
            image="registry.test/tasks@sha256:" + "c" * 64,
        ),
        env={"MODE": "test"},
    )
    documents = task_resources(
        prepare, namespace="case", command=("/bin/prepare",),
        env={"MODE": "test"}, identity=runner,
    )
    by_kind = {row["kind"]: row for row in documents}
    assert {"ServiceAccount", "Role", "RoleBinding", "Job"} == set(by_kind)
    spec = by_kind["Job"]["spec"]
    assert spec["backoffLimit"] == 0
    assert spec["activeDeadlineSeconds"] == 12
    pod = spec["template"]["spec"]
    assert pod["restartPolicy"] == "Never"
    assert pod["serviceAccountName"] == "brixtest-runner"
    assert pod["containers"][0]["env"] == [{"name": "MODE", "value": "test"}]


def test_kubernetes_server_renders_workspace_cwd_and_shutdown_deadline():
    origin = server(
        "origin", command=("/server",), image="registry.test/server@sha256:" + "a" * 64,
        cwd="instance", lifecycle=Lifecycle(stop_timeout=13),
    )
    documents = server_resources(
        origin, namespace="case", command=("/server",), env={},
        ports={"primary": 18000}, config_text="",
    )
    pod = _by(documents, "kind", "Deployment")["spec"]["template"]["spec"]
    assert pod["terminationGracePeriodSeconds"] == 13
    assert pod["containers"][0]["workingDir"] == "/brixtest/workspace/instance"
    assert _by(pod["volumes"], "name", "workspace")["emptyDir"] == {}


@pytest.mark.parametrize("origin,pattern", [
    (
        server(
            "origin", command=("/server",), image="registry.test/server@sha256:" + "a" * 64,
            lifecycle=Lifecycle(shutdown_signal="INT"),
        ),
        "background=True",
    ),
    (
        server(
            "origin", command=("/server",), image="registry.test/server@sha256:" + "a" * 64,
            placement=Placement(resources=ResourceLimits(pids=10)),
        ),
        "PID limit",
    ),
    (
        server(
            "origin", command=("/server",), image="registry.test/server@sha256:" + "a" * 64,
            placement=Placement(options={"runtime_args": ("--bad",)}),
        ),
        "runtime options",
    ),
])
def test_kubernetes_rejects_untranslated_server_policy_before_mutation(
    tmp_path, origin, pattern,
):
    root = tmp_path / "run"
    with pytest.raises(SpecError, match=pattern):
        CaseManager(_definition(origin, backend="kubernetes"), "k8s::policy", root=root)
    assert not root.exists()


def test_kubernetes_task_renders_declared_labels():
    prepare = task(
        "prepare", command=("/prepare",),
        placement=Placement(
            backend="kubernetes", image="registry.test/tasks@sha256:" + "c" * 64,
            labels={"suite": "auth"},
        ),
    )
    job = _by(task_resources(
        prepare, namespace="case", command=("/prepare",), env={},
    ), "kind", "Job")
    assert job["metadata"]["labels"]["suite"] == "auth"
    assert job["spec"]["template"]["metadata"]["labels"]["suite"] == "auth"


def test_kubernetes_task_rejects_untranslated_placement_before_mutation(tmp_path):
    prepare = task(
        "prepare", command=("/prepare",),
        placement=Placement(
            backend="kubernetes", image="registry.test/tasks@sha256:" + "c" * 64,
            options={"runtime_args": ("--privileged",)},
        ),
    )
    root = tmp_path / "run"
    with pytest.raises(SpecError, match="do not consume runtime options"):
        CaseManager(_definition(prepare, backend="kubernetes"), "k8s::task-policy", root=root)
    assert not root.exists()


def test_kubernetes_task_requires_digest_pinned_image():
    prepare = task(
        "prepare", command=("/bin/prepare",),
        placement=Placement(backend="kubernetes", image="tasks:latest"),
    )
    with pytest.raises(SpecError, match="digest-pinned"):
        task_resources(
            prepare, namespace="case", command=("/bin/prepare",), env={},
        )


def test_kubernetes_rejects_unimplemented_task_outputs_before_mutation(tmp_path):
    prepare = task(
        "prepare", command=("/bin/prepare",), outputs={"result": "result"},
        placement=Placement(
            backend="kubernetes",
            image="registry.test/tasks@sha256:" + "c" * 64,
        ),
    )
    root = tmp_path / "run"
    with pytest.raises(SpecError, match="provider-backed volume"):
        CaseManager(
            _definition(prepare, backend="kubernetes"),
            "kubernetes::task-output", root=root,
        )
    assert not root.exists()


def test_kubernetes_task_phases_follow_declared_dependencies(tmp_path):
    first = task(
        "first", command=("/first",),
        placement=Placement(
            backend="kubernetes", image="registry.test/tasks@sha256:" + "c" * 64,
        ),
    )
    second = task(
        "second", command=("/second",), depends_on=(first,),
        placement=Placement(
            backend="kubernetes", image="registry.test/tasks@sha256:" + "c" * 64,
        ),
    )
    completed = set()
    owner = type("Owner", (), {
        "definition": _definition(second, first, backend="kubernetes"),
        "_managed": type("Managed", (), {"_completed": completed})(),
    })()
    backend = object.__new__(KubernetesCaseManager)
    backend.owner = owner
    observed = []

    def execute(declaration):
        observed.append(declaration.name)
        completed.add(declaration.name)

    backend._run_task = execute
    backend.run_task_phase("prepare")
    assert observed == ["first", "second"]
