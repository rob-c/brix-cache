"""Multi-environment Kubernetes routing and ownership contracts."""

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from brixtest import CaseManager, Placement, case, client, endpoint, environment, server
from brixtest.errors import SpecError
from brixtest.runtime.kubernetes_documents import KubernetesDocumentMixin
from brixtest.runtime.kubernetes_environment_resources import (
    KubernetesEnvironmentResourcesMixin,
)
from brixtest.runtime.kubernetes_environments import KubernetesEnvironmentLayout
from brixtest.runtime.kubernetes_manifests import server_resources

_IMAGE = "registry.test/server@sha256:" + "a" * 64


def _definition(*resources):
    @case(*resources, backend="kubernetes", observe=())
    def declared(run):
        return None

    return declared.__brixtest_case__


def _layout(tmp_path: Path):
    east = environment("east", backend="kubernetes", namespace="front")
    west = environment("west", backend="kubernetes", namespace="back")
    origin = server(
        "origin", command=("/server",), image=_IMAGE,
        placement=Placement(environment=east),
    )
    monitor = server(
        "monitor", command=("/monitor",), image=_IMAGE,
        placement=Placement(environment=west),
    )
    owner = SimpleNamespace(
        root=tmp_path / "Attempt_ABC", definition=_definition(east, west, origin, monitor),
    )
    return KubernetesEnvironmentLayout(owner, "minikube")


def test_layout_resolves_stable_context_namespaces_and_service_dns(tmp_path):
    layout = _layout(tmp_path)
    east = layout.for_server("origin")
    west = layout.for_server("monitor")
    assert east.context == west.context == "minikube"
    assert east.namespace.startswith("front-") and west.namespace.startswith("back-")
    assert east.namespace != west.namespace
    assert layout.server_dns("origin") == "origin.%s.svc.cluster.local" % east.namespace
    assert {(item.context, item.namespace) for item in layout.targets} >= {
        (east.context, east.namespace), (west.context, west.namespace),
    }
    assert layout.has_resource(east, "server")
    assert not layout.has_resource(east, "client")


def test_cross_namespace_policy_selects_the_owned_case_namespace(tmp_path):
    layout = _layout(tmp_path)
    upstream = server(
        "origin", command=("/server",), image=_IMAGE,
        endpoints=(endpoint("primary"),),
    )
    downstream = server(
        "monitor", command=("/monitor",), image=_IMAGE, depends_on=(upstream,),
        endpoints=(endpoint("primary"),),
    )
    peers = {"origin": (upstream, {"primary": 18000}, layout.for_server("origin").namespace)}
    documents = server_resources(
        downstream, namespace=layout.for_server("monitor").namespace,
        command=("/monitor",), env={}, ports={"primary": 18100}, config_text="",
        peers=peers, render_network_policy=True, test_instance=layout.test_instance,
    )
    policy = next(item for item in documents if item["kind"] == "NetworkPolicy")
    destination = policy["spec"]["egress"][0]["to"][0]
    assert destination["podSelector"]["matchLabels"] == {
        "app.kubernetes.io/name": "origin",
    }
    assert destination["namespaceSelector"]["matchLabels"] == {
        "brixtest.io/test-instance": layout.test_instance,
    }


class _ControlBackend(KubernetesDocumentMixin):
    namespace = "legacy"

    def __init__(self, layout):
        self.environments = layout
        self._workload_kinds = {"origin": "deployment"}
        self.calls = []

    def _run(self, *args, **options):
        self.calls.append((args, options))


def test_server_controls_route_through_its_environment_context(tmp_path):
    backend = _ControlBackend(_layout(tmp_path))
    backend.signal("origin", "HUP")
    argv, options = backend.calls[0]
    target = backend.environments.for_server("origin")
    assert argv[:2] == ("-n", target.namespace)
    assert options["context"] == target.context


class _OwnershipBackend(KubernetesEnvironmentResourcesMixin):
    def __init__(self, layout):
        self.environments = layout
        self.namespace = layout.default.namespace
        self.context = layout.default.context
        self._namespace_created = True
        self._namespace_uids = {
            (item.context, item.namespace): "uid-%d" % index
            for index, item in enumerate(layout.targets)
        }
        self.deleted = []

    def _run(self, *args, context="", **_options):
        if args[0] == "get":
            target = next(
                item for item in self.environments.targets
                if item.namespace == args[2] and item.context == context
            )
            uid = self._namespace_uids[(target.context, target.namespace)]
            return subprocess.CompletedProcess(args, 0, json.dumps({
                "metadata": {"uid": uid},
            }), "")
        self.deleted.append((context, args[2]))
        return subprocess.CompletedProcess(args, 0, "", "")


def test_teardown_uid_checks_and_deletes_every_owned_environment(tmp_path):
    backend = _OwnershipBackend(_layout(tmp_path))
    assert backend._delete_environment_namespaces() == []
    assert set(backend.deleted) == {
        (item.context, item.namespace) for item in backend.environments.targets
    }
    assert backend._namespace_created is False


def test_role_secrets_are_not_copied_to_an_environment_without_a_consumer(tmp_path):
    server_file = tmp_path / "server.key"
    client_file = tmp_path / "client.token"
    server_file.write_text("server-only")
    client_file.write_text("client-only")
    target = SimpleNamespace(namespace="server-space", context="cluster")
    backend = object.__new__(KubernetesEnvironmentResourcesMixin)
    backend._client_secure_secret = "client-secret"
    backend.environments = SimpleNamespace(
        has_resource=lambda _target, kind: kind == "server",
    )
    applied = []
    backend._apply = lambda documents, **options: applied.extend(documents)
    backend._project_environment_secrets(
        target, {"auth/server.key": server_file}, "server-secret", (),
        {"auth/client.token": client_file},
    )
    assert [item["metadata"]["name"] for item in applied] == ["server-secret"]


def test_named_client_environment_requires_remote_executor_before_mutation(tmp_path):
    realm = environment("remote", backend="kubernetes")
    tool = client(
        "reader", command=("true",), placement=Placement(environment=realm),
    )
    root = tmp_path / "must-not-exist"
    with pytest.raises(SpecError, match="backend='kubernetes'"):
        CaseManager(_definition(realm, tool), "unit::environment", root=root)
    assert not root.exists()


def test_cross_context_dependency_is_rejected_before_mutation(tmp_path):
    east = environment("east", context="one")
    west = environment("west", context="two")
    upstream = server(
        "upstream", command=("/server",), image=_IMAGE,
        placement=Placement(environment=east),
    )
    downstream = server(
        "downstream", command=("/server",), image=_IMAGE, depends_on=(upstream,),
        placement=Placement(environment=west),
    )
    root = tmp_path / "must-not-exist"
    with pytest.raises(SpecError, match="managed transport"):
        CaseManager(
            _definition(east, west, upstream, downstream),
            "unit::cross-context", root=root,
        )
    assert not root.exists()


def test_independent_servers_may_select_different_kubernetes_contexts(tmp_path):
    east = environment("east", context="one")
    west = environment("west", context="two")
    servers = (
        server(
            "east_server", command=("/server",), image=_IMAGE,
            placement=Placement(environment=east),
        ),
        server(
            "west_server", command=("/server",), image=_IMAGE,
            placement=Placement(environment=west),
        ),
    )
    manager = CaseManager(
        _definition(east, west, *servers), "unit::multiple-contexts",
        root=tmp_path / "not-created",
    )
    layout = KubernetesEnvironmentLayout(manager, "default")
    assert {layout.for_server(item.name).context for item in servers} == {"one", "two"}
    assert not manager.root.exists()
