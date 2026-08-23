"""Kubernetes secrets, host aliases, and catalogue completeness (091-100)."""

import ast
import base64
import json
from pathlib import Path

import pytest

from brixtest import host_mapping, server, static_config, tcp
from brixtest.errors import SpecError
from brixtest.runtime.kubernetes import secure_secret_resource, server_resources

IMAGE = "example.test/server@sha256:" + "a" * 64


def _server(destination="server.conf"):
    return server(
        "origin", command=["/server", "{config}"],
        config=static_config("server.conf", destination=destination),
        ports=["http"], readiness=tcp("http"), image=IMAGE,
    )


def _resources(**kwargs):
    return server_resources(
        _server(), namespace="brixtest-unit", command=["/server"], env={"B": "2", "A": "1"},
        ports={"http": 18080, "primary": 18080}, config_text="config\n", **kwargs,
    )


def test_091_secure_secret_base64_encodes_file_content(tmp_path):
    secret_file = tmp_path / "secret"
    secret_file.write_text("private")
    document, _ = secure_secret_resource("namespace", {"auth/key": secret_file})
    assert base64.b64decode(document["data"]["file-0000"]) == b"private"


def test_092_secure_secret_projection_has_confined_path_and_mode(tmp_path):
    secret_file = tmp_path / "secret"
    secret_file.write_text("private")
    _, items = secure_secret_resource("namespace", {"auth/token/key": secret_file})
    assert items == [{"key": "file-0000", "path": "auth/token/key", "mode": 0o400}]


def test_093_secure_secret_document_does_not_embed_plaintext(tmp_path):
    secret_file = tmp_path / "secret"
    secret_file.write_text("must-not-appear")
    document, _ = secure_secret_resource("namespace", {"key": secret_file})
    assert "must-not-appear" not in json.dumps(document)


def test_094_deployment_mounts_secure_secret_read_only():
    _, deployment, _ = _resources(
        secure_secret="brixtest-secure",
        secure_items=[{"key": "file-0000", "path": "auth/key", "mode": 0o400}],
    )
    pod = deployment["spec"]["template"]["spec"]
    assert pod["volumes"][1]["secret"]["secretName"] == "brixtest-secure"
    assert pod["containers"][0]["volumeMounts"][1]["readOnly"] is True


def test_095_deployment_environment_is_sorted_for_stability():
    _, deployment, _ = _resources()
    environment = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
    assert [item["name"] for item in environment] == ["A", "B"]


def test_096_kubernetes_host_aliases_include_canonical_and_alias():
    mapping = host_mapping("auth", "auth.test", address="127.0.0.9", aliases=("alias.test",))
    _, deployment, _ = _resources(host_aliases=[mapping])
    aliases = deployment["spec"]["template"]["spec"]["hostAliases"]
    assert aliases == [{"ip": "127.0.0.9", "hostnames": ["auth.test", "alias.test"]}]


def test_097_empty_host_aliases_do_not_change_pod_dns():
    _, deployment, _ = _resources()
    assert "hostAliases" not in deployment["spec"]["template"]["spec"]


def test_098_nested_kubernetes_config_destination_is_rejected():
    with pytest.raises(SpecError, match="basenames"):
        server_resources(
            _server("nested/server.conf"), namespace="unit", command=["/server"], env={},
            ports={"http": 18080, "primary": 18080}, config_text="",
        )


def test_099_minikube_profile_is_docker_driven_and_digest_pinned():
    root = Path(__file__).resolve().parents[2]
    config = json.loads((root / "k8s" / "minikube" / "cluster.json").read_text())
    assert config["driver"] == "docker"
    assert "@sha256:" in config["server_image"]


def test_100_internal_catalogue_contains_exactly_one_hundred_numbered_tests():
    root = Path(__file__).parent
    names = [name for path in sorted(root.glob("test_*.py")) for name in _test_names(path)]
    numbers = sorted(int(name.split("_", 2)[1]) for name in names)
    assert (len(names), numbers) == (100, list(range(1, 101)))


def _test_names(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    return [
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    ]
