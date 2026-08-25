"""Error and security-negative contracts for the public declaration surface."""

import json
import subprocess
from pathlib import Path

import pytest

from brixtest import MB, binary, case, noise, server, static_config, tcp, template_config
from brixtest.errors import SpecError
from brixtest.runtime.kubernetes import KubernetesCaseManager, server_resources
from brixtest.runtime.manager import CaseManager


def test_success_noise_declaration_supports_exact_100mb_inputs():
    payload = noise("large_random", size=100 * MB, seed=41)
    assert payload.size == 100_000_000
    assert payload.kind == "noise"


def test_error_readiness_must_name_a_declared_port():
    item = server(
        "origin", command=["server"], config=static_config("origin.conf"),
        ports=["http"], readiness=tcp("admin"),
    )
    with pytest.raises(SpecError, match=r"readiness\.port"):
        from brixtest import case
        case(servers=[item])


def test_security_negative_config_destination_cannot_escape_run_root():
    with pytest.raises(SpecError, match="confined relative path"):
        static_config("origin.conf", destination="../../host.conf")


def test_kubernetes_manifest_uses_same_server_declaration():
    executable = binary(
        "origin_bin", image="registry.example/origin@sha256:" + "a" * 64,
        image_path="/opt/origin/bin/server",
    )
    item = server(
        "origin", command=[executable, "--config", "{config}"],
        config=static_config("origin.conf"), ports=["http"],
        readiness=tcp("http"),
    )
    config_map, deployment, service_doc = server_resources(
        item, namespace="brixtest-contract", command=["/opt/origin/bin/server"],
        env={}, ports={"http": 18080, "primary": 18080}, config_text="ok\n",
    )
    assert config_map["kind"] == "ConfigMap"
    assert deployment["spec"]["template"]["spec"]["containers"][0]["image"].endswith("a" * 64)
    assert service_doc["spec"]["ports"][0]["port"] == 18080


def test_kubernetes_security_negative_rejects_mutable_image_tags():
    item = server(
        "origin", command=["/server"], config=static_config(Path("origin.conf")),
        ports=["http"], readiness=tcp("http"), image="example/origin:latest",
    )
    with pytest.raises(SpecError, match="immutable image digest"):
        server_resources(
            item, namespace="brixtest-contract", command=["/server"], env={},
            ports={"http": 18080, "primary": 18080}, config_text="ok\n",
        )


def test_kubernetes_backend_preserves_the_run_api(tmp_path, monkeypatch):
    executable = binary(
        "origin_bin", image="registry.example/origin@sha256:" + "b" * 64,
        image_path="/opt/origin/bin/server",
    )
    origin = server(
        "origin", command=[executable, "--config", "{config}"],
        config=template_config("../configs/servers/echo.json.in"),
        ports=["http"], readiness=tcp("http"),
    )

    @case(servers=[origin], binaries=[executable], backend="kubernetes", keep="always")
    def declared_case(run):
        pass

    calls = []

    def fake_run(self, *args, **kwargs):
        calls.append(args)
        if args[:2] == ("get", "namespace"):
            return subprocess.CompletedProcess(
                args, 0, stdout='{"metadata":{"uid":"unit-namespace-uid"}}', stderr="",
            )
        if "get" in args and "pods" in args:
            return subprocess.CompletedProcess(args, 0, stdout=json.dumps({"items": [{
                "metadata": {"name": "origin-unit", "uid": "unit-pod-uid"},
                "spec": {"nodeName": "minikube"},
                "status": {
                    "podIP": "10.244.0.10", "phase": "Running",
                    "containerStatuses": [{"name": "origin", "ready": True}],
                },
            }]}), stderr="")
        return subprocess.CompletedProcess(args, 0, stdout="pod log\n", stderr="")

    monkeypatch.setattr("brixtest.runtime.kubernetes.shutil.which", lambda value: value)
    monkeypatch.setattr(KubernetesCaseManager, "_run", fake_run)
    monkeypatch.setattr(
        KubernetesCaseManager, "_forward",
        lambda self, declaration, remote: {"http": 45123},
    )
    monkeypatch.setattr(KubernetesCaseManager, "_wait_ready", lambda *args: None)

    definition = declared_case.__brixtest_case__
    manager = CaseManager(definition, "test_kubernetes", root=tmp_path / "run")
    run = manager.start()
    assert run.backend == "kubernetes"
    assert run.server(origin).url(role="http") == "http://127.0.0.1:45123/"
    assert run.server(origin).replicas[0].host == "10.244.0.10"
    manager.set_outcome("passed")
    manager.close()
    assert any("apply" in call for call in calls)
    assert any("delete" in call for call in calls)
