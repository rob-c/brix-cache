"""Cluster reuse must not hide a broken cluster or target a different context."""
import json
import subprocess

import pytest

from labtools import lab
from labtools.cluster_health import reusable_cluster


@pytest.fixture
def cluster():
    return {"Name": "lab", "Host": "Running", "Kubelet": "Running",
            "APIServer": "Running", "Kubeconfig": "Configured"}, {
                "valid": [{"Name": "lab", "ActiveKubeContext": True,
                           "Config": {"Driver": "docker", "Nodes": [{}],
                                      "KubernetesConfig": {
                                          "KubernetesVersion": "v1.37.2"}}}]}


def _runner(cluster):
    replies = iter(cluster)

    def run(command, **_kwargs):
        return subprocess.CompletedProcess(command, 0, json.dumps(next(replies)), "")

    return run


def test_matching_healthy_cluster_is_reusable(cluster):
    assert reusable_cluster(_runner(cluster), "docker", "1", "v1.37.2")


def test_unhealthy_api_requires_start(cluster):
    cluster[0]["APIServer"] = "Stopped"
    assert not reusable_cluster(_runner(cluster), "docker", "1", "v1.37.2")


def test_different_kube_context_cannot_be_reused(cluster):
    cluster[1]["valid"][0]["ActiveKubeContext"] = False
    assert not reusable_cluster(_runner(cluster), "docker", "1", "v1.37.2")


@pytest.mark.parametrize("driver,nodes,version", [
    ("podman", "1", "v1.37.2"), ("docker", "2", "v1.37.2"),
    ("docker", "1", "v1.36.0"),
])
def test_changed_settings_require_start(cluster, driver, nodes, version):
    assert not reusable_cluster(_runner(cluster), driver, nodes, version)


@pytest.mark.parametrize("returncode,output", [(1, "{}"), (0, "broken"), (0, "[]")])
def test_failed_or_invalid_status_requires_start(returncode, output):
    def run(command, **_kwargs):
        return subprocess.CompletedProcess(command, returncode, output, "")

    assert not reusable_cluster(run, "docker", "1", "v1.37.2")


def test_up_rechecks_ready_nodes_and_keeps_addons(monkeypatch):
    commands = []
    monkeypatch.setattr(lab, "reusable_cluster", lambda *_args: True)
    monkeypatch.setattr(lab, "_sh", lambda cmd, **_kwargs: commands.append(cmd))
    monkeypatch.delenv("XRD_LAB_DRY_RUN", raising=False)
    assert lab.main(["up"]) == 0
    assert commands == [
        ["kubectl", "wait", "--for=condition=Ready", "nodes", "--all", "--timeout=60s"],
        ["minikube", "addons", "enable", "metrics-server"],
    ]
