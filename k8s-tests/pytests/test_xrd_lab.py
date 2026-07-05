"""xrd-lab driver — command plans are pure Python (tests assert on the command
lists directly); a gated live `up` is @e2e. Was xrd_lab_unit + xrd_lab_e2e bats."""
import pytest

from labtools import lab


def _flat(cmds):
    return [" ".join(c) for c in cmds]


def test_up_plan_pins_version_and_nodes():
    assert ["minikube", "start", "--driver=docker", "--nodes=1",
            "--kubernetes-version=v1.31.4"] in lab.plan_up()


def test_up_plan_honors_nodes_override(monkeypatch):
    monkeypatch.setenv("XRD_LAB_NODES", "5")
    assert any("--nodes=5" in arg for arg in lab.plan_up()[0])


def test_deploy_plan_builds_image_and_installs_profile():
    cmds = _flat(lab.plan_deploy("dev"))
    assert any("minikube image build" in c and "brix-smoke:dev" in c for c in cmds)
    assert any("helm upgrade --install brix-dev" in c and "values.dev.yaml" in c
               and "--namespace brix-dev" in c for c in cmds)


def test_images_plan_is_profile_specific():
    assert lab.plan_images("cms")          # needs the server image
    assert lab.plan_images("nonesuch") == []


def test_down_plan_uninstalls_release_and_namespace():
    cmds = _flat(lab.plan_down("dev"))
    assert "helm uninstall brix-dev --namespace brix-dev" in cmds
    assert "kubectl delete namespace brix-dev --ignore-not-found" in cmds


def test_deploy_requires_a_profile():
    assert lab.main(["deploy"]) == 2


def test_unknown_command_returns_error():
    assert lab.main(["frobnicate"]) == 2


@pytest.mark.e2e
def test_up_brings_the_cluster_ready(kube):
    assert lab.main(["up"]) == 0
    assert kube.core.list_namespace()      # API reachable once up
