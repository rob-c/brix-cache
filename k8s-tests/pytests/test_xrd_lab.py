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


def test_stretch_profiles_build_authority_server_and_client_images():
    """The phase-80 stretch scenarios (s3voms, pbgsi) each need the GSI
    authority (proxies/PKI), the brix server, and the brix client that drives
    xrdcp/xrdfs — but NOT the standalone test-runner image."""
    for profile in ("s3voms", "pbgsi"):
        cmds = _flat(lab.plan_images(profile))
        blob = " ".join(cmds)
        assert "brix-authority:dev" in blob, profile
        assert "brix-server:dev" in blob, profile
        assert "brix-client:dev" in blob, profile
        assert "brix-test-runner" not in blob, profile


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
