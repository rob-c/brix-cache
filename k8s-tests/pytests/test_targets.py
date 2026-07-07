"""OS target and Ceph Docker gate planning.

These are fast, always-on checks: they do not start Docker/minikube, but they
make the AlmaLinux/CentOS target matrix and official Ceph gates part of the
k8s lab contract.
"""
import pytest

from labtools import ceph_docker, lab, targets


def _flat(cmds):
    return [" ".join(c) for c in cmds]


def test_default_target_is_alma9():
    t = targets.current("alma9")
    assert t.base_image == "almalinux:9"
    assert not t.enable_ceph_sig


def test_centos9_stream_target_enables_storage_sig():
    t = targets.current("centos9-stream")
    args = targets.build_args(t)
    assert t.base_image == "quay.io/centos/centos:stream9"
    assert t.enable_ceph_sig
    assert "BRIX_ENABLE_CEPH_SIG=1" in args
    assert "BRIX_CEPH_SIG_RELEASE=tentacle" in args


def test_unknown_target_is_rejected():
    with pytest.raises(KeyError):
        targets.current("solaris-2.6")


def test_lab_image_plan_carries_centos_target(monkeypatch):
    monkeypatch.setenv("XRD_LAB_OS_TARGET", "centos9-stream")
    cmds = _flat(lab.plan_images("fleet"))
    assert any("docker build" in c and "BRIX_BASE_IMAGE=quay.io/centos/centos:stream9" in c
               for c in cmds)
    assert any("BRIX_ENABLE_CEPH_SIG=1" in c for c in cmds)
    assert any("minikube image load brix-server:dev" in c for c in cmds)


def test_smoke_image_plan_carries_target_base(monkeypatch):
    monkeypatch.setenv("XRD_LAB_OS_TARGET", "centos9-stream")
    cmds = _flat(lab.plan_images("dev"))
    assert any("minikube image build" in c
               and "BRIX_SMOKE_BASE_IMAGE=quay.io/centos/centos:stream9" in c
               and "brix-smoke:dev" in c for c in cmds)


def test_ceph_docker_gate_is_official_storage_sig_plan():
    cmds = _flat(ceph_docker.plan_ceph_docker())
    assert "tests/ceph_harness.sh start" in cmds[0]
    assert any("tests/ceph/Dockerfile.build" in c for c in cmds)
    assert any("BRIX_BASE_IMAGE=quay.io/centos/centos:stream9" in c for c in cmds)
    assert any("BRIX_CEPH_SIG_RELEASE=tentacle" in c for c in cmds)
    assert any("run_sd_ceph_live.sh" in c for c in cmds)
    assert any("ceph_export_smoke.sh" in c for c in cmds)


def test_ceph_rpmbuild_gate_uses_k8s_rpm_builder():
    cmds = _flat(ceph_docker.plan_ceph_rpmbuild())
    assert len(cmds) == 1
    assert "k8s-tests/Dockerfiles/rpm-builder/Dockerfile" in cmds[0]
    assert "BRIX_ENABLE_CEPH_SIG=1" in cmds[0]
    assert "brix-rpm-builder:centos9-stream-0.1.0" in cmds[0]


def test_xrd_lab_dry_run_exposes_ceph_gates(lab):
    lab.dry("test", "ceph-docker").ok().shows("tests/ceph_harness.sh start",
                                                "run_sd_ceph_live.sh",
                                                "ceph_export_smoke.sh")
    lab.dry("test", "ceph-rpmbuild").ok().shows("k8s-tests/Dockerfiles/rpm-builder/Dockerfile",
                                                  "BRIX_ENABLE_CEPH_SIG=1")


def test_docs_name_targets_and_ceph_gates(reads):
    reads("README.md").shows("XRD_LAB_OS_TARGET=centos9-stream",
                             "./xrd-lab test ceph-docker",
                             "./xrd-lab test ceph-rpmbuild")
    reads("../tests/ceph/README.md").shows("CentOS Stream 9 Storage SIG",
                                           "./xrd-lab test ceph-docker")
