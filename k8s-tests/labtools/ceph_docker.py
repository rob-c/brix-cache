"""ceph_docker - official Ceph Docker gates exposed through xrd-lab.

These tests are Docker-backed rather than Kubernetes-backed, but they live in
the k8s lab because they validate the same containerized test targets and image
matrix.  The default gate is deliberately the always-runnable Ceph subset:
single-node demo cluster, Ceph-enabled module build, live sd_ceph driver test,
and root/WebDAV export smoke.
"""
from __future__ import annotations

import os
import subprocess

from . import REPO
from . import targets


def _env_value(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _tag(t: targets.Target) -> str:
    version = _env_value("XRD_LAB_RPM_VERSION", "0.1.0")
    return f"brix-rpm-builder:{t.name}-{version}"


def plan_ceph_docker() -> list[list[str]]:
    """Return the official live Ceph Docker gate command plan."""
    t = targets.current("centos9-stream")
    image = _env_value("XRD_LAB_CEPH_BUILD_IMAGE", "xrd-ceph-build")
    work = _env_value("XRD_LAB_CEPH_WORK_CONTAINER", "xrd-ceph-work")
    pool = _env_value("CEPH_POOL", "xrdtest")
    return [
        [str(REPO / "tests" / "ceph_harness.sh"), "start"],
        [
            "docker", "build",
            *targets.build_args(t),
            "-t", image,
            "-f", str(REPO / "tests" / "ceph" / "Dockerfile.build"),
            str(REPO / "tests" / "ceph"),
        ],
        ["env", f"IMAGE={image}", f"WORK={work}", str(REPO / "tests" / "ceph" / "build_in_container.sh")],
        ["env", f"WORK={work}", f"CEPH_POOL={pool}", str(REPO / "tests" / "ceph" / "run_sd_ceph_live.sh")],
        ["docker", "cp", str(REPO / "tests" / "ceph" / "ceph_export_smoke.sh"), f"{work}:/work/ceph_export_smoke.sh"],
        ["docker", "exec", "-e", f"CEPH_POOL={pool}", work, "bash", "/work/ceph_export_smoke.sh"],
    ]


def plan_ceph_rpmbuild() -> list[list[str]]:
    """Return the isolated CentOS Stream 9 + Storage SIG RPM build plan."""
    t = targets.current("centos9-stream")
    version = _env_value("XRD_LAB_RPM_VERSION", "0.1.0")
    return [[
        "docker", "build",
        *targets.build_args(t),
        "--build-arg", f"VERSION={version}",
        "-t", _tag(t),
        "-f", str(REPO / "k8s-tests" / "Dockerfiles" / "rpm-builder" / "Dockerfile"),
        str(REPO),
    ]]


def _dry() -> bool:
    return os.environ.get("XRD_LAB_DRY_RUN", "0") == "1"


def _run(cmds: list[list[str]]) -> list[str]:
    lines = []
    for cmd in cmds:
        lines.append(" ".join(cmd))
        if not _dry():
            subprocess.run(cmd, check=True)
    return lines


def run(kind: str) -> list[str]:
    if kind == "ceph-docker":
        return _run(plan_ceph_docker())
    if kind == "ceph-rpmbuild":
        return _run(plan_ceph_rpmbuild())
    raise ValueError(kind)
