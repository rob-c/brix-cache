"""targets - OS/image target metadata for the k8s lab.

The lab defaults to AlmaLinux 9 for continuity, but can build the same images
on CentOS Stream 9.  The CentOS Stream target enables the CentOS Storage SIG
Ceph repo so Ceph-devel/RADOS packages come from the SIG rather than a Ceph
demo image.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Target:
    name: str
    base_image: str
    runtime_image: str
    smoke_base_image: str
    enable_ceph_sig: bool = False
    ceph_sig_release: str = "tentacle"


TARGETS = {
    "alma9": Target(
        name="alma9",
        base_image="almalinux:9",
        runtime_image="almalinux:9",
        smoke_base_image="almalinux:9-minimal",
    ),
    "centos9-stream": Target(
        name="centos9-stream",
        base_image="quay.io/centos/centos:stream9",
        runtime_image="quay.io/centos/centos:stream9",
        smoke_base_image="quay.io/centos/centos:stream9",
        enable_ceph_sig=True,
        ceph_sig_release="tentacle",
    ),
}

DEFAULT = "alma9"


def current(name: Optional[str] = None) -> Target:
    """Return the requested target, defaulting from ``XRD_LAB_OS_TARGET``."""
    key = name or os.environ.get("XRD_LAB_OS_TARGET", DEFAULT)
    if key not in TARGETS:
        known = ", ".join(sorted(TARGETS))
        raise KeyError(f"unknown k8s lab OS target {key!r}; expected one of: {known}")
    t = TARGETS[key]
    release = os.environ.get("XRD_LAB_CEPH_SIG_RELEASE")
    if release:
        return Target(
            name=t.name,
            base_image=t.base_image,
            runtime_image=t.runtime_image,
            smoke_base_image=t.smoke_base_image,
            enable_ceph_sig=t.enable_ceph_sig,
            ceph_sig_release=release,
        )
    return t


def image_tag() -> str:
    """Mutable dev tag used by lab images."""
    return os.environ.get("XRD_LAB_IMAGE_TAG", "dev")


def build_args(t: Optional[Target] = None) -> list[str]:
    """Docker build args shared by EL-family lab images."""
    target = t or current()
    return [
        "--build-arg", f"BRIX_OS_TARGET={target.name}",
        "--build-arg", f"BRIX_BASE_IMAGE={target.base_image}",
        "--build-arg", f"BRIX_RUNTIME_IMAGE={target.runtime_image}",
        "--build-arg", f"BRIX_ENABLE_CEPH_SIG={int(target.enable_ceph_sig)}",
        "--build-arg", f"BRIX_CEPH_SIG_RELEASE={target.ceph_sig_release}",
    ]


def smoke_build_args(t: Optional[Target] = None) -> list[str]:
    """Docker build args for the tiny smoke image."""
    target = t or current()
    return [
        "--build-arg", f"BRIX_SMOKE_BASE_IMAGE={target.smoke_base_image}",
    ]
