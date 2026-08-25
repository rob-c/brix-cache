"""Opt-in RBAC and Ceph examples with no cluster-shaped test code."""

import hashlib
import os
import sys

import pytest

from brixtest import Placement, binary, case, identity, mount, probe, resource, server, volume

pytestmark = pytest.mark.skipif(
    os.environ.get("BRIXTEST_EXAMPLE_MINIKUBE_INFRA") != "1",
    reason="set BRIXTEST_EXAMPLE_MINIKUBE_INFRA=1 for the managed Minikube/Rook example",
)

PYTHON = binary(
    "infra_python", path=sys.executable,
    image="python@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a",
    image_path="/usr/local/bin/python3",
)
READER = identity(
    "pod_reader", service_account="brixtest-pod-reader",
    permissions={"pods": ("get", "list")},
)
CEPH = resource("ceph", "rook-ceph", storage_class="rook-cephfs")
DATA = volume(
    "ceph_data", kind="provider", provider=CEPH.name,
    access="read-write-many", size=1 << 20,
)
ORIGIN = server(
    "ceph_origin", command=(PYTHON, "-u", "-c", "import time;time.sleep(300)"),
    mounts=(mount(DATA, "data", read_only=False),), probe=probe("none"),
    placement=Placement(identity=READER),
    replicas=3,
)


@case(CEPH, DATA, READER, ORIGIN, PYTHON, backend="minikube", timeout=180, keep="never")
def test_rbac_identity_and_provider_volume_are_ordinary_resources(run):
    service = run.server(ORIGIN)
    assert len(service.replicas) == 3
    token = service.command("cat", "/var/run/secrets/kubernetes.io/serviceaccount/token")
    assert token.ok and token.stdout
    service.fs.write_text("data/persistent.txt", "managed by BriXTest")
    before = {item.uid for item in service.replicas}
    content_sha256 = hashlib.sha256(
        service.fs.read_bytes("data/persistent.txt")
    ).hexdigest()
    service = service.restart().wait_ready(timeout=60)
    assert before.isdisjoint({item.uid for item in service.replicas})
    retained = service.fs.read_bytes("data/persistent.txt")
    assert retained == b"managed by BriXTest"
    assert hashlib.sha256(retained).hexdigest() == content_sha256
    assert run.resource(CEPH).outputs["storage_class"] == "rook-cephfs"
