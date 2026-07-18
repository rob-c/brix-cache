"""End-to-end Ceph backend tests against a live demo RADOS cluster in Docker.

Where test_sd_ceph.py exercises pure path mapping with CEPH compiled out, and
test_cmd_ceph_operator.py only proves the operator ports import, this suite
actually RUNS the librados-backed sd_ceph driver and the operator smokes against
a real single-node ``quay.io/ceph/demo`` cluster -- and deliberately WITHOUT the
k8s suite (see tests_k8s_folder_split: CEPH is the one native-side exception).

The lab is expensive, so it is opt-in and Docker-gated. When enabled, the
session fixture stands the whole thing up once:

  1. ``ceph_harness.cmd_start()``  -- demo MON/MGR/OSD up, test pool ready, and
     ceph.conf + admin keyring extracted to /tmp/ceph-harness.
  2. ``ceph_operator.build_in_container()`` -- create the ``xrd-ceph-work``
     container from the prebuilt ``xrd-ceph-build`` image, deliver the source,
     and build the module against librados.
  3. Ensure the XRootD client (xrdcp/xrdfs) is present in the work container --
     the export smoke drives the running server through it. Newer images bake it
     in (Dockerfile.build); this backfills an older image without a rebuild.

Each test then invokes one operator check and asserts a REAL pass -- a SKIP
(which the checks return when their container is absent) is treated as a
failure here, because the fixture guarantees the lab is up.

Not covered here (they need capabilities this single-node demo lab does not
provide, and remain in the k8s suite / manual operator runs):
  * cephfs_ro_live / cephfs_ro_smoke -- need a CephFS (MDS + metadata/data
    pools) seeded with the fixture tree; the demo cluster is mon,mgr,osd only.
  * striper_migrate -- needs libradosstriper-devel, absent from the SIG stream
    the build image currently tracks.

Run (opt-out): runs by default whenever docker + the ``xrd-ceph-build`` image
are present; force-skip with ``PHASE81_RUN_CEPH_PORTS=0``.
  PYTHONPATH=tests pytest tests/test_ceph_live.py -v

Prerequisite (built once, then reused across runs):
  docker build -f tests/ceph/Dockerfile.build -t xrd-ceph-build tests/ceph

The in-container build is authoritative every session (no run tests stale
source); export CEPH_LAB_REUSE=1 to reuse an already-built work container for
fast local iteration.

The demo cluster and work container are left running for reuse (matching the
shell harness). Tear them down with CEPH_LAB_TEARDOWN=1, or manually:
  python3 -m cmdscripts.ceph_harness stop && docker rm -f xrd-ceph-work
"""

import os
import subprocess

import pytest

from cmdscripts import ceph_harness, ceph_operator

# Standing up the cluster + building the module in-container runs for minutes,
# well past the repo-wide 30s default; the ceiling covers the whole session
# fixture (attributed to the first test) plus each live check.
pytestmark = pytest.mark.timeout(1800)

BUILD_IMAGE = os.environ.get("IMAGE", "xrd-ceph-build")
WORK = os.environ.get("WORK", "xrd-ceph-work")


def _image_exists(name: str) -> bool:
    return subprocess.run(
        ["docker", "image", "inspect", name],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0


def _work_container_built() -> bool:
    """True iff the work container is already running with the module built."""
    return subprocess.run(
        ["docker", "exec", WORK, "test", "-x", "/opt/nginx-src/objs/nginx"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0


def _ensure_xrootd_client() -> None:
    """Backfill xrdcp/xrdfs into the work container if the image predates them."""
    have = subprocess.run(
        ["docker", "exec", WORK, "bash", "-lc", "command -v xrdcp && command -v xrdfs"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0
    if have:
        return
    installed = subprocess.run(
        ["docker", "exec", WORK, "dnf", "-y", "install", "xrootd-client"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert installed.returncode == 0, "failed to install xrootd-client in work container"


@pytest.fixture(scope="session")
def ceph_lab(tmp_path_factory):
    """Bring up demo Ceph + the built work container once for the suite."""
    if os.environ.get("PHASE81_RUN_CEPH_PORTS") == "0":
        pytest.skip("PHASE81_RUN_CEPH_PORTS=0 set — skipping the live Ceph lab")
    if not ceph_harness.have_docker():
        pytest.skip("docker not found")
    if not _image_exists(BUILD_IMAGE):
        pytest.skip(
            f"build image {BUILD_IMAGE} missing; build it once with: "
            f"docker build -f tests/ceph/Dockerfile.build -t {BUILD_IMAGE} tests/ceph"
        )

    assert ceph_harness.cmd_start() == 0, "demo Ceph cluster failed to start"

    base = tmp_path_factory.mktemp("ceph_lab")
    # The in-container module build takes minutes. It runs authoritatively every
    # session so no run tests stale source -- except with CEPH_LAB_REUSE=1, which
    # reuses an already-built work container for fast local iteration.
    if os.environ.get("CEPH_LAB_REUSE") == "1" and _work_container_built():
        pass
    else:
        build_dir = base / "build"
        build_dir.mkdir(parents=True, exist_ok=True)
        ok, msg = ceph_operator.build_in_container(build_dir)
        assert ok and not msg.startswith("SKIP"), f"build_in_container: {msg}"

    _ensure_xrootd_client()

    yield base

    if os.environ.get("CEPH_LAB_TEARDOWN") == "1":
        subprocess.run(["docker", "rm", "-f", WORK],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ceph_harness.cmd_stop()


def _run(ceph_lab, runner, name: str) -> None:
    """Execute one operator check against the live lab; a SKIP is a failure."""
    work = ceph_lab / name
    work.mkdir(parents=True, exist_ok=True)
    ok, msg = runner(work)
    assert not msg.startswith("SKIP"), f"{name} SKIPPED (lab is up, so this is a bug): {msg}"
    assert ok, f"{name} FAILED: {msg}"


def test_sd_ceph_live(ceph_lab):
    """Object read/write/stat/unlink round-trip through the librados driver."""
    _run(ceph_lab, ceph_operator.sd_ceph_live, "sd_ceph_live")


def test_sd_ceph_cred_live(ceph_lab):
    """Per-user CephX credential scoping (bob rwx, readonly r, u0..u9)."""
    _run(ceph_lab, ceph_operator.sd_ceph_cred_live, "sd_ceph_cred_live")


def test_ceph_export_smoke(ceph_lab):
    """xrdcp + WebDAV PUT/GET against a Ceph-backed brix_export, byte-for-byte,
    with the object confirmed present via `rados ls`."""
    _run(ceph_lab, ceph_operator.ceph_export_smoke, "ceph_export_smoke")


def test_rescue_tools_build(ceph_lab):
    """The rados/cephfs rescue + migrate tools compile+link against librados."""
    _run(ceph_lab, ceph_operator.rescue_tools, "rescue_tools")


def test_py_migrate_help(ceph_lab):
    """The Python migration entry points import and answer --help."""
    _run(ceph_lab, ceph_operator.py_migrate, "py_migrate")
