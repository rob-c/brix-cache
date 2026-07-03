"""Compile + run the standalone Ceph driver path-mapping suite
(src/fs/backend/sd_ceph_unittest.c).

The Ceph/RADOS backend maps a confined logical path onto a flat object id. That
map is the security-critical, cluster-independent core of the driver: it must be
injective (no two logical paths alias one object) and prefix-confined (no ".."
escapes the export's key prefix). The C suite exercises canonicalization
(slash-collapse, "." drop, ".." pop), injectivity, escape rejection, key
composition and the inode hash. It needs no librados and no running cluster, so
it compiles with BRIX_HAVE_CEPH OFF (only the pure helpers) and runs anywhere.

The live-cluster data-plane tests (root:///WebDAV/S3 round-trips through a real
RADOS pool) are phase-60 W6 and gated separately on TEST_CEPH.
"""
import os
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(REPO, "src", "fs", "backend")
RADOS = os.path.join(BACKEND, "rados")   # per-driver subdir (Ceph/RADOS backend)
SRC = os.path.join(RADOS, "sd_ceph.c")
# The pure OID/stripe helpers the unittest exercises live in sd_ceph_compat.c
# (split out of sd_ceph.c); it must be linked too or the CEPH-off build fails
# with undefined references to sd_ceph_oid_*.
COMPAT = os.path.join(RADOS, "sd_ceph_compat.c")
TEST = os.path.join(RADOS, "sd_ceph_unittest.c")


@pytest.fixture(scope="module")
def ceph_map_bin(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler")
    if not (os.path.exists(SRC) and os.path.exists(COMPAT) and os.path.exists(TEST)):
        pytest.skip("sd_ceph sources missing")
    out = str(tmp_path_factory.mktemp("sdceph") / "ut")
    r = subprocess.run(
        [cc, "-Wall", "-Wextra", "-Werror", "-I", RADOS, "-I", BACKEND,
         SRC, COMPAT, TEST, "-o", out],
        capture_output=True, text=True)
    if r.returncode != 0:
        pytest.fail(f"sd_ceph map suite failed to COMPILE (warnings are errors):"
                    f"\n{r.stderr}")
    return out


def test_ceph_path_mapping_suite(ceph_map_bin):
    r = subprocess.run([ceph_map_bin], capture_output=True, text=True, timeout=60)
    print(r.stdout)
    assert r.returncode == 0, \
        f"sd_ceph map suite reported failures:\n{r.stdout}\n{r.stderr}"
    assert "all checks passed" in r.stdout
