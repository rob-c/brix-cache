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

def _guard_ceph_map_bin_1(cc):
    if cc is None:
        pytest.skip("no C compiler")

def _guard_ceph_map_bin_2():
    if not (os.path.exists(SRC) and os.path.exists(COMPAT)
            and os.path.exists(META) and os.path.exists(TEST)):
        pytest.skip("sd_ceph sources missing")

def _guard_ceph_map_bin_3(r):
    if r.returncode != 0:
        pytest.fail(f"sd_ceph map suite failed to COMPILE (warnings are errors):"
                    f"\n{r.stderr}")


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(REPO, "src", "fs", "backend")
RADOS = os.path.join(BACKEND, "rados")   # per-driver subdir (Ceph/RADOS backend)
SRC = os.path.join(RADOS, "sd_ceph.c")
# The pure OID/stripe helpers the unittest exercises live in sd_ceph_compat.c
# (split out of sd_ceph.c); it must be linked too or the CEPH-off build fails
# with undefined references to sd_ceph_oid_*.
COMPAT = os.path.join(RADOS, "sd_ceph_compat.c")
# sd_ceph_meta.c defines sd_ceph_ck_crc32c_hex OUTSIDE its BRIX_HAVE_CEPH gate
# precisely so the checksum-offload conditioning is pinned here, with no cluster
# and no librados: with the gate off this TU compiles to that one pure function.
META = os.path.join(RADOS, "sd_ceph_meta.c")
# sd_ceph_normalize is now a thin shim over the shared canonicalizer in
# site_n2n.c (phase-108 C13): the ".."-reject / "."-and-"//"-fold rules live
# there and are linked in so the CEPH-off build resolves brix_n2n_canonicalize.
# The kernel moved to the path layer with its stage (W3/A.4), out of backend/.
N2N = os.path.join(REPO, "src", "fs", "path", "site_n2n.c")
TEST = os.path.join(RADOS, "sd_ceph_unittest.c")


@pytest.fixture(scope="module")
def ceph_map_bin(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    _guard_ceph_map_bin_1(cc)
    _guard_ceph_map_bin_2()
    out = str(tmp_path_factory.mktemp("sdceph") / "ut")
    # -I src too: sd_ceph.h reaches the moved kernel by its from-src include
    # `fs/path/site_n2n.h` (W3/A.4 relocated site_n2n out of backend/), the same
    # convention the nginx build uses.
    src_root = os.path.join(REPO, "src")
    r = subprocess.run(
        [cc, "-Wall", "-Wextra", "-Werror",
         "-I", RADOS, "-I", BACKEND, "-I", src_root,
         SRC, COMPAT, META, N2N, TEST, "-o", out],
        capture_output=True, text=True)
    _guard_ceph_map_bin_3(r)
    return out


def test_ceph_path_mapping_suite(ceph_map_bin):
    r = subprocess.run([ceph_map_bin], capture_output=True, text=True, timeout=60)
    print(r.stdout)
    assert r.returncode == 0, \
        f"sd_ceph map suite reported failures:\n{r.stdout}\n{r.stderr}"
    assert "all checks passed" in r.stdout
