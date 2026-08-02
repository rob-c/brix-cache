"""Compile + run the standalone CNS inventory table suite
(src/net/cms/cns_inventory_unittest.c).

The Composite Cluster Name Space manager keeps a path->metadata inventory. Phase-88
moved the slot logic into a pointer-free POD table (cns_inventory.c) so the SAME
struct can live either in a per-worker heap block or — the multi-worker residual
this closes — in an nginx SHM slab shared across every manager worker. cns.c hosts
that block under the zone's slab lock; this suite proves the pure slot/upsert/
delete/full-table semantics the shared path depends on, deterministically and
without an nginx runtime.
"""
import os
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CMS = os.path.join(REPO, "src", "net", "cms")
SRC = os.path.join(CMS, "cns_inventory.c")
TEST = os.path.join(CMS, "cns_inventory_unittest.c")


@pytest.fixture(scope="module")
def cns_inv_bin(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler")
    if not (os.path.exists(SRC) and os.path.exists(TEST)):
        pytest.skip("cns_inventory sources missing")
    out = str(tmp_path_factory.mktemp("cnsinv") / "ut")
    r = subprocess.run(
        [cc, "-Wall", "-Wextra", "-Werror", "-I", CMS, SRC, TEST, "-o", out],
        capture_output=True, text=True)
    if r.returncode != 0:
        pytest.fail("cns_inventory suite failed to COMPILE (warnings are errors):"
                    f"\n{r.stderr}")
    return out


def test_cns_inventory_suite(cns_inv_bin):
    r = subprocess.run([cns_inv_bin], capture_output=True, text=True, timeout=60)
    print(r.stdout)
    assert r.returncode == 0, \
        f"cns_inventory suite reported failures:\n{r.stdout}\n{r.stderr}"
    assert "all checks passed" in r.stdout
