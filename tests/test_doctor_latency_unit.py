"""Compile + run the phase-93 mesh-latency unit suite
(client/apps/diag/diag_doctor_latency_unittest.c).

The latency probe measures bi-directional round-trip latency to every mesh node
over the two XRootD control planes (data-server = kXR_stat, redirect = kXR_locate),
and the fan-out skips IPv6-only nodes when the local host has no IPv6 route. The
render/JSON emitters, the IPv6-only classifier, and the probe's unreachable branch
are proven here deterministically — no server, no libbrix: the TU is #included and
its wire externs are trivial stubs (brix_endpoint_parse fails, so the probe takes
its unreachable path), with output captured to a memstream.
"""
import os
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(REPO, "client")
DIAG = os.path.join(CLIENT, "apps", "diag")
SRC = os.path.join(DIAG, "diag_doctor_latency.c")
TEST = os.path.join(DIAG, "diag_doctor_latency_unittest.c")


@pytest.fixture(scope="module")
def latency_bin(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler")
    if not (os.path.exists(SRC) and os.path.exists(TEST)):
        pytest.skip("diag_doctor_latency sources missing")
    out = str(tmp_path_factory.mktemp("latut") / "ut")
    r = subprocess.run(
        [cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
         "-Ilib", "-I../src", "-I../shared", "-DXRDPROTO_NO_NGX",
         os.path.join("apps", "diag", "diag_doctor_latency_unittest.c"),
         "-o", out],
        cwd=CLIENT, capture_output=True, text=True)
    if r.returncode != 0:
        pytest.fail("diag_doctor_latency suite failed to COMPILE "
                    f"(warnings are errors):\n{r.stderr}")
    return out


def test_doctor_latency_suite(latency_bin):
    r = subprocess.run([latency_bin], capture_output=True, text=True, timeout=60)
    print(r.stdout)
    assert r.returncode == 0, \
        f"doctor_latency suite reported failures:\n{r.stdout}\n{r.stderr}"
    assert "all latency checks passed" in r.stdout
