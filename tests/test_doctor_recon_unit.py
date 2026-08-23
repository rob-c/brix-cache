"""Compile + run the phase-93 deep-recon parser unit suite
(client/apps/diag/diag_doctor_recon_unittest.c).

The --deep-recon mode parses a `query stats a` XML reply into a per-plane panel,
decodes the kXR_protocol capability bits, and lists authorized roots. The pure
parsers — the scoped XML field extractor (which must resolve colliding tag names
like <num>/<err>/<in> to the correct <stats id=...> block), the per-plane decode,
and the capability renderer — are proven here deterministically: no server, no
connection, no libbrix. The TU is #included and its wire/render externs are
satisfied by trivial stubs.
"""
import os
import shutil
import subprocess

import pytest

def _guard_recon_bin_1(cc):
    if cc is None:
        pytest.skip("no C compiler")

def _guard_recon_bin_2():
    if not (os.path.exists(SRC) and os.path.exists(TEST)):
        pytest.skip("diag_doctor_recon sources missing")

def _guard_recon_bin_3(r):
    if r.returncode != 0:
        pytest.fail("diag_doctor_recon suite failed to COMPILE "
                    f"(warnings are errors):\n{r.stderr}")


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(REPO, "client")
DIAG = os.path.join(CLIENT, "apps", "diag")
SRC = os.path.join(DIAG, "diag_doctor_recon.c")
TEST = os.path.join(DIAG, "diag_doctor_recon_unittest.c")


@pytest.fixture(scope="module")
def recon_bin(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    _guard_recon_bin_1(cc)
    _guard_recon_bin_2()
    out = str(tmp_path_factory.mktemp("reconut") / "ut")
    r = subprocess.run(
        [cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
         "-Ilib", "-I../src", "-I../shared", "-DXRDPROTO_NO_NGX",
         os.path.join("apps", "diag", "diag_doctor_recon_unittest.c"),
         "-o", out],
        cwd=CLIENT, capture_output=True, text=True)
    _guard_recon_bin_3(r)
    return out


def test_doctor_recon_suite(recon_bin):
    r = subprocess.run([recon_bin], capture_output=True, text=True, timeout=60)
    print(r.stdout)
    assert r.returncode == 0, \
        f"doctor_recon suite reported failures:\n{r.stdout}\n{r.stderr}"
    assert "all checks passed" in r.stdout
