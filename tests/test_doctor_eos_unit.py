"""Compile + run the EOS-dialect topology unit suite
(client/apps/diag/diag_doctor_eos_unittest.c).

`xrddiag --map` speaks EOS's own out-of-band /proc command channel to enrich the
mesh diagram: it detects an EOS MGM from its version banner and, when the
identity has the rights, enumerates the FST farm from `fs ls` — the storage
nodes a plain kXR_locate never reveals (an MGM answers locate with itself plus
the aggregate space report). The transport is the only wire code; every parser
(proc-envelope stdout/kv/retc, the version banner, the `fs ls -m` monitoring
format) and every renderer (text + JSON) is pure over a caller buffer, so they
are proven here deterministically — no server, no libbrix: the TU is #included
and its externs + wire calls are satisfied by trivial stubs, with the version
parser driven over the GENUINE eospublic reply and the FST parser over a
constructed `fs ls -m` fixture (live enumeration is admin-gated for `nobody`).
"""
import os
import shutil
import subprocess

import pytest

def _guard_eos_bin_1(cc):
    if cc is None:
        pytest.skip("no C compiler")

def _guard_eos_bin_2():
    if not (os.path.exists(SRC) and os.path.exists(TEST)):
        pytest.skip("diag_doctor_eos sources missing")

def _guard_eos_bin_3(r):
    if r.returncode != 0:
        pytest.fail("diag_doctor_eos suite failed to COMPILE "
                    f"(warnings are errors):\n{r.stderr}")


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(REPO, "client")
DIAG = os.path.join(CLIENT, "apps", "diag")
SRC = os.path.join(DIAG, "diag_doctor_eos.c")
TEST = os.path.join(DIAG, "diag_doctor_eos_unittest.c")


@pytest.fixture(scope="module")
def eos_bin(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    _guard_eos_bin_1(cc)
    _guard_eos_bin_2()
    out = str(tmp_path_factory.mktemp("eosut") / "ut")
    r = subprocess.run(
        [cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
         "-Ilib", "-I../src", "-I../shared", "-DXRDPROTO_NO_NGX",
         "-DBRIX_HAVE_KRB5", "-DBRIX_HAVE_LIBURING",
         os.path.join("apps", "diag", "diag_doctor_eos_unittest.c"),
         "-o", out],
        cwd=CLIENT, capture_output=True, text=True)
    _guard_eos_bin_3(r)
    return out


def test_doctor_eos_suite(eos_bin):
    r = subprocess.run([eos_bin], capture_output=True, text=True, timeout=60)
    print(r.stdout)
    assert r.returncode == 0, \
        f"doctor_eos suite reported failures:\n{r.stdout}\n{r.stderr}"
    assert "all EOS-dialect parser/renderer checks passed" in r.stdout
