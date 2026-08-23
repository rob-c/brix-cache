"""Compile + run the phase-93 config/performance advisor unit suite
(client/apps/diag/diag_doctor_audit_unittest.c).

The advisor classifies *scraped values* (Qconfig/Qspace scalars) rather than
error codes, so its value-predicates (checksum-CSV parse, free-space %, version
skew, manager count, capacity threshold) and its record-emitting rules
(audit_rules / cross_cluster) are proven here deterministically — no server, no
connection, no libbrix: the TU is #included and its wire/render externs are
satisfied by trivial stubs, with dx_record stubbed to a recorder so the emitted
findings can be asserted by probe id.
"""
import os
import shutil
import subprocess

import pytest

def _guard_audit_bin_1(cc):
    if cc is None:
        pytest.skip("no C compiler")

def _guard_audit_bin_2():
    if not (os.path.exists(SRC) and os.path.exists(TEST)):
        pytest.skip("diag_doctor_audit sources missing")

def _guard_audit_bin_3(r):
    if r.returncode != 0:
        pytest.fail("diag_doctor_audit suite failed to COMPILE "
                    f"(warnings are errors):\n{r.stderr}")


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(REPO, "client")
DIAG = os.path.join(CLIENT, "apps", "diag")
SRC = os.path.join(DIAG, "diag_doctor_audit.c")
TEST = os.path.join(DIAG, "diag_doctor_audit_unittest.c")


@pytest.fixture(scope="module")
def audit_bin(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    _guard_audit_bin_1(cc)
    _guard_audit_bin_2()
    out = str(tmp_path_factory.mktemp("auditut") / "ut")
    r = subprocess.run(
        [cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
         "-Ilib", "-I../src", "-I../shared", "-DXRDPROTO_NO_NGX",
         os.path.join("apps", "diag", "diag_doctor_audit_unittest.c"),
         "-o", out],
        cwd=CLIENT, capture_output=True, text=True)
    _guard_audit_bin_3(r)
    return out


def test_doctor_audit_suite(audit_bin):
    r = subprocess.run([audit_bin], capture_output=True, text=True, timeout=60)
    print(r.stdout)
    assert r.returncode == 0, \
        f"doctor_audit suite reported failures:\n{r.stdout}\n{r.stderr}"
    assert "all checks passed" in r.stdout
