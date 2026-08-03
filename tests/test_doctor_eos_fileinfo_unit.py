"""Compile + run the EOS unprivileged FST-discovery unit suite
(client/apps/diag/diag_doctor_eos_fileinfo_unittest.c).

When EOS gates the admin farm-enumeration commands (`fs ls`/`node ls`) for our
identity — as eospublic does, mapping a plain VO proxy to `nobody` — `xrddiag
--map` falls back to the *user*-plane `fileinfo` command: it walks a bounded
sample of files under the target, reads each file's replica table, and unions the
FSTs those tables name (partial coverage, tagged "via fileinfo replica sampling").
The URL-path helper and the replica-table parser are pure; the bounded walk is
proven here end-to-end over faked wire primitives (doctor_eos_proc / brix_dirlist)
that model a two-level tree with overlapping replica sets, so dedup is exercised.
The parser is driven over a GENUINE eospublic `fileinfo` reply — box-drawing rules
and ANSI-coloured `online` cell and all (the /proc route ignores `-m`).
"""
import os
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(REPO, "client")
DIAG = os.path.join(CLIENT, "apps", "diag")
SRC = os.path.join(DIAG, "diag_doctor_eos_fileinfo.c")
TEST = os.path.join(DIAG, "diag_doctor_eos_fileinfo_unittest.c")


@pytest.fixture(scope="module")
def eos_fi_bin(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler")
    if not (os.path.exists(SRC) and os.path.exists(TEST)):
        pytest.skip("diag_doctor_eos_fileinfo sources missing")
    out = str(tmp_path_factory.mktemp("eosfiut") / "ut")
    r = subprocess.run(
        [cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
         "-Ilib", "-I../src", "-I../shared", "-DXRDPROTO_NO_NGX",
         "-DBRIX_HAVE_KRB5", "-DBRIX_HAVE_LIBURING",
         os.path.join("apps", "diag", "diag_doctor_eos_fileinfo_unittest.c"),
         "-o", out],
        cwd=CLIENT, capture_output=True, text=True)
    if r.returncode != 0:
        pytest.fail("diag_doctor_eos_fileinfo suite failed to COMPILE "
                    f"(warnings are errors):\n{r.stderr}")
    return out


def test_doctor_eos_fileinfo_suite(eos_fi_bin):
    r = subprocess.run([eos_fi_bin], capture_output=True, text=True, timeout=60)
    print(r.stdout)
    assert r.returncode == 0, \
        f"doctor_eos_fileinfo suite reported failures:\n{r.stdout}\n{r.stderr}"
    assert "all EOS fileinfo-discovery checks passed" in r.stdout
