"""Compile + run the phase-93 tpc-egress self-test classifier unit suite
(client/apps/diag/diag_tpc_egress_unittest.c).

The `xrddiag tpc-egress` self-test maps a live gateway's TPC-pull outcome to a
verdict: whether egress was refused by policy (safe) or permitted, and when
permitted whether the source was conn-refused, filtered, or reachable. The pure
decision logic — the trigger-outcome classifier (which must read the gateway's
generic "connect failed" text plus timing to tell an active RST from a dropped
SYN) and the egress-denial message discriminator (which must not mistake an
unrelated NotAuthorized for a working guard) — is proven here deterministically:
no server, no connection, no libbrix. The TU is #included and its wire externs
are satisfied by trivial stubs.
"""
import os
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(REPO, "client")
DIAG = os.path.join(CLIENT, "apps", "diag")
SRC = os.path.join(DIAG, "diag_tpc_egress.c")
TEST = os.path.join(DIAG, "diag_tpc_egress_unittest.c")


@pytest.fixture(scope="module")
def egress_bin(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler")
    if not (os.path.exists(SRC) and os.path.exists(TEST)):
        pytest.skip("diag_tpc_egress sources missing")
    out = str(tmp_path_factory.mktemp("egressut") / "ut")
    r = subprocess.run(
        [cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
         "-Ilib", "-I../src", "-I../shared", "-DXRDPROTO_NO_NGX",
         os.path.join("apps", "diag", "diag_tpc_egress_unittest.c"),
         "-o", out],
        cwd=CLIENT, capture_output=True, text=True)
    if r.returncode != 0:
        pytest.fail("diag_tpc_egress suite failed to COMPILE "
                    f"(warnings are errors):\n{r.stderr}")
    return out


def test_tpc_egress_suite(egress_bin):
    r = subprocess.run([egress_bin], capture_output=True, text=True, timeout=60)
    print(r.stdout)
    assert r.returncode == 0, \
        f"tpc_egress suite reported failures:\n{r.stdout}\n{r.stderr}"
    assert "all checks passed" in r.stdout
