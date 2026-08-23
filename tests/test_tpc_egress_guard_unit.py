"""Compile + run the TPC source-egress allowlist pure-predicate unit suite
(src/tpc/common/egress_guard_unittest.c).

The source-egress guard refuses to originate a TPC pull unless the named source
host is on an operator allowlist (an SSRF control: in TPC-pull the gateway dials
the source). Its security-load-bearing core is the host/pattern match rule —
exact vs leading-'.' domain suffix, case-insensitive, fail-closed on degenerate
input. That rule is proven here deterministically with no server and no nginx:
egress_guard.c is #included under -DXRDPROTO_NO_NGX so only the pure predicate
is built. The ngx allowlist-iteration + refusal-text wrappers are covered online
by test_tpc_source_egress_guard.py against a live gateway.
"""
import os
import shutil
import subprocess

import pytest

def _guard_guard_bin_1(cc):
    if cc is None:
        pytest.skip("no C compiler")

def _guard_guard_bin_2():
    if not (os.path.exists(SRC) and os.path.exists(TEST)):
        pytest.skip("egress_guard sources missing")

def _guard_guard_bin_3(r):
    if r.returncode != 0:
        pytest.fail("egress_guard suite failed to COMPILE "
                    f"(warnings are errors):\n{r.stderr}")


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMMON = os.path.join(REPO, "src", "tpc", "common")
SRC = os.path.join(COMMON, "egress_guard.c")
TEST = os.path.join(COMMON, "egress_guard_unittest.c")


@pytest.fixture(scope="module")
def guard_bin(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    _guard_guard_bin_1(cc)
    _guard_guard_bin_2()
    out = str(tmp_path_factory.mktemp("egguard") / "ut")
    r = subprocess.run(
        [cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-DXRDPROTO_NO_NGX",
         "egress_guard_unittest.c", "-o", out],
        cwd=COMMON, capture_output=True, text=True)
    _guard_guard_bin_3(r)
    return out


def test_tpc_egress_guard_suite(guard_bin):
    r = subprocess.run([guard_bin], capture_output=True, text=True, timeout=60)
    print(r.stdout)
    assert r.returncode == 0, \
        f"egress_guard suite reported failures:\n{r.stdout}\n{r.stderr}"
    assert "all checks passed" in r.stdout
