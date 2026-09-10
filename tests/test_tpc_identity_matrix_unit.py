"""Compile + run the TPC identity-matrix pure-predicate unit suite
(src/tpc/common/identity_matrix_unittest.c).

2.0 F18 gives BriX the `ofs.tpc allow|require|restrict|oids` identity matrix
under the names brix_tpc_allow_identity / brix_tpc_require / brix_tpc_restrict /
brix_tpc_oids.  It is an INNER gate: the host plane (brix_tpc_source_guard,
brix_tpc_allow_local/_private) stays the outer one, so a matrix rule can only
narrow.  Its decision core is pure C — stage order, CSV element boundaries,
component-aware path prefixes, the party scoping that makes `require dest`
unsatisfiable by a client credential, and the fixed low-cardinality refusal
texts (INVARIANT 8).  All of that is proven here deterministically with no
server and no nginx: identity_matrix.c (plus egress_guard.c, whose
brix_tpc_host_pattern_match the matrix deliberately reuses so there is ONE host
spelling) is #included under -DXRDPROTO_NO_NGX.

The ngx half — conf-array adaptation, the identity projection, the three
directive setters and the two gate call sites — is covered online by
tests/test_release20_tpc_identity_matrix.py.
"""
import os
import shutil
import subprocess

import pytest


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMMON = os.path.join(REPO, "src", "tpc", "common")
SRCS = (os.path.join(COMMON, "identity_matrix.c"),
        os.path.join(COMMON, "egress_guard.c"))
TEST = os.path.join(COMMON, "identity_matrix_unittest.c")


def _guard_matrix_bin_1(cc):
    if cc is None:
        pytest.skip("no C compiler")


def _guard_matrix_bin_2():
    missing = [p for p in (*SRCS, TEST) if not os.path.exists(p)]
    if missing:
        pytest.skip(f"identity_matrix sources missing: {missing}")


def _guard_matrix_bin_3(r):
    if r.returncode != 0:
        pytest.fail("identity_matrix suite failed to COMPILE "
                    f"(warnings are errors):\n{r.stderr}")


@pytest.fixture(scope="module")
def matrix_bin(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    _guard_matrix_bin_1(cc)
    _guard_matrix_bin_2()
    out = str(tmp_path_factory.mktemp("tpcmatrix") / "ut")
    r = subprocess.run(
        [cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-DXRDPROTO_NO_NGX",
         "identity_matrix_unittest.c", "-o", out],
        cwd=COMMON, capture_output=True, text=True)
    _guard_matrix_bin_3(r)
    return out


def test_tpc_identity_matrix_suite(matrix_bin):
    """(success) every pure predicate and the whole staged evaluation behave as
    the header specifies — including the fail-closed and party-scoping cases."""
    r = subprocess.run([matrix_bin], capture_output=True, text=True, timeout=60)
    print(r.stdout)
    assert r.returncode == 0, \
        f"identity_matrix suite reported failures:\n{r.stdout}\n{r.stderr}"
    assert "all checks passed" in r.stdout


def test_matrix_reuses_the_one_host_spelling():
    """(security negative) the matrix must not grow a second host-pattern
    implementation: `allow ... host` has to mean exactly what the egress
    allowlist means, or an operator's two host rules would disagree."""
    body = open(SRCS[0], encoding="utf-8").read()
    assert 'brix_tpc_host_pattern_match' in body
    assert '#include "egress_guard.h"' in body
    # no local re-implementation of the suffix rule
    assert "strcasecmp(pattern" not in body
