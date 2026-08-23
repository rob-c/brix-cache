"""Compile + run the phase-93 mesh-diagram unit suite
(client/apps/diag/diag_doctor_graph_unittest.c).

The mesh diagram renders the topology doctor_fanout discovered over the wire
(eps[0]=manager, eps[1..]=CMS-located data servers) as an ASCII tree, a Graphviz
DOT digraph, or a Mermaid graph. It is pure formatting over the scraped
doctor_ep[], so the format classifier and all three renderers are proven here
deterministically — no server, no connection, no libbrix: the TU is #included
and its two externs (doc_color, capacity_pct) are satisfied by trivial stubs,
with output captured to a memstream and asserted per format.
"""
import os
import shutil
import subprocess

import pytest

def _guard_graph_bin_1(cc):
    if cc is None:
        pytest.skip("no C compiler")

def _guard_graph_bin_2():
    if not (os.path.exists(SRC) and os.path.exists(TEST)):
        pytest.skip("diag_doctor_graph sources missing")

def _guard_graph_bin_3(r):
    if r.returncode != 0:
        pytest.fail("diag_doctor_graph suite failed to COMPILE "
                    f"(warnings are errors):\n{r.stderr}")


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(REPO, "client")
DIAG = os.path.join(CLIENT, "apps", "diag")
SRC = os.path.join(DIAG, "diag_doctor_graph.c")
TEST = os.path.join(DIAG, "diag_doctor_graph_unittest.c")


@pytest.fixture(scope="module")
def graph_bin(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    _guard_graph_bin_1(cc)
    _guard_graph_bin_2()
    out = str(tmp_path_factory.mktemp("graphut") / "ut")
    r = subprocess.run(
        [cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
         "-Ilib", "-I../src", "-I../shared", "-DXRDPROTO_NO_NGX",
         os.path.join("apps", "diag", "diag_doctor_graph_unittest.c"),
         "-o", out],
        cwd=CLIENT, capture_output=True, text=True)
    _guard_graph_bin_3(r)
    return out


def test_doctor_graph_suite(graph_bin):
    r = subprocess.run([graph_bin], capture_output=True, text=True, timeout=60)
    print(r.stdout)
    assert r.returncode == 0, \
        f"doctor_graph suite reported failures:\n{r.stdout}\n{r.stderr}"
    assert "all graph-renderer checks passed" in r.stdout
