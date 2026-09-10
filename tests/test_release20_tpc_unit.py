"""2.0 F7 — the C unit suites behind native TPC multihop and multi-stream.

Two pure-C kernels carry the arithmetic the live suites cannot reach corner by
corner: `stream_plan.c` (hint clamp, round advance/EOF, kXR_read args) and the
header-only `frame_hdr.h` redirect decoder. Each ships a `*_unittest.c`; this
wrapper compiles and runs both so a change to either kernel fails the Python
tier, and pins that the live loops call the kernels rather than re-deriving
them.
"""

import os
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO, "src")
TPC = os.path.join(SRC, "tpc", "outbound")
PROTO = os.path.join(SRC, "protocols", "root", "protocol")

SUITES = {
    "stream_plan": (["-I", TPC],
                    [os.path.join(TPC, "stream_plan_unittest.c"),
                     os.path.join(TPC, "stream_plan.c")]),
    "frame_hdr": (["-I", SRC],
                  [os.path.join(PROTO, "frame_hdr_unittest.c")]),
}


def _guard_compiler():
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler on PATH")
    return cc


@pytest.fixture(scope="module", params=sorted(SUITES))
def unit_binary(request, tmp_path_factory):
    cc = _guard_compiler()
    includes, sources = SUITES[request.param]
    missing = [path for path in sources if not os.path.exists(path)]
    if missing:
        pytest.skip(f"unit sources missing: {missing}")
    out = str(tmp_path_factory.mktemp("f7unit") / request.param)
    build = subprocess.run([cc, "-Wall", "-Wextra", "-Werror", *includes, *sources, "-o", out],
                           capture_output=True, text=True, timeout=120)
    if build.returncode != 0:
        pytest.fail(f"{request.param} failed to compile:\n{build.stderr}")
    return out


def test_unit_suite_passes(unit_binary):
    run = subprocess.run([unit_binary], capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "all checks passed" in run.stdout


def _source(*parts):
    with open(os.path.join(SRC, *parts), encoding="utf-8") as fh:
        return fh.read()


def test_multi_stream_loop_uses_the_plan_kernel():
    """The loop schedules and frames reads through stream_plan, not privately."""
    loop = _source("tpc", "outbound", "source_stream_multi.c")
    assert "tpc_stream_plan_round(" in loop
    assert "tpc_stream_plan_read_args(" in loop
    assert "tpc_stream_plan_clamp(" in _source("tpc", "engine", "launch_prepare.c")


def test_redirect_decoder_has_one_home():
    """Server hop-following and the client copier decode a redirect the same way."""
    server = _source("tpc", "outbound", "redirect.c")
    client_path = os.path.join(REPO, "client", "lib", "protocols", "root", "frame_roundtrip.c")
    with open(client_path, encoding="utf-8") as fh:
        client = fh.read()
    assert "xrd_redirect_body_decode(" in server
    assert "xrd_redirect_body_decode(" in client
    assert "memchr(" not in server
