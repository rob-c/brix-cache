"""Compile + run the standalone TPC transfer-loop suite
(src/tpc/outbound/io_xfer_unittest.c).

Native TPC pulls frame their wire traffic as a fixed-size ServerResponseHdr
followed by a length-prefixed body, so every read is "give me exactly N bytes".
That loop used to exist twice — once for send, once for recv, differing only in
which syscall it called — which meant the EINTR rule, the ``<= 0`` rule and the
INT_MAX clamp each had two homes and could drift.  It now lives once, in a
translation unit deliberately free of nginx headers so it can be driven over a
socketpair here instead of only through a live pull against a remote origin.

The load-bearing cases are the truncation negatives: a loop that returns success
having moved fewer bytes than asked hands the caller uninitialised buffer as
though it were wire data, and desynchronises the stream so the next header is
parsed out of body bytes.
"""

import os
import shutil
import subprocess

import pytest

def _guard_io_xfer_bin_1(cc):
    if cc is None:
        pytest.skip("no C compiler")

def _guard_io_xfer_bin_2():
    if not (os.path.exists(SRC) and os.path.exists(TEST)):
        pytest.skip("io_xfer sources missing")

def _guard_io_xfer_bin_3(r):
    if r.returncode != 0:
        pytest.fail("io_xfer suite failed to COMPILE (warnings are errors):"
                    f"\n{r.stderr}")


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TPC = os.path.join(REPO, "src", "tpc", "outbound")
SRC = os.path.join(TPC, "io_xfer.c")
TEST = os.path.join(TPC, "io_xfer_unittest.c")


@pytest.fixture(scope="module")
def io_xfer_bin(tmp_path_factory):
    cc = shutil.which("gcc") or shutil.which("cc")
    _guard_io_xfer_bin_1(cc)
    _guard_io_xfer_bin_2()
    out = str(tmp_path_factory.mktemp("tpcxfer") / "ut")
    r = subprocess.run(
        [cc, "-Wall", "-Wextra", "-Werror", "-I", TPC, SRC, TEST, "-o", out,
         "-lssl", "-lcrypto"],
        capture_output=True, text=True)
    _guard_io_xfer_bin_3(r)
    return out


def test_io_xfer_suite(io_xfer_bin):
    r = subprocess.run([io_xfer_bin], capture_output=True, text=True, timeout=60)
    print(r.stdout)
    assert r.returncode == 0, \
        f"io_xfer suite reported failures:\n{r.stdout}\n{r.stderr}"
    assert "all checks passed" in r.stdout


def test_the_transfer_loop_has_exactly_one_home():
    """io.c must delegate, not keep a second copy of the loop.

    Reintroducing an inline ``while (len > 0)`` in io.c is how the duplication
    got there the first time, and the copy-paste guard only notices once the
    two copies are large enough to match.
    """
    io_c = open(os.path.join(TPC, "io.c"), encoding="utf-8").read()
    assert "brix_tpc_xfer_all" in io_c, "io.c must call the shared loop"
    for banned in ("SSL_write(", "SSL_read(", "send(fd,", "recv(fd,"):
        assert banned not in io_c, \
            f"io.c reimplements the transfer loop ({banned}); delegate instead"
