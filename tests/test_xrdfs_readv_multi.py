"""xrdfs multi-file readv — per-segment fhandle (parity-audit §7.15).

Stock's readahead_list carries a per-segment fhandle (verified in the stock
XProtocol.hh: `struct readahead_list { fhandle[4]; rlen; offset; }`), so ONE
kXR_readv can scatter-gather across multiple open files.  BriX's client sent a
single fhandle for every segment; the SERVER already supported per-segment
handles (audit §1), so the gap was purely client-side.  The new
brix_file_readv_multi + the `xrdfs readvm` verb close it.

  * success   — a readvm interleaving segments from two files reassembles each
                segment from the CORRECT file, in one round trip
  * success   — the same file repeated across segments (handle dedup) works,
                and the plain single-file `readv` is unchanged (regression)
  * error     — a missing file in any segment is a clean open error, no output

Run:
    PYTHONPATH=tests pytest tests/test_xrdfs_readv_multi.py -v
"""

import os
import subprocess

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")

URL = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"

pytestmark = [
    pytest.mark.requires_local_server,
    pytest.mark.timeout(60),
    pytest.mark.skipif(not os.path.exists(XRDFS),
                       reason="brix-xrdfs not built (client/bin/xrdfs)"),
]

A = bytes(range(65, 65 + 26)) * 8      # 'A'.. pattern, 208 bytes
B = bytes(range(97, 97 + 26)) * 8      # 'a'.. pattern, 208 bytes


@pytest.fixture(scope="module", autouse=True)
def staged():
    os.makedirs(DATA_ROOT, exist_ok=True)
    with open(os.path.join(DATA_ROOT, "rvm-a.bin"), "wb") as f:
        f.write(A)
    with open(os.path.join(DATA_ROOT, "rvm-b.bin"), "wb") as f:
        f.write(B)
    yield
    for n in ("rvm-a.bin", "rvm-b.bin"):
        try:
            os.remove(os.path.join(DATA_ROOT, n))
        except FileNotFoundError:
            pass


def _run(*args):
    return subprocess.run([XRDFS, URL, *args],
                          capture_output=True, timeout=30)


class TestReadvMulti:

    def test_two_files_interleaved(self):
        """(success) segments alternate between two files and each lands from
        the right one — proving the per-segment fhandle rode the wire."""
        res = _run("readvm",
                   "/rvm-a.bin", "0", "10",
                   "/rvm-b.bin", "50", "10",
                   "/rvm-a.bin", "100", "10",
                   "/rvm-b.bin", "0", "10")
        assert res.returncode == 0, res.stderr
        assert res.stdout == A[0:10] + B[50:60] + A[100:110] + B[0:10]

    def test_repeated_file_dedup(self):
        """(success) the same file across every segment (one open, dedup) —
        equivalent to a single-file readv."""
        res = _run("readvm",
                   "/rvm-a.bin", "0", "8",
                   "/rvm-a.bin", "8", "8",
                   "/rvm-a.bin", "16", "8")
        assert res.returncode == 0, res.stderr
        assert res.stdout == A[0:24]

    def test_single_file_readv_regression(self):
        """(regression) the original single-file `readv` verb is unchanged by
        the per-segment refactor."""
        res = _run("readv", "/rvm-b.bin", "0", "5", "5", "5")
        assert res.returncode == 0, res.stderr
        assert res.stdout == B[0:10]

    def test_missing_file_clean_error(self):
        """(error) a non-existent file in one segment fails cleanly at open —
        no partial data on stdout."""
        res = _run("readvm",
                   "/rvm-a.bin", "0", "10",
                   "/no-such-file-xyz.bin", "0", "10")
        assert res.returncode != 0
        assert res.stdout == b""
