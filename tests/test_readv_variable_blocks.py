"""
tests/test_readv_variable_blocks.py

Verify THIS PROJECT'S native client (libbrix, brix_file_readv) correctly handles
variably-sized kXR_readv response blocks — in particular blocks the server makes
SHORTER than requested by capping each element to brix_readv_segment_size. The
client must read each segment's actual returned length from the response (not
assume it equals the request) and deliver byte-exact data per segment.

A dedicated anonymous nginx is started with brix_readv_segment_size 1m over a
5 MiB random file, then a compiled libbrix consumer (examples/brix_readv_demo.c)
issues one readv mixing tiny, mid, exactly-cap and over-cap (-> capped/short)
elements. The test checks each segment's reported `got` and its bytes.

Run:
    pytest tests/test_readv_variable_blocks.py -v
"""

import os
import subprocess
import shutil

import pytest

from settings import HOST, BIND_HOST
from server_registry import NginxInstanceSpec

# Reuse the proven static-link probes from the libbrix test.
from test_libbrix import _codec_link_libs, _krb5_link_libs, _uring_link_libs

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-readv-var1m")]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(REPO, "client")
SRC = os.path.join(REPO, "src")
SHARED = os.path.join(REPO, "shared", "xrdproto")
DEMO_SRC = os.path.join(CLIENT, "examples", "brix_readv_demo.c")
LIBXRDC = os.path.join(CLIENT, "libbrix.a")
LIBXRDPROTO = os.path.join(SHARED, "libxrdproto.a")
CC = os.environ.get("CC", "cc")

FILE_BYTES = 5 * 1024 * 1024
CAP = 1024 * 1024                 # brix_readv_segment_size 1m


@pytest.fixture(scope="module")
def demo_bin(tmp_path_factory):
    if shutil.which(CC) is None:
        pytest.skip("no C compiler")
    for need in (DEMO_SRC, LIBXRDC, LIBXRDPROTO):
        if not os.path.isfile(need):
            pytest.skip(f"missing build artifact: {need}")
    out = str(tmp_path_factory.mktemp("readv_demo") / "demo")
    cmd = [CC, "-std=c11", "-O2",
           f"-I{os.path.join(CLIENT, 'lib')}", f"-I{SRC}", "-DXRDPROTO_NO_NGX",
           DEMO_SRC, LIBXRDC, LIBXRDPROTO,
           "-lssl", "-lcrypto", "-lz",
           *_codec_link_libs(), *_krb5_link_libs(), *_uring_link_libs(),
           "-lpthread", "-ldl", "-o", out]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if proc.returncode != 0:
        pytest.skip(f"demo build failed:\n{' '.join(cmd)}\n{proc.stderr}")
    return out


@pytest.fixture()
def server1m(lifecycle, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    payload = os.urandom(FILE_BYTES)
    (data / "big.bin").write_bytes(payload)
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-readv-var1m",
        template="nginx_lc_readv.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data),
                         "READV_SEG": "1m"},
        reason="variable/capped readv blocks against a 1m brix_readv_segment_size"))
    return {"url": f"root://{HOST}:{ep.port}", "payload": payload}


def _run_demo(demo_bin, url, segs, outfile):
    args = [demo_bin, url, "/big.bin", outfile] + [f"{o}:{l}" for (o, l) in segs]
    env = dict(os.environ)
    env.pop("LD_LIBRARY_PATH", None)
    return subprocess.run(args, capture_output=True, text=True, timeout=60, env=env)


def test_variable_and_capped_blocks(demo_bin, server1m, tmp_path):
    """One readv mixing tiny / mid / exactly-cap / over-cap (capped) elements,
    all within EOF and non-contiguous (no coalescing). Each block is verified for
    its actual length (got == min(req, cap)) and byte-exactness."""
    payload = server1m["payload"]
    # (offset, requested_len) — non-contiguous, all within the 5 MiB file.
    segs = [
        (100, 7),                 # tiny
        (5000, 65536),            # mid
        (200000, CAP),            # exactly the cap
        (1300000, 3 * 1024 * 1024),   # over cap -> capped/short
        (2500000, 200000),        # another size
        (3000000, 2 * 1024 * 1024),   # over cap -> capped/short
        (4194304, 1000000),       # ends at file end - within EOF
    ]
    outfile = str(tmp_path / "out.bin")
    r = _run_demo(demo_bin, server1m["url"], segs, outfile)
    assert r.returncode == 0, f"demo failed: {r.stderr}\n{r.stdout}"

    # Parse "seg <i> <off> <req> <got>" lines.
    got = {}
    for line in r.stdout.splitlines():
        f = line.split()
        if f and f[0] == "seg":
            got[int(f[1])] = (int(f[2]), int(f[3]), int(f[4]))  # off, req, got

    with open(outfile, "rb") as fh:
        blob = fh.read()

    cursor = 0
    for i, (off, req) in enumerate(segs):
        assert i in got, f"segment {i} missing from demo output"
        g_off, g_req, g_got = got[i]
        assert (g_off, g_req) == (off, req)
        expected_got = min(req, CAP)              # capped, never short of EOF here
        assert g_got == expected_got, (
            f"seg {i}: got {g_got} != expected {expected_got} (req {req}, cap {CAP})")
        block = blob[cursor:cursor + g_got]
        cursor += g_got
        assert block == payload[off:off + g_got], f"seg {i}: bytes not byte-exact"
    assert cursor == len(blob), "trailing/short data in demo output"


def test_short_eof_readv_is_a_clean_error(demo_bin, server1m, tmp_path):
    """A segment that runs short of EOF must surface as a clean client error
    (brix_file_readv returns -1 with status set), not a hang or partial garbage —
    the project's client correctly propagates the server's past-EOF rejection."""
    segs = [(FILE_BYTES - 1000, 65536)]   # 1000 bytes of file, 65536 requested
    outfile = str(tmp_path / "eof.bin")
    r = _run_demo(demo_bin, server1m["url"], segs, outfile)
    assert r.returncode != 0, f"expected readv error, got success:\n{r.stdout}"
    assert "readv" in (r.stderr + r.stdout).lower()
