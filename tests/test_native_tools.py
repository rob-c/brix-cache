"""
Native Tier-1 tools (phase-37 §14): xrdcrc32c, xrdadler32, xrdqstats, wait41,
xrdprep — thin front-ends over the clean-room client library (libXrdCl-free).

Run (serial, against a manually-started fleet):
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
    pytest tests/test_native_tools.py -v -p no:xdist
"""

import os
import re
import shutil
import subprocess
import zlib

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST

pytestmark = pytest.mark.timeout(120)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANON_URL = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"
_CLEAN_ENV = {k: v for k, v in os.environ.items()}
_CLEAN_ENV.pop("X509_USER_PROXY", None)
_CLEAN_ENV.pop("X509_CERT_DIR", None)

TOOLS = ["xrdcrc32c", "xrdadler32", "xrdqstats", "wait41-brix", "xrdprep"]

# Standard reflected CRC32c (Castagnoli, init/xorout 0xFFFFFFFF) — matches the
# client's libxrdproto routine (see test_native_xrdcp_xrdfs.py).
_POLY = 0x82F63B78
_TAB = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (_POLY if (_c & 1) else 0)
    _TAB.append(_c & 0xFFFFFFFF)


def _crc32c(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ _TAB[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFFFFFF


@pytest.fixture(scope="module")
def tools():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    proc = subprocess.run(["make", "-C", os.path.join(REPO, "client")],
                          capture_output=True, text=True, timeout=180)
    paths = {t: os.path.join(REPO, "client", "bin", t) for t in TOOLS}
    if proc.returncode != 0 or not all(os.path.exists(p) for p in paths.values()):
        pytest.skip(f"tool build failed:\n{proc.stdout}\n{proc.stderr}")
    return paths


def _run(path, *args, timeout=20):
    return subprocess.run([path, *args], capture_output=True, text=True,
                          env=_CLEAN_ENV, timeout=timeout)


@pytest.fixture
def seeded():
    name = f"_tool_{os.getpid()}.bin"
    path = os.path.join(DATA_ROOT, name)
    payload = os.urandom(40000)
    with open(path, "wb") as fh:
        fh.write(payload)
    try:
        yield name, path, payload
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


# ---- xrdcrc32c ----

def test_xrdcrc32c_local_and_remote(tools, seeded):
    name, path, payload = seeded
    want = "%08x" % _crc32c(payload)
    rl = _run(tools["xrdcrc32c"], path)
    assert rl.returncode == 0 and rl.stdout.split()[0] == want, rl.stdout
    rr = _run(tools["xrdcrc32c"], f"{ANON_URL}//{name}")
    assert rr.returncode == 0 and rr.stdout.split()[0] == want, rr.stdout


# ---- xrdadler32 ----

def test_xrdadler32_local_and_remote(tools, seeded):
    name, path, payload = seeded
    want = "%08x" % (zlib.adler32(payload) & 0xffffffff)
    rl = _run(tools["xrdadler32"], path)
    assert rl.returncode == 0 and rl.stdout.split()[0] == want, rl.stdout
    rr = _run(tools["xrdadler32"], f"{ANON_URL}//{name}")
    assert rr.returncode == 0 and rr.stdout.split()[0] == want, rr.stdout


# ---- xrdqstats ----

def test_xrdqstats_stats(tools):
    r = _run(tools["xrdqstats"], f"{SERVER_HOST}:{NGINX_ANON_PORT}")
    assert r.returncode == 0 and r.stdout.strip(), r.stderr


def test_xrdqstats_config(tools):
    r = _run(tools["xrdqstats"], "-c", "tpc", f"{SERVER_HOST}:{NGINX_ANON_PORT}")
    assert r.returncode == 0 and r.stdout.strip() != "", r.stderr


# ---- wait41 ----

def test_wait41_ready(tools):
    r = _run(tools["wait41-brix"], "--timeout", "5", f"{SERVER_HOST}:{NGINX_ANON_PORT}")
    assert r.returncode == 0, r.stderr
    assert "ready" in r.stdout


def test_wait41_timeout(tools):
    # A port with nothing listening → non-zero within ~2s.
    r = _run(tools["wait41-brix"], "--timeout", "2", f"{SERVER_HOST}:12977", timeout=10)
    assert r.returncode != 0, "wait41 reported ready on a closed port"


# ---- xrdprep ----

def test_xrdprep_stage(tools, seeded):
    name, _, _ = seeded
    r = _run(tools["xrdprep"], "-s", f"{SERVER_HOST}:{NGINX_ANON_PORT}", f"/{name}")
    assert r.returncode == 0, r.stderr


def test_xrdprep_evict(tools, seeded):
    name, _, _ = seeded
    r = _run(tools["xrdprep"], "-e", f"{SERVER_HOST}:{NGINX_ANON_PORT}", f"/{name}")
    assert r.returncode == 0, r.stderr


# ---- clean-room linkage ----

@pytest.mark.parametrize("tool", TOOLS)
def test_tool_no_libbrixl(tools, tool):
    out = subprocess.run(["ldd", tools[tool]], capture_output=True, text=True).stdout
    bad = [ln for ln in out.splitlines() if re.search(r"XrdCl|XrdSec|libXrd", ln)]
    assert not bad, f"{tool} links upstream xrootd libs:\n{out}"


# --------------------------------------------------------------------------
# mpxstats (phase-37 §14.5): parse-only /metrics aggregator
# Self-contained — builds the specific target + feeds a canned blob on stdin.
# --------------------------------------------------------------------------

MPXSTATS = os.path.join(REPO, "client", "bin", "mpxstats-brix")


@pytest.fixture(scope="module")
def mpxstats_bin():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    proc = subprocess.run(["make", "-C", os.path.join(REPO, "client"), "mpxstats-brix"],
                          capture_output=True, text=True, timeout=180)
    if proc.returncode != 0 or not os.path.exists(MPXSTATS):
        pytest.skip(f"mpxstats build failed:\n{proc.stdout}\n{proc.stderr}")
    return MPXSTATS


def test_mpxstats_aggregates_stdin(mpxstats_bin):
    blob = ("# HELP x\n"
            'brix_requests_total{op="stat"} 5\n'
            'brix_requests_total{op="read"} 9\n'
            'brix_bytes_total{port="11094"} 1000\n')
    p = subprocess.run([mpxstats_bin, "-"], input=blob, capture_output=True,
                       text=True, timeout=20)
    assert p.returncode == 0, p.stderr
    out = p.stdout
    # the two requests_total series fold into one metric with summed value 14
    assert re.search(r"brix_requests_total\s+2\s+14", out), out
    assert re.search(r"brix_bytes_total\s+1\s+1000", out), out
    assert "2 metric name(s), 3 series" in out, out


def test_mpxstats_no_libbrixl(mpxstats_bin):
    out = subprocess.run(["ldd", mpxstats_bin], capture_output=True, text=True).stdout
    assert not re.search(r"XrdCl|XrdSec|libXrd", out), out
