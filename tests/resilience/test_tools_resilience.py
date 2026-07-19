"""
test_tools_resilience.py — every networked client tool rides out wire loss.

WHAT: drives a spread of tools (xrdfs cat/ls/stat/cksum/mkdir, xrdcp download)
      through the fault proxy's `lossy` sever lever and asserts they recover
      (succeed within the resilience window) instead of failing on the first
      sever — the xrootdfs-parity contract, now centralized in libbrix.

WHY:  proves the resilient seam (client/lib/resilient.c) reaches all tools:
      streaming via brix_rfile, metadata via the baked brix_roundtrip_resilient /
      brix_with_resilience, xrdcp via its own copy.c loop.

HOW:  client -> brix-fault-proxy(lossy) -> dedicated nginx (GSI, port 13901), isolated
      from the main suite. Metadata ops are tiny (few frames) so a high loss rate
      is used to make a sever likely; streaming uses a moderate rate. A wide
      window is given since each recovery pays a re-handshake.

Run:
  PYTHONPATH=tests python3 -m pytest tests/resilience/test_tools_resilience.py -v
"""
import hashlib
import os
import subprocess
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import servers  # noqa: E402

pytestmark = pytest.mark.timeout(360)

DATA = "/t/data.bin"
DATA_SIZE = 24 * 1024 * 1024
WINDOW = 60000   # ms; recovery re-handshakes, so give it room


def _why_skip():
    if not os.path.isfile(servers.NGINX_BIN):
        return f"nginx not built: {servers.NGINX_BIN}"
    if not os.path.isfile(servers.FAULT_PROXY):
        return f"brix-fault-proxy not built: {servers.FAULT_PROXY}"
    if not os.path.isfile(servers.XRDCP):
        return f"xrdcp not built: {servers.XRDCP}"
    return None


_skip_reason = _why_skip()
if _skip_reason:
    pytest.skip(_skip_reason, allow_module_level=True)


@pytest.fixture(scope="module")
def nginx():
    """Dedicated GSI nginx seeded with a data file, a listing dir, and the
    reference md5 of the data file."""
    servers.ensure_pki()
    with servers.NginxGsi() as n:
        src = os.path.join(servers.PREFIX, "tools_src.bin")
        servers.seed_file(os.path.dirname(src), os.path.basename(src), DATA_SIZE)
        servers.seed_file(n.data, DATA, DATA_SIZE, src=src)
        servers.seed_file(n.data, "/t/d/a.bin", 4096)
        servers.seed_file(n.data, "/t/d/b.bin", 4096)
        with open(src, "rb") as fh:
            md5 = hashlib.md5(fh.read()).hexdigest()
        yield types.SimpleNamespace(port=n.port, data=n.data, data_md5=md5)


def _run(argv, window=WINDOW, timeout=120):
    env = servers.gsi_env()
    if window is not None:
        env["XRDC_MAX_STALL_MS"] = str(window)
    return subprocess.run(argv, env=env, capture_output=True, text=True,
                          timeout=timeout)


# --- streaming -------------------------------------------------------------

def test_xrdfs_cat_recovers(nginx, tmp_path):
    """cat rides out mid-stream severs (rfile reopen+resume) and returns the file
    byte-exact."""
    out = tmp_path / "cat.bin"
    env = servers.gsi_env()
    env["XRDC_MAX_STALL_MS"] = str(WINDOW)
    with servers.FaultProxy(nginx.port) as fp:
        fp.set_loss(3)
        with open(out, "wb") as fo:
            r = subprocess.run([servers.XRDFS, fp.url(), "cat", DATA], env=env,
                               stdout=fo, stderr=subprocess.PIPE, timeout=150)
    assert r.returncode == 0, r.stderr.decode(errors="replace")[-300:]
    assert hashlib.md5(out.read_bytes()).hexdigest() == nginx.data_md5


def test_xrdcp_download_recovers(nginx, tmp_path):
    out = tmp_path / "dl.bin"
    with servers.FaultProxy(nginx.port) as fp:
        fp.set_loss(3)
        r = _run([servers.XRDCP, "-f", f"{fp.url()}{DATA}", str(out)], timeout=150)
    assert r.returncode == 0, r.stderr[-300:]
    assert hashlib.md5(out.read_bytes()).hexdigest() == nginx.data_md5


# --- metadata (resilient connect + baked op resilience, inherited by all) ---

@pytest.mark.parametrize("cmd,needle", [
    (["ls", "/t/d"], "a.bin"),
    (["stat", DATA], None),
    (["cksum", DATA], None),
])
def test_xrdfs_metadata_recovers(nginx, cmd, needle):
    """Tiny ops over a lossy link: the loss-fragile multi-RTT GSI connect is
    retried (brix_connect_resilient) and the op itself is resilient, so they
    succeed instead of failing on a severed handshake."""
    with servers.FaultProxy(nginx.port) as fp:
        fp.set_loss(12)
        r = _run([servers.XRDFS, fp.url()] + cmd)
    assert r.returncode == 0, r.stderr[-300:]
    if needle:
        assert needle in r.stdout


# --- mutation: resilient create --------------------------------------------

def test_mkdir_resilient_creates(nginx):
    # Unique name so a persisted data root from a prior run can't pre-create it.
    new = f"/t/mk_resilient_{os.getpid()}_{id(nginx) & 0xffff:x}"
    with servers.FaultProxy(nginx.port) as fp:
        fp.set_loss(12)
        r = _run([servers.XRDFS, fp.url(), "mkdir", new])
    # Under loss the op is retried after a severed connection.  If the FIRST
    # attempt created the directory but its ack was lost, the retry legitimately
    # gets kXR_ItExists — that is still a successful resilient mkdir (the dir is
    # there).  What matters is the end state, confirmed by the stat below.
    assert (r.returncode == 0
            or "ItExists" in r.stderr or "file exists" in r.stderr), r.stderr[-300:]
    # Confirm it really landed (direct, no proxy).
    chk = _run([servers.XRDFS, f"root://127.0.0.1:{nginx.port}/", "stat", new],
               window=0)
    assert chk.returncode == 0, chk.stderr[-200:]
