"""
test_loss_sweep_gsi.py — fast smoke test for the dedicated GSI loss-sweep harness.

WHAT: brings up the self-contained nginx (root://+GSI) and official xrootd
      (root://+GSI) on dedicated ports (servers.py), then proves, with a small
      file, that (a) a clean 0% transfer is byte-exact against both backends and
      (b) the fault proxy's `lossy` lever makes `xrdfs cat` fail *cleanly and
      fast* (no hang) rather than silently truncating.

WHY:  keeps the dedicated harness exercised by the suite without paying for the
      full 256 MiB x 5-rep sweep (that lives in run_loss_sweep.py).  Documents
      that the synchronous `xrdfs cat` CLI does not reconnect mid-read — the
      resilient path is the FUSE driver (see test_xrootdfs_resilience.py).

HOW:  client -> fault_proxy -> {nginx|xrootd}, on ports 13901/13902, isolated
      from the main suite (11094-12126).  Skips cleanly when the official
      xrootd, the repo's nginx, the fault proxy, or libXrdSec is unavailable.

Run:
  PYTHONPATH=tests python3 -m pytest tests/resilience/test_loss_sweep_gsi.py -v
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import servers  # noqa: E402
from run_loss_sweep import measure  # noqa: E402

SIZE = 8 * 1024 * 1024            # small: smoke, not benchmark
TIMEOUT = 30
FILE_PATH = "/loss/small.bin"

pytestmark = pytest.mark.timeout(240)

def _why_skip():
    if not os.path.isfile(servers.NGINX_BIN):
        return f"nginx not built: {servers.NGINX_BIN}"
    if servers.XROOTD_BIN is None:
        return "official `xrootd` not installed"
    if not os.path.isfile(servers.FAULT_PROXY):
        return f"fault_proxy not built: {servers.FAULT_PROXY}"
    if servers.find_sec_lib() is None:
        return "libXrdSec not found"
    return None


_skip_reason = _why_skip()
if _skip_reason:
    pytest.skip(_skip_reason, allow_module_level=True)


@pytest.fixture(scope="module")
def fleet():
    """Dedicated nginx+xrootd (GSI) with an identical small file seeded into
    both data roots.  Yields {name: port}."""
    servers.ensure_pki()
    with servers.NginxGsi() as nginx, servers.XrootdGsi() as xrootd:
        src = os.path.join(servers.PREFIX, "src_small.bin")
        servers.seed_file(os.path.dirname(src), os.path.basename(src), SIZE)
        servers.seed_file(nginx.data, FILE_PATH, SIZE, src=src)
        servers.seed_file(xrootd.data, FILE_PATH, SIZE, src=src)
        yield {"nginx": nginx.port, "xrootd": xrootd.port}


@pytest.mark.parametrize("name", ["nginx", "xrootd"])
def test_baseline_0pct_byte_exact(fleet, name):
    """Clean (no-proxy) GSI cat returns the whole file."""
    url = f"root://127.0.0.1:{fleet[name]}/"
    ok, elapsed, nbytes, why = measure(url, FILE_PATH, SIZE, TIMEOUT)
    assert ok, f"{name} 0% baseline failed: {why}"
    assert nbytes == SIZE


@pytest.mark.parametrize("name", ["nginx", "xrootd"])
def test_through_proxy_0pct_byte_exact(fleet, name):
    """The fault proxy at 0% loss is a transparent passthrough."""
    with servers.FaultProxy(fleet[name]) as fp:
        fp.set_loss(0)
        ok, elapsed, nbytes, why = measure(fp.url(), FILE_PATH, SIZE, TIMEOUT)
    assert ok, f"{name} via proxy 0% failed: {why}"
    assert nbytes == SIZE


@pytest.mark.parametrize("name", ["nginx", "xrootd"])
def test_resilient_recovers_under_loss(fleet, name):
    """With resilience on (default), `xrdfs cat` rides out a lossy link —
    reconnecting + reopening + resuming — and returns the file byte-exact, the
    way xrootdfs does. (Recovery pays a re-handshake per sever, so a wide window
    is given; higher loss simply needs a wider window.)"""
    with servers.FaultProxy(fleet[name]) as fp:
        fp.set_loss(2)
        ok, elapsed, nbytes, why = measure(fp.url(), FILE_PATH, SIZE, 90,
                                           client_max_stall_ms=60000)
    assert ok, f"{name}: resilient cat did not recover under 2% loss: {why}"
    assert nbytes == SIZE


@pytest.mark.parametrize("name", ["nginx", "xrootd"])
def test_no_retry_fails_fast(fleet, name):
    """The escape hatch: XRDC_MAX_STALL_MS=0 restores the legacy fail-fast path —
    a sever fails the transfer immediately rather than retrying."""
    with servers.FaultProxy(fleet[name]) as fp:
        fp.set_loss(15)
        ok, elapsed, nbytes, why = measure(fp.url(), FILE_PATH, SIZE, TIMEOUT,
                                           client_max_stall_ms=0)
    assert not ok, f"{name}: expected fail-fast with resilience off, got success"
    assert why != "timeout", f"{name}: hung instead of failing fast"
    assert nbytes < SIZE
