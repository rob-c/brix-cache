"""Server-side-only TPC against a STOCK xrootd GSI source (`--tpc only` gate).

This is the interop gate for the long-open "native TPC vs stock `ofs.tpc` source"
item: unlike `--tpc first` (test_tpc_gsi_outbound.py), `--tpc only` forbids the
client-mediated fallback, so it passes ONLY when the nginx destination performs a
genuine server-side pull whose rendezvous facts (tpc.key / tpc.org / lfn / dest
host) exact-match the authorization the client registered on the stock source
(XrdOfsTPCInfo::Match is a raw strcmp on all four).

Reuses the `gsi_tpc` fixture (stock GSI source + nginx TPC destination) from
test_tpc_gsi_outbound.py.
"""
from pathlib import Path

import pytest

from test_tpc_gsi_outbound import XRDCP, _run, gsi_tpc  # noqa: F401  (fixture)

pytestmark = pytest.mark.uses_lifecycle_harness


def test_tpc_only_stock_gsi_source(gsi_tpc):  # noqa: F811
    """`xrdcp --tpc only` from a stock GSI source must complete server-side."""
    src = f"{gsi_tpc['src_url']}//gsidata/hello.txt"
    dst = f"{gsi_tpc['dst_url']}//pulled-only.txt"

    r = _run([XRDCP, "-f", "-s", "--tpc", "only", src, dst], env=gsi_tpc["env"])

    pulled = Path(gsi_tpc["dst_data"]) / "pulled-only.txt"
    if r.returncode != 0 or not pulled.exists():
        err = Path(gsi_tpc["logs"]) / "nginx-err.log"
        tail = ""
        if err.exists():
            tail = "\n".join(err.read_text(errors="replace").splitlines()[-40:])
        pytest.fail(
            f"--tpc only against stock GSI source failed (rc={r.returncode}).\n"
            f"xrdcp stdout: {r.stdout}\nxrdcp stderr: {r.stderr}\n"
            f"--- nginx dest error.log tail ---\n{tail}")

    assert pulled.read_text() == "hello-tpc-gsi\n"
