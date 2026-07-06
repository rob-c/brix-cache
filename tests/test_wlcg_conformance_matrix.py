"""The 500+ clause matrix on the live davs:// wire.

Every davs-surface clause runs against the ConformanceFleet — a fixed set of
long-lived servers, one per config-group on the shared multi-CA directory.  A
PASS proves the production WebDAV verification path (auth_cert.c ->
brix_gsi_verify_chain) reaches the same verdict the manifest asserts, i.e. the
same decision the C oracle validates in bulk.

Marked slow; the whole matrix runs in a couple of minutes against the pre-stood
fleet.  Proxy (PXY) cases run through the C oracle (WebDAV refuses proxies) and
are covered by tests/c/run_x509_oracle.sh, not here.
"""
import json
import os
from pathlib import Path

import pytest

import x509forge
from clauses import ALL_CLAUSES
from wlcg_conformance_fleet import ConformanceFleet

# Building 559 certs takes longer than the default 30s per-test cap.
pytestmark = [pytest.mark.x509conf, pytest.mark.slow, pytest.mark.timeout(1200)]


@pytest.fixture(scope="module")
def fleet(tmp_path_factory):
    # Reuse a pre-built fixture tree if BRIX_X509_MATRIX points at one (the
    # runner builds it once outside pytest to dodge the per-test timeout).
    pre = os.environ.get("BRIX_X509_MATRIX")
    if pre and (Path(pre) / "manifest.json").exists():
        root = Path(pre)
    else:
        root = x509forge.build_all(tmp_path_factory.mktemp("matrix"),
                                   ALL_CLAUSES)
    f = ConformanceFleet(root)
    f.start()
    yield root, f
    f.stop()


def _davs_rows(root):
    return [r for r in json.loads((root / "manifest.json").read_text())
            if r["surface"] == "davs"]


def test_matrix_davs(fleet):
    root, f = fleet
    failures = []
    for r in _davs_rows(root):
        accepted, code = f.verdict(r["cred"], r["group"])
        if accepted != (r["expected"] == "accept"):
            failures.append(f"{r['id']} [{r['clause']}] {r['title']}: "
                            f"expected {r['expected']}, HTTP {code}")
    assert not failures, (
        f"{len(failures)} wire-verdict mismatches:\n" + "\n".join(failures[:60]))
