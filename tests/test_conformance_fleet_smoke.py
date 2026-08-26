"""Smoke test: the conformance fleet serves the smoke clause family correctly."""
import json

import pytest

import x509forge
from clauses import ALL_CLAUSES
from wlcg_conformance_fleet import ConformanceFleet

# build_all(ALL_CLAUSES) materialises ~560 scenarios of RSA keygen + openssl
# forks — ~80s idle but 240s+ on a CPU-saturated box (measured 240.3s, right at
# the old ceiling), so it needs generous headroom and must run serially rather
# than 12-wide in a parallel lane where the concurrent keygens crash xdist
# workers.  A timeout here should mean "wedged", never merely "slow under load".
pytestmark = [pytest.mark.x509conf, pytest.mark.slow, pytest.mark.serial,
              pytest.mark.timeout(600)]


def test_fleet_serves_smoke(tmp_path):
    root = x509forge.build_all(tmp_path / "conf", ALL_CLAUSES)
    fleet = ConformanceFleet(root)
    fleet.start()
    try:
        for r in json.loads((root / "manifest.json").read_text()):
            if r["surface"] != "davs":
                continue
            acc, code = fleet.verdict(r["cred"], r["group"])
            assert acc == (r["expected"] == "accept"), \
                f"{r['id']} ({r['title']}): HTTP {code}, expected {r['expected']}"
    finally:
        fleet.stop()
