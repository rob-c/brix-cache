"""Selftest for forge v2 — the Clause registry + build_all materialiser."""
import json

import pytest

# The forge build_all setup is an RSA-keygen storm (~4 min serial): slow lane,
# with a generous ceiling so a CPU-saturated parallel box cannot time it out.
pytestmark = [pytest.mark.slow, pytest.mark.timeout(900)]

import x509forge
from clauses import ALL_CLAUSES


@pytest.fixture(scope="module")
def built_corpus(tmp_path_factory):
    """Materialise the full clause corpus ONCE per module.

    build_all(ALL_CLAUSES) generates ~560 conformance scenarios (a distinct
    keypair per credential + openssl forks for the weak-digest cases), which
    is CPU-bound work whose cost is hardware-dependent: ~80s on the perf host,
    ~320s on a modest dev box (measured).  The two consumers below previously
    each called it, doubling that and — running unmarked in the parallel bulk
    lane at the 30s default timeout — always timing out and crashing xdist
    workers.  Building once here, behind the slow/serial markers on the
    consumers, keeps the corpus smoke test honest without melting the box.

    The consumers deliberately carry NO per-test timeout override: the build
    happens inside whichever of them runs first, so a 240s cap failed the pair
    on any box slower than the perf host.  The module-level 900s budget still
    catches a genuine hang.
    """
    return x509forge.build_all(tmp_path_factory.mktemp("x509conf") / "conf",
                               ALL_CLAUSES)


def test_registry_nonempty_unique():
    assert len(ALL_CLAUSES) >= 6
    ids = [c.id for c in ALL_CLAUSES]
    assert len(ids) == len(set(ids)), "duplicate clause ids"


@pytest.mark.slow
@pytest.mark.serial
def test_build_all_materializes(built_corpus):
    root = built_corpus
    manifest = json.loads((root / "manifest.json").read_text())
    assert len(manifest) == len(ALL_CLAUSES)
    assert (root / "manifest.tsv").exists()
    assert (root / "shared" / "ca").is_dir()
    for r in manifest:
        assert r["clause"] and r["expected"] in ("accept", "reject")
        assert r["group"] in x509forge.GROUPS
        if r["surface"] != "config":
            assert (root / "creds" / r["cred"]).exists(), r["id"]


@pytest.mark.slow
@pytest.mark.serial
def test_shared_ca_dir_has_hash_links(built_corpus):
    root = built_corpus
    names = [p.name for p in (root / "shared" / "ca").iterdir()]
    assert any(n.endswith(".0") for n in names)
