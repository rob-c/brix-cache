"""Selftest for forge v2 — the Clause registry + build_all materialiser."""
import json

import x509forge
from clauses import ALL_CLAUSES


def test_registry_nonempty_unique():
    assert len(ALL_CLAUSES) >= 6
    ids = [c.id for c in ALL_CLAUSES]
    assert len(ids) == len(set(ids)), "duplicate clause ids"


def test_build_all_materializes(tmp_path):
    root = x509forge.build_all(tmp_path / "conf", ALL_CLAUSES)
    manifest = json.loads((root / "manifest.json").read_text())
    assert len(manifest) == len(ALL_CLAUSES)
    assert (root / "manifest.tsv").exists()
    assert (root / "shared" / "ca").is_dir()
    for r in manifest:
        assert r["clause"] and r["expected"] in ("accept", "reject")
        assert r["group"] in x509forge.GROUPS
        if r["surface"] != "config":
            assert (root / "creds" / r["cred"]).exists(), r["id"]


def test_shared_ca_dir_has_hash_links(tmp_path):
    root = x509forge.build_all(tmp_path / "conf", ALL_CLAUSES)
    names = [p.name for p in (root / "shared" / "ca").iterdir()]
    assert any(n.endswith(".0") for n in names)
