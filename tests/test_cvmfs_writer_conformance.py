"""Writer ↔ repo_forge.py agreement guard (phase-96 Wave-A exit criterion).

Pins that the product writers (sign.c / object_write.c / catalog_write.c)
byte-agree with the corpus fixture `repo_forge.py` on an identical input —
manifest/whitelist/CAS byte-for-byte, catalogs semantically per-table.
"""

from cmdscripts.cvmfs_writer_conformance import run_checks


def test_cvmfs_writer_forge_agreement(tmp_path):
    results = run_checks(tmp_path)
    assert all(ok for ok, _ in results), "\n".join(
        f"{'ok' if ok else 'FAIL'} {message}" for ok, message in results)
