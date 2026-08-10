"""Phase-88 W2 — ``pblock-fsck`` and the packed small-blob arena.

The arena moves a small blob's bytes out of ``data/<aa>/<bb>/<blob>/0`` into a
shared ``pack/seg-<n>.dat`` record indexed by the catalog ``pack`` table, so
fsck's classic "row with no blob dir" rule would misfire catastrophically:
every healthy packed object would be DANGLING and ``--gc`` would delete its
namespace row. These tests pin the corrected contract:

  * SUCCESS      — a packed object is CLEAN (no DANGLING), ``--verify-csi``
                   re-CRCs its record, and ``--gc`` leaves it alone (the
                   regression leg); a size divergence is a PACK-SIZE finding.
  * ERROR        — crash residue is found and reclaimed: a dual-layout blob
                   (record + leftover striped copy) loses the striped copy
                   under ``--gc``; an orphan pack row is deleted; a segment
                   with no remaining rows is reaped whole; an orphan record
                   (append landed, index insert did not) is reported.
  * SECURITY-NEG — a bit-flipped record is a PACK crc finding under
                   ``--verify-csi``; a torn tail is PACK-TORN. Damage is
                   reported, never silently "repaired".

State is fabricated directly (catalog rows + format-exact "BXS1" records —
the byte layout is single-sourced in shared/cache/cas_pack_format.h and pinned
producer-side by sd_pblock_unittest_pack.c), exactly how the replay/crash fsck
suites fabricate their scenarios.
"""

from __future__ import annotations

import sqlite3
import struct
import subprocess
import zlib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FSCK_SRC = REPO_ROOT / "tools/pblock-fsck/pblock-fsck.c"

SEG_HDR = 28
BLOB_A = "aabb" + "0" * 28          # 32-hex blob ids, like the real generator
BLOB_B = "ccdd" + "1" * 28
PAYLOAD_A = b"packed-arena-fsck-payload-A"
PAYLOAD_B = b"second-record-payload-B"


@pytest.fixture(scope="module")
def fsck(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Compile the standalone oracle once (single-file cc contract)."""
    out = tmp_path_factory.mktemp("fsck") / "pblock-fsck"
    cflags = subprocess.run(["pkg-config", "--cflags", "sqlite3"],
                            capture_output=True, text=True).stdout.split()
    libs = subprocess.run(["pkg-config", "--libs", "sqlite3"],
                          capture_output=True, text=True).stdout.split() \
        or ["-lsqlite3"]
    rc = subprocess.run(["cc", "-O2", "-Wall", "-Wextra", *cflags,
                         "-o", str(out), str(FSCK_SRC), *libs],
                        capture_output=True, text=True)
    if rc.returncode:
        pytest.fail(f"pblock-fsck build failed: {rc.stderr}")
    return out


def _record(key: str, data: bytes) -> bytes:
    """One format-exact segment record (cas_pack_format.h: 'BXS1' · u16 klen ·
    u8 fmt · u8 rsvd · u32 crc32(data) · u64 stored · u64 raw · key · data)."""
    k = key.encode()
    return struct.pack("<IHBBIQQ", 0x31535842, len(k), 0, 0,
                       zlib.crc32(data) & 0xFFFFFFFF,
                       len(data), len(data)) + k + data


def _mk_export(root: Path, *, objects, pack_rows, seg_records) -> None:
    """Fabricate a pack-armed export: minimal catalog (the columns fsck
    queries) + segment files holding format-exact records."""
    (root / "data").mkdir(parents=True)
    (root / "pack").mkdir()
    db = sqlite3.connect(root / "catalog.db")
    db.execute("CREATE TABLE objects(path TEXT PRIMARY KEY, is_dir INT,"
               " blob_id TEXT, size INT, block_size INT);")
    db.execute("CREATE TABLE pack(blob_id TEXT PRIMARY KEY, seg INT,"
               " off INT, len INT);")
    for path, blob, size in objects:
        db.execute("INSERT INTO objects VALUES(?, 0, ?, ?, 4096);",
                   (path, blob, size))
    for blob, seg, off, length in pack_rows:
        db.execute("INSERT INTO pack VALUES(?, ?, ?, ?);",
                   (blob, seg, off, length))
    db.commit()
    db.close()
    for seg, payload in seg_records.items():
        (root / "pack" / f"seg-{seg}.dat").write_bytes(payload)


def _run(fsck: Path, root: Path, *args: str):
    p = subprocess.run([str(fsck), str(root), *args],
                       capture_output=True, text=True, timeout=60)
    return p.returncode, p.stdout


class TestPackClean:
    def test_packed_object_is_not_dangling(self, fsck, tmp_path):
        """SUCCESS + the regression: a healthy packed object is CLEAN — no
        DANGLING finding, and --gc must not delete its row."""
        root = tmp_path / "exp"
        rec = _record(BLOB_A, PAYLOAD_A)
        _mk_export(root,
                   objects=[("/f1", BLOB_A, len(PAYLOAD_A))],
                   pack_rows=[(BLOB_A, 1, 0, len(PAYLOAD_A))],
                   seg_records={1: rec})
        rc, out = _run(fsck, root, "--verify-csi")
        assert rc == 0 and "DANGLING" not in out, \
            f"healthy packed object misjudged (rc={rc}):\n{out}"

        rc, out = _run(fsck, root, "--gc")
        assert rc == 0, f"--gc on a healthy packed export found work:\n{out}"
        db = sqlite3.connect(root / "catalog.db")
        n = db.execute("SELECT COUNT(*) FROM objects;").fetchone()[0]
        db.close()
        assert n == 1, "--gc deleted a healthy packed object's row"

    def test_size_divergence_is_a_finding(self, fsck, tmp_path):
        """SUCCESS/divergence: catalog size != record length → PACK-SIZE."""
        root = tmp_path / "exp"
        rec = _record(BLOB_A, PAYLOAD_A)
        _mk_export(root,
                   objects=[("/f1", BLOB_A, len(PAYLOAD_A) + 7)],
                   pack_rows=[(BLOB_A, 1, 0, len(PAYLOAD_A))],
                   seg_records={1: rec})
        rc, out = _run(fsck, root)
        assert rc == 1 and "PACK-SIZE /f1" in out, \
            f"size divergence not reported (rc={rc}):\n{out}"


class TestPackResidue:
    def test_dual_layout_reclaimed(self, fsck, tmp_path):
        """ERROR/residue: record + leftover striped copy → finding; --gc drops
        the striped copy and the export converges to clean."""
        root = tmp_path / "exp"
        rec = _record(BLOB_A, PAYLOAD_A)
        _mk_export(root,
                   objects=[("/f1", BLOB_A, len(PAYLOAD_A))],
                   pack_rows=[(BLOB_A, 1, 0, len(PAYLOAD_A))],
                   seg_records={1: rec})
        leaf = root / "data" / BLOB_A[0:2] / BLOB_A[2:4] / BLOB_A
        leaf.mkdir(parents=True)
        (leaf / "0").write_bytes(PAYLOAD_A)

        rc, out = _run(fsck, root)
        assert rc == 1 and f"PACK {BLOB_A} dual-layout" in out, \
            f"dual layout not reported (rc={rc}):\n{out}"
        rc, _ = _run(fsck, root, "--gc")
        assert rc == 1
        assert not leaf.exists(), "--gc left the redundant striped copy"
        rc, out = _run(fsck, root)
        assert rc == 0, f"did not converge to clean after --gc:\n{out}"

    def test_orphans_reported_and_segment_reaped(self, fsck, tmp_path):
        """ERROR/residue: an orphan pack row is deleted by --gc; an orphan
        record is reported; a segment whose rows all died is reaped whole."""
        root = tmp_path / "exp"
        rec_a = _record(BLOB_A, PAYLOAD_A)          # indexed, but unreferenced
        rec_b = _record(BLOB_B, PAYLOAD_B)          # appended, never indexed
        _mk_export(root,
                   objects=[],                       # nothing references A
                   pack_rows=[(BLOB_A, 1, 0, len(PAYLOAD_A))],
                   seg_records={1: rec_a + rec_b})
        rc, out = _run(fsck, root)
        assert rc == 1, f"expected findings:\n{out}"
        assert f"PACK-ORPHAN-ROW {BLOB_A}" in out, out
        assert f"PACK-ORPHAN-REC seg=1 off={len(rec_a)}" in out, out

        rc, _ = _run(fsck, root, "--gc")
        assert rc == 1
        db = sqlite3.connect(root / "catalog.db")
        n = db.execute("SELECT COUNT(*) FROM pack;").fetchone()[0]
        db.close()
        assert n == 0, "--gc left the orphan pack row"
        assert not (root / "pack" / "seg-1.dat").exists(), \
            "--gc left a segment no row references"
        rc, out = _run(fsck, root)
        assert rc == 0, f"did not converge to clean:\n{out}"


class TestPackDamage:
    def test_bit_flip_is_a_crc_finding(self, fsck, tmp_path):
        """SECURITY-NEG: a flipped payload byte → PACK crc under --verify-csi;
        never silently repaired (the record survives the run)."""
        root = tmp_path / "exp"
        rec = bytearray(_record(BLOB_A, PAYLOAD_A))
        rec[SEG_HDR + len(BLOB_A) + 3] ^= 0x40      # payload byte
        _mk_export(root,
                   objects=[("/f1", BLOB_A, len(PAYLOAD_A))],
                   pack_rows=[(BLOB_A, 1, 0, len(PAYLOAD_A))],
                   seg_records={1: bytes(rec)})
        rc, out = _run(fsck, root, "--verify-csi")
        assert rc == 1 and f"PACK {BLOB_A} seg=1 crc" in out, \
            f"crc damage not reported (rc={rc}):\n{out}"
        assert (root / "pack" / "seg-1.dat").exists()

    def test_torn_tail_reported(self, fsck, tmp_path):
        """SECURITY-NEG: a record cut mid-payload is PACK-TORN, and the intact
        indexed record before it still verifies clean."""
        root = tmp_path / "exp"
        rec_a = _record(BLOB_A, PAYLOAD_A)
        rec_b = _record(BLOB_B, PAYLOAD_B)
        _mk_export(root,
                   objects=[("/f1", BLOB_A, len(PAYLOAD_A))],
                   pack_rows=[(BLOB_A, 1, 0, len(PAYLOAD_A))],
                   seg_records={1: rec_a + rec_b[:SEG_HDR + 10]})
        rc, out = _run(fsck, root, "--verify-csi")
        assert rc == 1 and f"PACK-TORN seg=1 off={len(rec_a)}" in out, \
            f"torn tail not reported (rc={rc}):\n{out}"
        assert f"PACK {BLOB_A}" not in out, \
            f"the intact record was misjudged:\n{out}"
