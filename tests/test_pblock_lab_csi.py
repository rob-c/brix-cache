"""Phase-83 F3 — per-block CRC32c integrity (CSI) over a live pblock export.

With `csi=1` in the backend `?tail`, the driver keeps one CRC32c (Castagnoli,
INVARIANT 1/9) per pblock block at rest in a `csi(blob_id, block_no, crc)`
catalog table: computed on write (staged commit / pwrite-close / server_copy),
snapshotted into a handle-local array at open, and verified purely in memory on
every read. The block granule IS the CSI granule (one CRC per block file); the
table is keyed by blob_id (rename-stable) not by logical path. The tests prove:
clean files round-trip and their CRCs survive a rename (success); a byte flipped
in a block file on disk makes the read fail closed rather than serve corruption
(error); and corrupting the *tag* itself — data untouched — also fails closed,
because the driver trusts the at-rest CRC, not the bytes (security-neg).
"""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import subprocess
import time

import pytest

from cmdscripts.live_common import LiveRun, REPO_ROOT, random_file, sha256
from cmdscripts.pblock_live import XRDCP, XRDFS, pblock_lab_spec

pytestmark = pytest.mark.uses_lifecycle_harness

FSCK_SRC = REPO_ROOT / "tools/pblock-fsck/pblock-fsck.c"


@pytest.fixture(scope="module")
def fsck(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Compile the standalone --verify-csi oracle once for the module."""
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


def _fsck(binary: Path, root: Path, *flags: str) -> subprocess.CompletedProcess:
    return subprocess.run([str(binary), str(root), *flags],
                          capture_output=True, text=True)


def _blob_id(catalog: Path, path: str) -> str:
    conn = sqlite3.connect(str(catalog), timeout=10)
    try:
        row = conn.execute(
            "SELECT blob_id FROM objects WHERE path = ?;", (path,)).fetchone()
    finally:
        conn.close()
    assert row is not None and row[0], f"no objects row / blob for {path}"
    return row[0]


def _csi_rows(catalog: Path, blob_id: str) -> dict[int, int]:
    conn = sqlite3.connect(str(catalog), timeout=10)
    try:
        rows = conn.execute(
            "SELECT block_no, crc FROM csi WHERE blob_id = ?;",
            (blob_id,)).fetchall()
    finally:
        conn.close()
    return {int(b): int(c) for b, c in rows}


def _block_file(root: Path, blob_id: str, idx: int) -> Path:
    """Mirror pblock_block_path: <root>/data/<b0b1>/<b2b3>/<blob_id>/<idx>."""
    return (root / "data" / blob_id[0:2] / blob_id[2:4] / blob_id
            / str(idx))


def _flip_byte(path: Path, off: int = 0) -> None:
    data = bytearray(path.read_bytes())
    assert off < len(data), f"offset {off} past block file {path} ({len(data)})"
    data[off] ^= 0xFF
    path.write_bytes(bytes(data))


def _need_bins() -> None:
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    if not XRDCP.exists():
        pytest.skip("xrdcp not built")


@pytest.mark.optin
@pytest.mark.timeout(150)
def test_csi_clean_roundtrip_and_survives_rename(lifecycle, fsck: Path) -> None:
    """(success) A multi-block PUT lands one CRC row per block; the file reads
    back byte-exact under verification; the offline oracle is quiet; and because
    the table is keyed by blob_id (rename is a pure catalog row-move that keeps
    the blob), the CRCs survive a rename and the renamed object verifies clean."""
    _need_bins()
    with LiveRun("pblock_csi_ok", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-csi-ok", "?csi=1"))
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        host = f"root://{ep.host}:{ep.port}"
        hub = f"{host}/"
        src = run.root / "src.bin"
        random_file(src, 2_500_000)   # 3 blocks at 1m stripe

        assert run.call([XRDCP, "-f", src, f"{hub}f.bin"],
                        check=False).returncode == 0

        blob = _blob_id(catalog, "/f.bin")
        crcs = _csi_rows(catalog, blob)
        # 2_500_000 / 1_048_576 → blocks 0,1,2 all get a CRC row.
        assert set(crcs) == {0, 1, 2}, f"expected 3 CRC rows, got {crcs}"

        # Offline oracle agrees the block bytes match their recorded CRCs.
        root = Path(ep.data_root)
        clean = _fsck(fsck, root, "--verify-csi")
        assert clean.returncode == 0, \
            f"fsck flagged a clean store: rc={clean.returncode} {clean.stdout}"
        assert "CSI " not in clean.stdout, f"unexpected CSI finding: {clean.stdout}"

        got = run.root / "got.bin"
        assert run.call([XRDCP, "-f", f"{hub}f.bin", got],
                        check=False).returncode == 0
        assert got.exists() and sha256(got) == sha256(src), "GET not byte-exact"

        # Rename keeps the blob → the CRC rows are unchanged and still apply.
        assert run.call([XRDFS, host, "mv", "/f.bin", "/g.bin"],
                        check=False).returncode == 0
        assert _blob_id(catalog, "/g.bin") == blob, "rename changed the blob"
        assert _csi_rows(catalog, blob) == crcs, "CRC rows lost across rename"

        got2 = run.root / "got2.bin"
        assert run.call([XRDCP, "-f", f"{hub}g.bin", got2],
                        check=False).returncode == 0
        assert got2.exists() and sha256(got2) == sha256(src), \
            "renamed object failed to verify / read byte-exact"


@pytest.mark.optin
@pytest.mark.timeout(120)
def test_csi_flipped_block_fails_closed(lifecycle, fsck: Path) -> None:
    """(error) Flip a byte in a block file on disk. The at-rest CRC no longer
    matches, so the read fails with an I/O error — the corrupt bytes are never
    served — the offline oracle pinpoints the bad block — while a sibling file
    whose blocks are untouched still reads clean (per-block, not blanket)."""
    _need_bins()
    with LiveRun("pblock_csi_flip", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-csi-flip", "?csi=1"))
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        data = Path(ep.data_root)
        hub = f"root://{ep.host}:{ep.port}/"
        src = run.root / "src.bin"
        random_file(src, 2_500_000)

        assert run.call([XRDCP, "-f", src, f"{hub}bad.bin"],
                        check=False).returncode == 0
        assert run.call([XRDCP, "-f", src, f"{hub}ok.bin"],
                        check=False).returncode == 0

        # Corrupt block 1 of bad.bin directly on disk (data path, not the tag).
        bad_blob = _blob_id(catalog, "/bad.bin")
        blk1 = _block_file(data, bad_blob, 1)
        assert blk1.exists(), f"block-1 file missing: {blk1}"
        _flip_byte(blk1, off=17)

        # The offline oracle pinpoints the corrupted block (exit 1, one CSI line).
        report = _fsck(fsck, data, "--verify-csi")
        assert report.returncode == 1, \
            f"fsck did not flag the flip: rc={report.returncode} {report.stdout}"
        csi_lines = [ln for ln in report.stdout.splitlines()
                     if ln.startswith("CSI ")]
        assert any("/bad.bin" in ln and "block=1" in ln for ln in csi_lines), \
            f"oracle missed bad.bin block 1: {report.stdout}"
        assert not any("/ok.bin" in ln for ln in csi_lines), \
            f"oracle wrongly flagged the clean sibling: {report.stdout}"

        # The GET must fail — never hand back the corrupted stream.
        got = run.root / "got.bin"
        rc = run.call([XRDCP, "-f", f"{hub}bad.bin", got], check=False).returncode
        assert rc != 0, "GET of a corrupted block succeeded (served bad bytes!)"
        assert not (got.exists() and sha256(got) == sha256(src)), \
            "corrupted GET produced a byte-exact copy — verify did not fire"

        # The untouched sibling still round-trips: failure is per-block.
        good = run.root / "good.bin"
        assert run.call([XRDCP, "-f", f"{hub}ok.bin", good],
                        check=False).returncode == 0
        assert good.exists() and sha256(good) == sha256(src), \
            "unrelated file broke — CSI failure was not scoped to the bad block"


@pytest.mark.optin
@pytest.mark.timeout(120)
def test_csi_tag_tamper_fails_closed(lifecycle) -> None:
    """(security-neg) Corrupt the *tag* row itself — the on-disk data is left
    pristine — and the read still fails closed. The driver trusts the at-rest
    CRC as the source of truth, so a tampered/desynced csi table cannot be used
    to smuggle a mismatch past the reader (it is never 'the bytes look fine, so
    serve them')."""
    _need_bins()
    with LiveRun("pblock_csi_tag", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-csi-tag", "?csi=1"))
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        hub = f"root://{ep.host}:{ep.port}/"
        src = run.root / "src.bin"
        random_file(src, 2_500_000)

        assert run.call([XRDCP, "-f", src, f"{hub}t.bin"],
                        check=False).returncode == 0
        blob = _blob_id(catalog, "/t.bin")
        crcs = _csi_rows(catalog, blob)
        assert 1 in crcs, f"no CRC row for block 1: {crcs}"

        # Flip the stored CRC for block 1 to a value that cannot be 0 (the
        # unset sentinel) and differs from the honest CRC. Data untouched.
        bad = (crcs[1] ^ 0xA5A5A5A5) & 0xFFFFFFFF
        if bad == 0:
            bad = 1
        conn = sqlite3.connect(str(catalog), timeout=10)
        try:
            conn.execute("UPDATE csi SET crc = ? WHERE blob_id = ? "
                         "AND block_no = 1;", (bad, blob))
            conn.commit()
        finally:
            conn.close()

        got = run.root / "got.bin"
        rc = run.call([XRDCP, "-f", f"{hub}t.bin", got], check=False).returncode
        assert rc != 0, "GET succeeded despite a tampered CSI tag (not fail-closed)"
        assert not (got.exists() and sha256(got) == sha256(src)), \
            "tampered-tag GET produced a byte-exact copy — verify did not fire"
