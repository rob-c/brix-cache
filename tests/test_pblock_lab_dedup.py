"""Phase-83 F10 — content-addressed dedup + refcounted blobs (pblock).

With `dedup=1` in the backend `?tail`, the driver keeps a
`blobs(blob_id, refcount, size, block_size, content_hash)` table so several
`objects` rows can share one physical blob. Identical PUTs fold onto a single
blob at publish time (a whole-object CRC nominates candidates; a mandatory
byte-verify confirms them, so a hash collision or a forged row can never make
differing content alias). A write to a shared blob first breaks the share by
copying its blocks to a fresh private blob — the sibling is never disturbed.
server_copy is an O(metadata) refcount bump.

The tests plant/observe state through the catalog (`objects.blob_id` says which
blob backs a path, `blobs.refcount` says how many rows share it) and use the
`pblock-fsck --verify-refs` oracle to prove the refcount ledger stays honest.

Proves: identical PUTs share one blob (refcount 2) and read back byte-exact,
and removing one sharer leaves the other intact at refcount 1 (success);
overwriting a shared path forks a private blob without disturbing the sibling
(error/CoW); a forged `content_hash` cannot alias differing content — the
byte-verify rejects it — and a gate-off export keeps identical PUTs distinct
(security-neg). A deliberately corrupted refcount is caught by `--verify-refs`.
"""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import subprocess
import time

import pytest

from cmdscripts.live_common import LiveRun, random_file, sha256
from cmdscripts.pblock_live import XRDCP, XRDFS, pblock_lab_spec

pytestmark = pytest.mark.uses_lifecycle_harness

REPO_ROOT = Path(__file__).resolve().parent.parent
FSCK_SRC = REPO_ROOT / "tools/pblock-fsck/pblock-fsck.c"


def _need_bins() -> None:
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    if not XRDCP.exists():
        pytest.skip("xrdcp not built")


@pytest.fixture(scope="module")
def fsck(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("fsck") / "pblock-fsck"
    cflags = subprocess.run(["pkg-config", "--cflags", "sqlite3"],
                            capture_output=True, text=True).stdout.split()
    libs = subprocess.run(["pkg-config", "--libs", "sqlite3"],
                          capture_output=True, text=True).stdout.split() \
        or ["-lsqlite3"]
    rc = subprocess.run(["cc", "-O2", "-Wall", "-Wextra", *cflags,
                         str(FSCK_SRC), *libs, "-o", str(out)],
                        capture_output=True, text=True)
    if rc.returncode != 0:
        pytest.fail(f"pblock-fsck build failed: {rc.stderr}")
    return out


def _blob_id(catalog: Path, path: str) -> str:
    conn = sqlite3.connect(str(catalog), timeout=10)
    try:
        row = conn.execute(
            "SELECT blob_id FROM objects WHERE path = ?", (path,)).fetchone()
        return row[0] if row else ""
    finally:
        conn.close()


def _refcount(catalog: Path, blob_id: str) -> int:
    """Tracked refcount, or -1 for the implicit single reference — a missing row
    OR (gate off) a missing blobs table entirely."""
    conn = sqlite3.connect(str(catalog), timeout=10)
    try:
        row = conn.execute(
            "SELECT refcount FROM blobs WHERE blob_id = ?", (blob_id,)
        ).fetchone()
        return row[0] if row else -1
    except sqlite3.OperationalError:
        return -1                          # no blobs table ⇒ dedup gate off
    finally:
        conn.close()


def _run_fsck(fsck: Path, root: Path) -> subprocess.CompletedProcess:
    return subprocess.run([str(fsck), str(root), "--verify-refs"],
                          capture_output=True, text=True)


@pytest.mark.optin
@pytest.mark.timeout(150)
def test_dedup_identical_puts_share_blob(lifecycle, fsck: Path) -> None:
    """(success) Two identical PUTs fold onto one blob (refcount 2) and read
    back byte-exact; removing one sharer decrements to 1 and the survivor is
    untouched; the refcount ledger passes --verify-refs throughout."""
    _need_bins()
    with LiveRun("pblock_dd_ok", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-dd-ok", "?dedup=1"))
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        root = Path(ep.data_root)
        host = f"root://{ep.host}:{ep.port}"
        src = run.root / "src.bin"
        random_file(src, 500_000)

        assert run.call([XRDCP, "-f", src, f"{host}/a.bin"],
                        check=False).returncode == 0
        assert run.call([XRDCP, "-f", src, f"{host}/b.bin"],
                        check=False).returncode == 0

        ba, bb = _blob_id(catalog, "/a.bin"), _blob_id(catalog, "/b.bin")
        assert ba and ba == bb, "identical PUTs did not share a blob"
        assert _refcount(catalog, ba) == 2, "shared blob refcount != 2"

        got = run.root / "got.bin"
        for name in ("a.bin", "b.bin"):
            assert run.call([XRDCP, "-f", f"{host}/{name}", got],
                            check=False).returncode == 0
            assert sha256(got) == sha256(src)

        assert _run_fsck(fsck, root).returncode == 0, "clean export shows drift"

        # Remove one sharer → the blob loses a reference, never its blocks.
        assert run.call([XRDFS, host, "rm", "/a.bin"],
                        check=False).returncode == 0
        assert _refcount(catalog, bb) == 1, "refcount != 1 after one unlink"
        assert run.call([XRDCP, "-f", f"{host}/b.bin", got],
                        check=False).returncode == 0
        assert sha256(got) == sha256(src), "survivor content lost"
        assert _run_fsck(fsck, root).returncode == 0, "drift after unlink"

        # Remove the last sharer → gone entirely.
        assert run.call([XRDFS, host, "rm", "/b.bin"],
                        check=False).returncode == 0
        assert run.call([XRDCP, "-f", f"{host}/b.bin", got],
                        check=False).returncode != 0, "blob outlived last ref"
        assert _run_fsck(fsck, root).returncode == 0, "drift after final unlink"


@pytest.mark.optin
@pytest.mark.timeout(150)
def test_dedup_cow_break_on_overwrite(lifecycle, fsck: Path) -> None:
    """(error/CoW) Two identical PUTs share one blob (refcount 2); overwriting
    one path forks a private blob, the two blob_ids diverge, the sibling is
    byte-exact unchanged, and both blobs end at refcount 1. (The server_copy
    refcount-bump variant of the share is covered directly through the vtable
    in the C unit; native TPC over the wire is a separate open bug.)"""
    _need_bins()
    with LiveRun("pblock_dd_cow", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-dd-cow", "?dedup=1"))
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        root = Path(ep.data_root)
        host = f"root://{ep.host}:{ep.port}"
        src = run.root / "src.bin"
        src2 = run.root / "src2.bin"
        random_file(src, 400_000)
        random_file(src2, 300_000)

        # Identical PUTs fold onto one shared blob (refcount 2).
        assert run.call([XRDCP, "-f", src, f"{host}/orig.bin"],
                        check=False).returncode == 0
        assert run.call([XRDCP, "-f", src, f"{host}/clone.bin"],
                        check=False).returncode == 0
        borig = _blob_id(catalog, "/orig.bin")
        bclone = _blob_id(catalog, "/clone.bin")
        assert borig and borig == bclone, "identical PUTs did not share a blob"
        assert _refcount(catalog, borig) == 2, "shared blob refcount != 2"

        # Overwrite the clone → break the share into a private blob.
        assert run.call([XRDCP, "-f", src2, f"{host}/clone.bin"],
                        check=False).returncode == 0
        borig2 = _blob_id(catalog, "/orig.bin")
        bclone2 = _blob_id(catalog, "/clone.bin")
        assert borig2 == borig, "overwrite disturbed the sibling's blob"
        assert bclone2 != borig2, "overwrite did not break the share"
        assert _refcount(catalog, borig2) == 1, "original refcount not back to 1"

        got = run.root / "got.bin"
        assert run.call([XRDCP, "-f", f"{host}/orig.bin", got],
                        check=False).returncode == 0
        assert sha256(got) == sha256(src), "sibling changed after overwrite"
        assert run.call([XRDCP, "-f", f"{host}/clone.bin", got],
                        check=False).returncode == 0
        assert sha256(got) == sha256(src2), "overwrite content wrong"
        assert _run_fsck(fsck, root).returncode == 0, "drift after CoW break"


@pytest.mark.optin
@pytest.mark.timeout(150)
def test_dedup_forged_hash_cannot_alias_and_gate_off(lifecycle, fsck: Path) -> None:
    """(security-neg) A forged `content_hash` row cannot make differing content
    alias — the mandatory byte-verify rejects the candidate — and a
    hand-corrupted refcount is caught by --verify-refs. Without `dedup=1` the
    identical PUTs stay physically distinct (enforcement can't be armed via
    sqlite alone)."""
    _need_bins()

    # --- forged-hash rejection (gate on) --------------------------------------
    with LiveRun("pblock_dd_sec", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-dd-sec", "?dedup=1"))
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        root = Path(ep.data_root)
        host = f"root://{ep.host}:{ep.port}"
        victim = run.root / "victim.bin"
        attack = run.root / "attack.bin"
        random_file(victim, 500_000)
        random_file(attack, 500_000)      # same size, different bytes

        assert run.call([XRDCP, "-f", victim, f"{host}/victim.bin"],
                        check=False).returncode == 0
        assert run.call([XRDCP, "-f", attack, f"{host}/attack.bin"],
                        check=False).returncode == 0
        bvictim = _blob_id(catalog, "/victim.bin")
        battack = _blob_id(catalog, "/attack.bin")
        assert bvictim != battack, "different content shared a blob"

        # Forge the attacker blob's hash to equal the victim's.
        conn = sqlite3.connect(str(catalog), timeout=10)
        try:
            vh = conn.execute(
                "SELECT content_hash, block_size FROM blobs WHERE blob_id=?",
                (bvictim,)).fetchone()
            conn.execute(
                "UPDATE blobs SET content_hash=? WHERE blob_id=?",
                (vh[0], battack))
            conn.commit()
        finally:
            conn.close()

        # A third file identical to the victim: its only forged-hash candidate
        # is the attacker blob, whose bytes differ → byte-verify rejects it, so
        # it shares the genuine victim blob (or keeps its own), never the
        # attacker's. Content is honest regardless.
        assert run.call([XRDCP, "-f", victim, f"{host}/probe.bin"],
                        check=False).returncode == 0
        bprobe = _blob_id(catalog, "/probe.bin")
        assert bprobe != battack, "probe aliased the forged attacker blob"
        got = run.root / "got.bin"
        assert run.call([XRDCP, "-f", f"{host}/probe.bin", got],
                        check=False).returncode == 0
        assert sha256(got) == sha256(victim), "probe content corrupted"
        assert run.call([XRDCP, "-f", f"{host}/attack.bin", got],
                        check=False).returncode == 0
        assert sha256(got) == sha256(attack), "attacker content changed"

        # --verify-refs catches a hand-corrupted refcount ledger.
        assert _run_fsck(fsck, root).returncode == 0, "unexpected pre-corrupt drift"
        conn = sqlite3.connect(str(catalog), timeout=10)
        try:
            conn.execute("UPDATE blobs SET refcount=9 WHERE blob_id=?",
                         (bvictim,))
            conn.commit()
        finally:
            conn.close()
        cp = _run_fsck(fsck, root)
        assert cp.returncode == 1 and "REFS" in cp.stdout, \
            f"--verify-refs missed a refcount drift: {cp.stdout}"

    # --- gate off: identical PUTs stay distinct -------------------------------
    with LiveRun("pblock_dd_off", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-dd-off", ""))  # gate OFF
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        host = f"root://{ep.host}:{ep.port}"
        src = run.root / "src.bin"
        random_file(src, 400_000)

        assert run.call([XRDCP, "-f", src, f"{host}/g1.bin"],
                        check=False).returncode == 0
        assert run.call([XRDCP, "-f", src, f"{host}/g2.bin"],
                        check=False).returncode == 0
        b1, b2 = _blob_id(catalog, "/g1.bin"), _blob_id(catalog, "/g2.bin")
        assert b1 and b1 != b2, "gate-off export deduplicated identical PUTs"
        assert _refcount(catalog, b1) == -1, "gate-off export tracked a blob row"

        got = run.root / "got.bin"
        assert run.call([XRDFS, host, "rm", "/g1.bin"],
                        check=False).returncode == 0
        assert run.call([XRDCP, "-f", f"{host}/g2.bin", got],
                        check=False).returncode == 0
        assert sha256(got) == sha256(src), "gate-off unlink corrupted sibling"
