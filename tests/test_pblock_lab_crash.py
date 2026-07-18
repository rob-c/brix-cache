"""Phase-83 F7 — crash points + pblock-fsck consistency oracle (live).

Arms a compiled-in crash point via the ctl table, drives an op that dies
mid-flight (worker _exit(86), master respawns), then uses the standalone
``pblock-fsck`` binary to classify the catalog<->blocks residue and prove
``--gc`` converges. Gate-off and unknown-schema refusal are the negatives.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sqlite3
import time

import pytest

from cmdscripts.live_common import LiveRun, REPO_ROOT, random_file
from cmdscripts.pblock_live import XRDCP, _ctl_set, pblock_lab_spec

pytestmark = pytest.mark.uses_lifecycle_harness

FSCK_SRC = REPO_ROOT / "tools/pblock-fsck/pblock-fsck.c"


@pytest.fixture(scope="module")
def fsck(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Compile the standalone oracle once for the module."""
    out = tmp_path_factory.mktemp("fsck") / "pblock-fsck"
    cflags = subprocess.run(["pkg-config", "--cflags", "sqlite3"],
                            capture_output=True, text=True).stdout.split()
    libs = subprocess.run(["pkg-config", "--libs", "sqlite3"],
                          capture_output=True, text=True).stdout.split() or ["-lsqlite3"]
    rc = subprocess.run(["cc", "-O2", "-Wall", "-Wextra", *cflags,
                         "-o", str(out), str(FSCK_SRC), *libs],
                        capture_output=True, text=True)
    if rc.returncode:
        pytest.fail(f"pblock-fsck build failed: {rc.stderr}")
    return out


def _fsck(binary: Path, root: Path, *flags: str) -> subprocess.CompletedProcess:
    return subprocess.run([str(binary), str(root), *flags],
                          capture_output=True, text=True)


def _need_bins() -> None:
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    if not XRDCP.exists():
        pytest.skip("xrdcp not built")


@pytest.mark.optin
@pytest.mark.timeout(180)
def test_crash_point_orphan_and_fsck_gc(lifecycle, fsck: Path) -> None:
    """(success/oracle) fsck is quiet on a clean store; a crash point mid-write
    leaves residue fsck flags and --gc converges to zero, then I/O recovers."""
    _need_bins()
    with LiveRun("pblock_crash", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-crash", "?lab=1"))
        time.sleep(1)
        root = Path(ep.data_root)
        catalog = root / "catalog.db"
        hub = f"root://{ep.host}:{ep.port}/"
        src = run.root / "src.bin"
        random_file(src, 700000)

        # Clean baseline transfer, then fsck must report zero findings.
        assert run.call([XRDCP, "-f", src, f"{hub}clean.bin"], check=False).returncode == 0
        base = _fsck(fsck, root)
        assert base.returncode == 0, f"clean store not quiet: {base.stdout}{base.stderr}"
        assert "FINDINGS 0" in base.stdout

        # Arm the crash point; the next write dies mid-flight → non-zero xrdcp.
        _ctl_set(catalog, "crash.at", "after_block_write", 1)
        rc = run.call([XRDCP, "-f", src, f"{hub}victim.bin"], check=False).returncode
        assert rc != 0, "PUT should fail when the worker crashes mid-write"
        time.sleep(1)   # let the master respawn the worker

        # Residue is present; fsck classifies it (a half-written victim leaves
        # either an orphan blob or a catalog/blocks size disagreement).
        dirty = _fsck(fsck, root)
        assert dirty.returncode == 1, f"expected findings, got: {dirty.stdout}"
        assert dirty.stdout.count("\n") >= 1

        # --gc (orphans) + --repair (size truth) converge to a clean store.
        fix = _fsck(fsck, root, "--gc", "--repair")
        after = _fsck(fsck, root)
        assert after.returncode == 0 and "FINDINGS 0" in after.stdout, \
            f"fsck did not converge: fix={fix.stdout} after={after.stdout}"

        # Disarm and prove I/O recovered.
        _ctl_set(catalog, "crash.at", "", 2)
        assert run.call([XRDCP, "-f", src, f"{hub}recovered.bin"], check=False).returncode == 0


@pytest.mark.optin
@pytest.mark.timeout(120)
def test_crash_gate_off_is_inert(lifecycle, fsck: Path) -> None:
    """(security-neg) With the master gate OFF, an armed crash point is never
    consulted — the write completes normally and the store stays consistent."""
    _need_bins()
    with LiveRun("pblock_crash_off", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-crash-off", ""))  # lab OFF
        time.sleep(1)
        root = Path(ep.data_root)
        hub = f"root://{ep.host}:{ep.port}/"
        src = run.root / "src.bin"
        random_file(src, 700000)

        _ctl_set(root / "catalog.db", "crash.at", "after_block_write", 1)
        assert run.call([XRDCP, "-f", src, f"{hub}safe.bin"], check=False).returncode == 0
        assert _fsck(fsck, root).returncode == 0


@pytest.mark.timeout(60)
def test_fsck_orphan_detect_and_gc(fsck: Path, tmp_path: Path) -> None:
    """(oracle) A blob dir on disk with no catalog row is an ORPHAN; --gc
    removes it and the store then reports clean — the mid_staged_commit residue
    class, exercised directly without a live server."""
    root = tmp_path / "exp"
    (root / "data" / "ab" / "cd").mkdir(parents=True)
    blob = root / "data" / "ab" / "cd" / "abcdef0123456789abcdef0123456789"
    blob.mkdir()
    (blob / "0").write_bytes(b"orphaned block payload")

    conn = sqlite3.connect(str(root / "catalog.db"))
    conn.execute("CREATE TABLE objects(path TEXT PRIMARY KEY, parent TEXT, "
                 "is_dir INT, blob_id TEXT DEFAULT '', size INT DEFAULT 0, "
                 "block_size INT DEFAULT 0);")
    conn.commit()
    conn.close()

    dirty = _fsck(fsck, root)
    assert dirty.returncode == 1 and "ORPHAN abcdef0123456789abcdef0123456789" in dirty.stdout
    _fsck(fsck, root, "--gc")
    assert not blob.exists(), "orphan blob dir should be removed by --gc"
    assert _fsck(fsck, root).returncode == 0


@pytest.mark.timeout(60)
def test_fsck_refuses_unknown_schema(fsck: Path, tmp_path: Path) -> None:
    """(error/refusal) A mutating fsck run fails closed on a catalog whose
    schema version this build does not know — no clobbering an unknown layout."""
    root = tmp_path / "exp"
    (root).mkdir()
    conn = sqlite3.connect(str(root / "catalog.db"))
    conn.execute("PRAGMA user_version = 999;")
    conn.execute("CREATE TABLE objects(path TEXT PRIMARY KEY, parent TEXT, "
                 "is_dir INT, blob_id TEXT DEFAULT '', size INT DEFAULT 0, "
                 "block_size INT DEFAULT 0);")
    conn.commit()
    conn.close()

    assert _fsck(fsck, root, "--gc").returncode == 3
    assert _fsck(fsck, root, "--repair").returncode == 3
    # A read-only check is still permitted on the unknown schema.
    assert _fsck(fsck, root).returncode in (0, 1)
