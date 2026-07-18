"""Phase-83 F6 — snapshots / instant fixture reset (pblock).

With `snap=1` in the backend `?tail`, the driver keeps
`snapshots`/`snap_objects`/`snap_xattrs` tables and auto-arms the F10 refcounted
blobs it depends on (a snapshot pins the blobs its copied rows reference, so a
delete between take and restore *decrements* a shared blob rather than
physically removing it — the blocks survive for the restore). Take/restore/drop
each run in one `BEGIN IMMEDIATE` transaction and finish by recomputing every
blob's refcount from live objects + all snapshot copies, so the F10 release
path stays exact.

The runtime control plane is service-only by design: `mkdir /.pblock/snap/<n>`
takes, `mkdir /.pblock/restore/<n>` restores, `rmdir /.pblock/snap/<n>` drops —
intercepted in the inner (service) namespace path, so the resolve/parent-exist
gate keeps an identity-carrying wire request out. That driver control path is
exercised directly through the vtable in the C unit (sd_pblock_unittest.c:
test_snapshot). Here the equivalent take/restore is driven through the offline
`pblock-fsck --snapshot`/`--restore` oracle, which shares the driver's exact SQL
and name-validation, with the data path running over a real server.

Proves: snapshot → delete → restore reproduces byte-identical reads and leaves a
consistent export (success); a hostile snapshot name (SQL/traversal
metacharacters) is refused by the oracle and the catalog is unharmed, so a
legitimate snapshot still round-trips (security-neg); and a gate-off export
never grows the snapshot tables — pblock stays the plain production driver
(inertness).
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


def _fsck(fsck: Path, root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([str(fsck), str(root), *args],
                          capture_output=True, text=True)


def _has_table(catalog: Path, name: str) -> bool:
    conn = sqlite3.connect(str(catalog), timeout=10)
    try:
        return conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (name,)).fetchone() is not None
    finally:
        conn.close()


@pytest.mark.optin
@pytest.mark.timeout(180)
def test_snapshot_take_restore_roundtrip(lifecycle, fsck: Path) -> None:
    """(success) Seed two files (one spanning >1 block), snapshot the export,
    delete both over the wire, restore, and read back byte-identical content;
    the restored export is consistent under fsck throughout."""
    _need_bins()
    with LiveRun("pblock_snap_ok", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-snap-ok", "?snap=1", workers=1))
        catalog = Path(ep.data_root) / "catalog.db"
        root = Path(ep.data_root)
        host = f"root://{ep.host}:{ep.port}"
        one = run.root / "one.bin"
        two = run.root / "two.bin"
        random_file(one, 300_000)          # single block
        random_file(two, 1_500_000)        # spans two 1m blocks

        time.sleep(1)
        assert run.call([XRDCP, "-f", one, f"{host}/one.bin"],
                        check=False).returncode == 0
        assert run.call([XRDCP, "-f", two, f"{host}/two.bin"],
                        check=False).returncode == 0
        lifecycle.stop("lc-pblock-snap-ok")

        # Take the snapshot offline (catalog unlocked while the server is down).
        cp = _fsck(fsck, root, "--snapshot", "fix")
        assert cp.returncode == 0 and "SNAPSHOT fix" in cp.stdout, cp.stderr
        assert _fsck(fsck, root, "--verify-refs").returncode == 0, "post-snap drift"

        # Delete everything over the wire — snapshot-pinned blocks must survive.
        lifecycle.start_registered("lc-pblock-snap-ok")
        time.sleep(1)
        assert run.call([XRDFS, host, "rm", "/one.bin"],
                        check=False).returncode == 0
        assert run.call([XRDFS, host, "rm", "/two.bin"],
                        check=False).returncode == 0
        got = run.root / "got.bin"
        assert run.call([XRDCP, "-f", f"{host}/one.bin", got],
                        check=False).returncode != 0, "file survived its delete"
        lifecycle.stop("lc-pblock-snap-ok")

        # Restore and confirm byte-identical reads through the live server.
        cp = _fsck(fsck, root, "--restore", "fix")
        assert cp.returncode == 0 and "RESTORE fix" in cp.stdout, cp.stderr
        assert _fsck(fsck, root, "--verify-refs").returncode == 0, "post-restore drift"

        lifecycle.start_registered("lc-pblock-snap-ok")
        time.sleep(1)
        assert run.call([XRDCP, "-f", f"{host}/one.bin", got],
                        check=False).returncode == 0
        assert sha256(got) == sha256(one), "one.bin not byte-identical after restore"
        assert run.call([XRDCP, "-f", f"{host}/two.bin", got],
                        check=False).returncode == 0
        assert sha256(got) == sha256(two), "two.bin not byte-identical after restore"
        lifecycle.stop("lc-pblock-snap-ok")
        assert _fsck(fsck, root).returncode == 0, "restored export inconsistent"


@pytest.mark.optin
@pytest.mark.timeout(120)
def test_snapshot_hostile_name_refused(lifecycle, fsck: Path) -> None:
    """(security-neg) A snapshot name carrying SQL or traversal metacharacters is
    refused at the charset gate (exit 3) — the name is only ever a bound column,
    so injection is structurally impossible — and the catalog is unharmed: a
    legitimate snapshot/restore still round-trips byte-identical afterwards."""
    _need_bins()
    with LiveRun("pblock_snap_sec", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-snap-sec", "?snap=1", workers=1))
        root = Path(ep.data_root)
        host = f"root://{ep.host}:{ep.port}"
        src = run.root / "src.bin"
        random_file(src, 250_000)

        time.sleep(1)
        assert run.call([XRDCP, "-f", src, f"{host}/keep.bin"],
                        check=False).returncode == 0
        lifecycle.stop("lc-pblock-snap-sec")

        # Hostile names refused (exit 3, refused) — the injection is never run.
        for bad in ("x';DROP TABLE snapshots;--", "..", ".", "a/b", "no space"):
            cp = _fsck(fsck, root, "--snapshot", bad)
            assert cp.returncode == 3, f"hostile snapshot name accepted: {bad!r}"
        cp = _fsck(fsck, root, "--restore", "'; DELETE FROM objects; --")
        assert cp.returncode == 3, "hostile restore name accepted"

        # The catalog is intact — a legitimate snapshot/restore still works and
        # the file is byte-identical, proving nothing was dropped or deleted.
        assert _fsck(fsck, root, "--snapshot", "good").returncode == 0
        assert _fsck(fsck, root, "--restore", "good").returncode == 0
        lifecycle.start_registered("lc-pblock-snap-sec")
        time.sleep(1)
        got = run.root / "got.bin"
        assert run.call([XRDCP, "-f", f"{host}/keep.bin", got],
                        check=False).returncode == 0
        assert sha256(got) == sha256(src), "file corrupted after injection attempt"
        lifecycle.stop("lc-pblock-snap-sec")


@pytest.mark.optin
@pytest.mark.timeout(120)
def test_snapshot_gate_off_inert(lifecycle) -> None:
    """(inertness) Without `snap=1` the driver never arms F6: normal PUT/GET
    works and the export never grows the `snapshots` table — pblock stays the
    plain production driver."""
    _need_bins()
    with LiveRun("pblock_snap_off", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-snap-off", "", workers=1))
        catalog = Path(ep.data_root) / "catalog.db"
        host = f"root://{ep.host}:{ep.port}"
        src = run.root / "src.bin"
        random_file(src, 200_000)

        time.sleep(1)
        assert run.call([XRDCP, "-f", src, f"{host}/n.bin"],
                        check=False).returncode == 0
        got = run.root / "got.bin"
        assert run.call([XRDCP, "-f", f"{host}/n.bin", got],
                        check=False).returncode == 0
        assert sha256(got) == sha256(src), "gate-off PUT/GET corrupted"
        lifecycle.stop("lc-pblock-snap-off")

        assert not _has_table(catalog, "snapshots"), \
            "gate-off export grew the snapshot tables"
