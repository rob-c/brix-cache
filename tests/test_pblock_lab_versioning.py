"""Phase-83 F11 — versioning + trash/undelete (pblock).

With `versions=N&trash=1` in the backend `?tail` (persisted as the
`<root>/pblock.opts` sidecar), the driver auto-arms the F10 refcounted blobs it
builds on and keeps two history tables:

  * `versions(path, gen, blob_id, …)` — an atomic-publish overwrite (WebDAV/S3
    PUT → `staged_commit` over an existing path) moves the prior object's blob
    here BEFORE the destructive drop, trimmed to the newest N generations. The
    blob is held by an explicit bump-before-release copy-on-write transfer, so
    the blocks are never freed mid-move.
  * `trash(trash_id, path, blob_id, …)` — unlink becomes a move into the trash
    ledger (same held-blob transfer), recoverable until a `--gc --trash-ttl`
    purge.

Both captures are pure refcount arithmetic, so every history-pinned blob keeps
its blocks alive and `--verify-refs` stays balanced (referrers = live objects +
snapshot copies + versions + trash rows).

The runtime recovery control plane is service-only by design: `mkdir
/.pblock/undelete/<path>` pops the most-recent trash instance back into the
namespace — intercepted in the inner (service) namespace path, so the
resolve/parent-exist gate keeps an identity-carrying wire request out. That
driver control path is exercised directly through the vtable in the C unit
(sd_pblock_unittest.c: test_versioning). Here the equivalent list/undelete/GC is
driven through the offline `pblock-fsck` oracle (`--list-versions`,
`--list-trash`, `--undelete`, `--gc --trash-ttl`), which shares the driver's
exact SQL and held-blob accounting, with the data path running over a real
server.

Proves: three overwrites retain exactly two prior generations and a delete is
recoverable byte-identical, and a TTL purge reclaims the trash while the export
stays ref-consistent throughout (success); a hostile undelete path (SQL /
traversal metacharacters) is a bound column that can only miss — refused with
the trash ledger unharmed, and undelete over a live name is EEXIST
(security-neg); and a gate-off export never grows the versions/trash tables —
pblock stays the plain production driver (inertness).
"""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import subprocess
import time

import pytest

from cmdscripts.live_common import LiveRun, random_file, sha256
from cmdscripts.pblock_live import XRDCP, pblock_lab_spec

pytestmark = pytest.mark.uses_lifecycle_harness

REPO_ROOT = Path(__file__).resolve().parent.parent
FSCK_SRC = REPO_ROOT / "tools/pblock-fsck/pblock-fsck.c"


def _need_bins() -> None:
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")


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
def test_versioning_trash_roundtrip(lifecycle, fsck: Path) -> None:
    """(success) Overwrite /f three times (each an atomic publish) → exactly two
    prior generations retained; delete /f and /g into the trash; recover /f via
    the offline undelete oracle byte-identical; purge the rest with a TTL GC. The
    export stays ref-consistent at every offline checkpoint."""
    _need_bins()
    with LiveRun("pblock_ver_ok", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-ver-ok", "?versions=2&trash=1",
                                             workers=1, webdav=True))
        root = Path(ep.data_root)
        url = f"http://{ep.host}:{ep.port}"

        v1, v2, v3, g = (run.root / n for n in ("v1", "v2", "v3", "g"))
        for p in (v1, v2, v3, g):
            random_file(p, 700_000)            # single 1m block, distinct bytes

        time.sleep(1)
        # Three publishes over the SAME path: v1 creates, v2/v3 each move the
        # prior blob into `versions`. Trimmed to newest 2 ⇒ {v1, v2} retained.
        assert run.curl_status(f"{url}/f", "-T", str(v1)) in (201, 204)
        assert run.curl_status(f"{url}/f", "-T", str(v2)) in (201, 204)
        assert run.curl_status(f"{url}/f", "-T", str(v3)) in (201, 204)
        assert run.curl_status(f"{url}/g", "-T", str(g)) in (201, 204)
        assert run.curl_bytes(f"{url}/f") == v3.read_bytes(), "live /f not v3"
        lifecycle.stop("lc-pblock-ver-ok")

        # Offline: exactly two retained generations, and the store is balanced.
        cp = _fsck(fsck, root, "--list-versions", "/f")
        assert cp.returncode == 0 and "VERSIONS /f n=2" in cp.stdout, cp.stdout
        assert _fsck(fsck, root, "--verify-refs").returncode == 0, "post-put drift"

        # Delete both files over the wire → each moves into the trash ledger.
        lifecycle.start_registered("lc-pblock-ver-ok")
        time.sleep(1)
        assert run.curl_status(f"{url}/f", "-X", "DELETE") == 204
        assert run.curl_status(f"{url}/g", "-X", "DELETE") == 204
        assert run.curl_status(f"{url}/f", "-I") == 404, "deleted /f still visible"
        lifecycle.stop("lc-pblock-ver-ok")

        # Offline: both trashed, recover /f, still balanced (net-zero transfer).
        cp = _fsck(fsck, root, "--list-trash")
        assert cp.returncode == 0 and "TRASH n=2" in cp.stdout, cp.stdout
        assert "path=/f" in cp.stdout and "path=/g" in cp.stdout, cp.stdout
        cp = _fsck(fsck, root, "--undelete", "/f")
        assert cp.returncode == 0 and "UNDELETE /f" in cp.stdout, cp.stderr
        assert _fsck(fsck, root, "--verify-refs").returncode == 0, "post-undelete drift"

        # The recovered file reads back byte-identical to its pre-delete content.
        lifecycle.start_registered("lc-pblock-ver-ok")
        time.sleep(1)
        assert run.curl_bytes(f"{url}/f") == v3.read_bytes(), "undelete not byte-exact"
        lifecycle.stop("lc-pblock-ver-ok")

        # TTL GC purges the remaining trash (age >= 0): the ledger row goes and
        # its now-unreferenced blocks are reported+reclaimed in this pass (a
        # reclaiming --gc run reports the orphan it removes, so exit 1 here) ...
        cp = _fsck(fsck, root, "--gc", "--trash-ttl", "0")
        assert cp.returncode in (0, 1), cp.stdout
        assert "TRASH-PURGED" in cp.stdout, cp.stdout
        # ... and the second pass is clean and balanced — nothing left to reclaim.
        cp = _fsck(fsck, root, "--verify-refs")
        assert cp.returncode == 0, f"post-gc drift: {cp.stdout}"
        assert _fsck(fsck, root, "--list-trash").stdout.strip().endswith("n=0"), \
            "trash not purged"


@pytest.mark.optin
@pytest.mark.timeout(120)
def test_versioning_hostile_undelete_refused(lifecycle, fsck: Path) -> None:
    """(security-neg) An undelete path carrying SQL/traversal metacharacters is a
    bound column that can only miss the ledger (exit 1, nothing dropped), and
    undelete over a live name is EEXIST — then a legitimate delete/undelete still
    round-trips byte-identical, proving the trash table was never harmed."""
    _need_bins()
    with LiveRun("pblock_ver_sec", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-ver-sec", "?versions=2&trash=1",
                                             workers=1, webdav=True))
        root = Path(ep.data_root)
        url = f"http://{ep.host}:{ep.port}"
        keep = run.root / "keep.bin"
        random_file(keep, 250_000)

        time.sleep(1)
        assert run.curl_status(f"{url}/keep.bin", "-T", str(keep)) in (201, 204)
        assert run.curl_status(f"{url}/live.bin", "-T", str(keep)) in (201, 204)
        assert run.curl_status(f"{url}/keep.bin", "-X", "DELETE") == 204
        lifecycle.stop("lc-pblock-ver-sec")

        # Hostile names are never in the ledger ⇒ a plain finding (exit 1), and
        # the injection is never executed (the trash table still exists below).
        for bad in ("x';DROP TABLE trash;--", "/../etc/passwd",
                    "'; DELETE FROM objects; --"):
            cp = _fsck(fsck, root, "--undelete", bad)
            assert cp.returncode == 1, f"hostile undelete accepted: {bad!r}"
        # Undelete over a live name is refused (EEXIST) — never clobbers.
        cp = _fsck(fsck, root, "--undelete", "/live.bin")
        assert cp.returncode == 1 and "EEXIST" in cp.stderr, cp.stderr
        assert _has_table(root / "catalog.db", "trash"), "trash table dropped"

        # The ledger is intact — the legitimate trashed file still recovers.
        cp = _fsck(fsck, root, "--undelete", "/keep.bin")
        assert cp.returncode == 0 and "UNDELETE /keep.bin" in cp.stdout, cp.stderr
        lifecycle.start_registered("lc-pblock-ver-sec")
        time.sleep(1)
        assert run.curl_bytes(f"{url}/keep.bin") == keep.read_bytes(), \
            "file corrupted after injection attempt"
        lifecycle.stop("lc-pblock-ver-sec")


@pytest.mark.optin
@pytest.mark.timeout(120)
def test_versioning_gate_off_inert(lifecycle) -> None:
    """(inertness) Without a versions/trash tail the driver never arms F11:
    overwrite + delete behave as plain production ops and the export never grows
    the `versions` or `trash` tables."""
    _need_bins()
    with LiveRun("pblock_ver_off", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-ver-off", "",
                                             workers=1, webdav=True))
        catalog = Path(ep.data_root) / "catalog.db"
        url = f"http://{ep.host}:{ep.port}"
        a, b = run.root / "a", run.root / "b"
        random_file(a, 200_000)
        random_file(b, 200_000)

        time.sleep(1)
        assert run.curl_status(f"{url}/n.bin", "-T", str(a)) in (201, 204)
        assert run.curl_status(f"{url}/n.bin", "-T", str(b)) in (201, 204)  # overwrite
        assert run.curl_bytes(f"{url}/n.bin") == b.read_bytes(), "overwrite corrupted"
        assert run.curl_status(f"{url}/n.bin", "-X", "DELETE") == 204
        assert run.curl_status(f"{url}/n.bin", "-I") == 404, "delete failed"
        lifecycle.stop("lc-pblock-ver-off")

        assert not _has_table(catalog, "versions"), "gate-off grew versions table"
        assert not _has_table(catalog, "trash"), "gate-off grew trash table"
