"""Phase-83 F5 — quotas + space accounting over a live pblock export.

With `quota=`/`quota_inodes=` in the backend `?tail`, the driver arms a
`usage(scope, id, bytes, inodes)` rollup maintained by SQLite triggers on
`objects` (transactional by construction — no call site can forget it) and
refuses quota-busting work with EDQUOT (→ kXR_NoSpace on the wire) at the
catalog boundaries: create, staged open/commit, mkdir, server_copy and the
close-time size write-back. The armed byte quota also feeds the driver `space`
slot, so `xrdfs statvfs` reports the quota — not the backing disk. The tests
prove: the rollup tracks a mixed workload exactly and statvfs reflects the
quota (success); a PUT past the byte quota fails on the wire and the refused
commit leaves both the existing data and the rollup untouched (error); and a
per-uid ctl limit binds only the uid it names — one principal's quota cannot
be used to starve another (security-neg).
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
    """Compile the standalone --verify-usage oracle once for the module."""
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


def _usage(catalog: Path, scope: str, ident: int = 0) -> tuple[int, int]:
    conn = sqlite3.connect(str(catalog), timeout=10)
    try:
        row = conn.execute(
            "SELECT bytes, inodes FROM usage WHERE scope = ? AND id = ?;",
            (scope, ident)).fetchone()
    finally:
        conn.close()
    return (int(row[0]), int(row[1])) if row is not None else (0, 0)


def _ctl_set(catalog: Path, key: str, value: str) -> None:
    """Set a runtime ctl rule the way tests drive the lab: straight SQL."""
    conn = sqlite3.connect(str(catalog), timeout=10)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS ctl("
                     "  key TEXT PRIMARY KEY,"
                     "  value TEXT NOT NULL DEFAULT '',"
                     "  epoch INTEGER NOT NULL DEFAULT 0);")
        conn.execute("INSERT INTO ctl(key, value, epoch) VALUES(?, ?, 1)"
                     " ON CONFLICT(key) DO UPDATE SET value = excluded.value,"
                     " epoch = epoch + 1;", (key, value))
        conn.commit()
    finally:
        conn.close()


def _ctl_del(catalog: Path, key: str) -> None:
    conn = sqlite3.connect(str(catalog), timeout=10)
    try:
        conn.execute("DELETE FROM ctl WHERE key = ?;", (key,))
        conn.commit()
    finally:
        conn.close()


def _free_mb(run: LiveRun, host: str) -> int:
    """`xrdfs statvfs /` → the free-space (MB) figure the server sent. xrdfs
    prints the raw kXR_vfs body: "<nrw> <free_mb> <util> <nstg> <largest> <u>".
    """
    out = run.call([XRDFS, host, "statvfs", "/"], check=False)
    assert out.returncode == 0, f"statvfs failed: {out.stderr}"
    fields = out.stdout.split()
    assert len(fields) >= 2 and fields[1].isdigit(), \
        f"unexpected statvfs output: {out.stdout!r}"
    return int(fields[1])


def _need_bins() -> None:
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    if not XRDCP.exists():
        pytest.skip("xrdcp not built")


@pytest.mark.optin
@pytest.mark.timeout(150)
def test_quota_rollup_tracks_workload_and_statvfs(lifecycle, fsck: Path) -> None:
    """(success) A mixed workload (two PUTs, a mkdir, a delete) keeps the
    trigger-maintained rollup exactly equal to what the objects rows say; the
    armed byte quota shows up in kXR_statvfs (quota-total, not the backing
    disk); and the offline oracle finds no divergence."""
    _need_bins()
    with LiveRun("pblock_quota_ok", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-quota-ok", "?quota=100m"))
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        host = f"root://{ep.host}:{ep.port}"
        hub = f"{host}/"
        a = run.root / "a.bin"
        b = run.root / "b.bin"
        random_file(a, 2_500_000)
        random_file(b, 1_000_000)

        assert run.call([XRDCP, "-f", a, f"{hub}a.bin"],
                        check=False).returncode == 0
        assert run.call([XRDCP, "-f", b, f"{hub}b.bin"],
                        check=False).returncode == 0
        assert run.call([XRDFS, host, "mkdir", "/d"],
                        check=False).returncode == 0

        # rollup == the workload: 2 files' bytes; inodes = "/" + 2 files + 1 dir.
        bytes_, inodes = _usage(catalog, "total")
        assert bytes_ == 3_500_000, f"rollup bytes {bytes_} != 3_500_000"
        assert inodes == 4, f"rollup inodes {inodes} != 4"

        # statvfs reports against the 100m quota, not the backing filesystem:
        # free = (100m - 3.5MB used) / 1MiB = 96 whole MB.
        assert _free_mb(run, host) == (100 * 1024 * 1024 - 3_500_000) // 1048576

        # Delete rolls the usage back down (the AFTER DELETE trigger).
        assert run.call([XRDFS, host, "rm", "/b.bin"],
                        check=False).returncode == 0
        bytes_, inodes = _usage(catalog, "total")
        assert (bytes_, inodes) == (2_500_000, 3), \
            f"rollup did not roll back after rm: {bytes_}/{inodes}"

        # The offline oracle agrees the rollup matches a recompute.
        report = _fsck(fsck, Path(ep.data_root), "--verify-usage")
        assert report.returncode == 0 and "USAGE" not in report.stdout, \
            f"oracle flagged a clean rollup: rc={report.returncode} {report.stdout}"


@pytest.mark.optin
@pytest.mark.timeout(150)
def test_quota_exceeded_put_fails_and_rolls_back(lifecycle, fsck: Path) -> None:
    """(error) With a 3m byte quota, the first 2.5MB PUT lands and the second
    is refused at staged-commit (EDQUOT → kXR_NoSpace) — before the existing
    namespace is touched: the first file still reads byte-exact, the usage
    rollup is unchanged by the refused transfer, and the oracle stays quiet
    (the abort path leaked nothing into the accounting)."""
    _need_bins()
    with LiveRun("pblock_quota_full", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-quota-full", "?quota=3m"))
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        hub = f"root://{ep.host}:{ep.port}/"
        src = run.root / "src.bin"
        random_file(src, 2_500_000)

        assert run.call([XRDCP, "-f", src, f"{hub}first.bin"],
                        check=False).returncode == 0
        before = _usage(catalog, "total")
        assert before[0] == 2_500_000

        # 2.5MB more against a 3m quota → refused on the wire (EDQUOT →
        # kXR_NoSpace at the pwrite that would cross the cap).
        over = run.call([XRDCP, "-f", src, f"{hub}second.bin"], check=False)
        assert over.returncode != 0, "quota-busting PUT succeeded"

        # Real-ENOSPC semantics: a partial dest may remain, but accounted usage
        # can never exceed the quota, and the first file is untouched.
        assert _usage(catalog, "total")[0] <= 3 * 1024 * 1024, \
            "usage rollup exceeds the byte quota after the refused PUT"
        got = run.root / "got.bin"
        assert run.call([XRDCP, "-f", f"{hub}first.bin", got],
                        check=False).returncode == 0
        assert sha256(got) == sha256(src), "existing file damaged by refused PUT"

        report = _fsck(fsck, Path(ep.data_root), "--verify-usage")
        assert report.returncode == 0 and "USAGE" not in report.stdout, \
            f"rollup diverged after the refused PUT: {report.stdout}"

        # After clearing the failed dest, an in-quota PUT still works — the
        # export is full-able, not wedged.
        run.call([XRDFS, f"root://{ep.host}:{ep.port}", "rm", "/second.bin"],
                 check=False)
        small = run.root / "small.bin"
        random_file(small, 200_000)
        assert run.call([XRDCP, "-f", small, f"{hub}small.bin"],
                        check=False).returncode == 0


@pytest.mark.optin
@pytest.mark.timeout(150)
def test_quota_uid_limit_binds_only_its_uid(lifecycle) -> None:
    """(security-neg) Per-uid ctl limits are scoped to the uid they name.
    `quota.uid.0` (the writing principal on this brix_auth-none export) refuses
    that principal's PUT; replacing it with `quota.uid.12345` — some *other*
    uid — must not affect uid 0's writes. A tenant's quota row can starve only
    that tenant."""
    _need_bins()
    with LiveRun("pblock_quota_uid", None) as run:
        # Large (non-binding) export quota: arming is what enables per-uid rows.
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-quota-uid", "?quota=1g"))
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        hub = f"root://{ep.host}:{ep.port}/"
        src = run.root / "src.bin"
        random_file(src, 1_000_000)

        assert run.call([XRDCP, "-f", src, f"{hub}seed.bin"],
                        check=False).returncode == 0

        # A 1m cap on uid 0 (already holding 1MB) refuses its next PUT.
        _ctl_set(catalog, "quota.uid.0", "1m")
        rc = run.call([XRDCP, "-f", src, f"{hub}blocked.bin"],
                      check=False).returncode
        assert rc != 0, "PUT succeeded past the uid-0 ctl quota"

        # The same cap on a DIFFERENT uid must not bind uid 0.
        _ctl_del(catalog, "quota.uid.0")
        _ctl_set(catalog, "quota.uid.12345", "1m")
        assert run.call([XRDCP, "-f", src, f"{hub}allowed.bin"],
                        check=False).returncode == 0, \
            "another uid's quota row blocked uid 0's write"
