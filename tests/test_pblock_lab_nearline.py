"""Phase-83 F4 — nearline/tape simulation over a live pblock export.

With `nearline=1` in the backend `?tail`, the driver keeps a driver-owned
`nearline(path, res)` residency table (absent row = ONLINE) and advertises
CAP_NEARLINE. A read-open of a demoted file runs a bounded synchronous recall
(the sd_frm contract): sleep `ctl:nearline.recall_ms`, then flip the row
ONLINE — or, when `ctl:nearline.fail.<path>` is set, land it LOST and error.
Tests demote files by inserting rows via sqlite3, the standard ctl channel.
The tests prove: a demoted file's GET takes the simulated recall latency and
then serves byte-exact, after which the file is online and fast (success); a
failed recall errors on the wire — not a hang — and classifies the object LOST
so later opens fail immediately (error); and residency is honest — a stat
never triggers a recall, and on an export without the `nearline=1` opt the
identical demotion rows are inert (security-neg).
"""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import time

import pytest

from cmdscripts.live_common import LiveRun, random_file, sha256
from cmdscripts.pblock_live import XRDCP, XRDFS, pblock_lab_spec, pblock_worker_own

pytestmark = pytest.mark.uses_lifecycle_harness


def _sql(catalog: Path, *stmts: tuple) -> None:
    conn = sqlite3.connect(str(catalog), timeout=10)
    try:
        for stmt, params in stmts:
            conn.execute(stmt, params)
        conn.commit()
    finally:
        conn.close()
    pblock_worker_own(catalog)


def _ctl_set(catalog: Path, key: str, value: str) -> None:
    _sql(catalog,
         ("CREATE TABLE IF NOT EXISTS ctl("
          "  key TEXT PRIMARY KEY,"
          "  value TEXT NOT NULL DEFAULT '',"
          "  epoch INTEGER NOT NULL DEFAULT 0);", ()),
         ("INSERT INTO ctl(key, value, epoch) VALUES(?, ?, 1)"
          " ON CONFLICT(key) DO UPDATE SET value = excluded.value,"
          " epoch = epoch + 1;", (key, value)))


def _demote(catalog: Path, path: str, res: int) -> None:
    """Mark `path` nearline(1)/offline(2)/lost(3) — the test-side tape robot."""
    _sql(catalog,
         ("CREATE TABLE IF NOT EXISTS nearline("
          "  path TEXT PRIMARY KEY, res INTEGER NOT NULL);", ()),
         ("INSERT INTO nearline VALUES(?, ?)"
          " ON CONFLICT(path) DO UPDATE SET res = excluded.res;", (path, res)))


def _residency(catalog: Path, path: str) -> int | None:
    """The stored residency row, or None (= ONLINE by absence)."""
    conn = sqlite3.connect(str(catalog), timeout=10)
    try:
        row = conn.execute("SELECT res FROM nearline WHERE path = ?;",
                           (path,)).fetchone()
    finally:
        conn.close()
    pblock_worker_own(catalog)
    return int(row[0]) if row is not None else None


def _need_bins() -> None:
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    if not XRDCP.exists():
        pytest.skip("xrdcp not built")


@pytest.mark.optin
@pytest.mark.timeout(150)
def test_nearline_recall_serves_after_latency(lifecycle) -> None:
    """(success) A demoted file's GET blocks for the simulated recall latency,
    then serves byte-exact; the recall brings it online (row cleared) so the
    next GET is immediate."""
    _need_bins()
    with LiveRun("pblock_nl_ok", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-nl-ok", "?nearline=1"))
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        hub = f"root://{ep.host}:{ep.port}/"
        src = run.root / "src.bin"
        random_file(src, 300_000)

        assert run.call([XRDCP, "-f", src, f"{hub}f.bin"],
                        check=False).returncode == 0

        _demote(catalog, "/f.bin", 1)          # NEARLINE
        _ctl_set(catalog, "nearline.recall_ms", "1500")

        got = run.root / "got.bin"
        t0 = time.monotonic()
        assert run.call([XRDCP, "-f", f"{hub}f.bin", got],
                        check=False).returncode == 0, \
            "GET of a nearline file failed instead of recalling"
        elapsed = time.monotonic() - t0
        assert elapsed >= 1.4, f"recall latency not simulated ({elapsed:.2f}s)"
        assert sha256(got) == sha256(src), "recalled bytes differ"

        # The recall landed the file online: row gone, next GET immediate.
        assert _residency(catalog, "/f.bin") is None, "row not flipped online"
        t0 = time.monotonic()
        assert run.call([XRDCP, "-f", f"{hub}f.bin", got],
                        check=False).returncode == 0
        assert time.monotonic() - t0 < 1.0, "online file still paying recall"


@pytest.mark.optin
@pytest.mark.timeout(150)
def test_nearline_failed_recall_classifies_lost(lifecycle) -> None:
    """(error) With `nearline.fail.<path>` set, the recall errors on the wire
    (no hang) and reclassifies the object LOST, so a later open fails
    immediately — the client re-prepares or gives up, it never spins."""
    _need_bins()
    with LiveRun("pblock_nl_fail", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-nl-fail", "?nearline=1"))
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        hub = f"root://{ep.host}:{ep.port}/"
        src = run.root / "src.bin"
        random_file(src, 200_000)

        assert run.call([XRDCP, "-f", src, f"{hub}f.bin"],
                        check=False).returncode == 0

        _demote(catalog, "/f.bin", 2)          # OFFLINE
        _ctl_set(catalog, "nearline.recall_ms", "100")
        _ctl_set(catalog, "nearline.fail./f.bin", "1")

        got = run.root / "got.bin"
        assert run.call([XRDCP, "-f", f"{hub}f.bin", got],
                        check=False).returncode != 0, \
            "GET served a file whose recall was set to fail"
        assert _residency(catalog, "/f.bin") == 3, "failed recall not LOST"

        # LOST is terminal: the next open fails fast, no recall latency.
        t0 = time.monotonic()
        assert run.call([XRDCP, "-f", f"{hub}f.bin", got],
                        check=False).returncode != 0
        assert time.monotonic() - t0 < 2.0, "LOST open paid recall latency"


@pytest.mark.optin
@pytest.mark.timeout(150)
def test_nearline_stat_never_recalls_and_gate_off_inert(lifecycle) -> None:
    """(security-neg) Residency is a pure read: `xrdfs stat` of an offline file
    answers fast and leaves the demotion untouched (no recall side effect a
    client could trigger for free). And without `nearline=1` in the tail, the
    identical demotion + ctl rows are inert — the feature cannot be armed from
    the data plane."""
    _need_bins()
    with LiveRun("pblock_nl_sec", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-nl-sec", "?nearline=1"))
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        host = f"root://{ep.host}:{ep.port}"
        src = run.root / "src.bin"
        random_file(src, 200_000)

        assert run.call([XRDCP, "-f", src, f"{host}/f.bin"],
                        check=False).returncode == 0
        _demote(catalog, "/f.bin", 2)          # OFFLINE
        _ctl_set(catalog, "nearline.recall_ms", "5000")

        t0 = time.monotonic()
        assert run.call([XRDFS, host, "stat", "/f.bin"],
                        check=False).returncode == 0, "stat of offline failed"
        assert time.monotonic() - t0 < 2.0, "stat paid recall latency"
        assert _residency(catalog, "/f.bin") == 2, "stat advanced the recall"

    with LiveRun("pblock_nl_off", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-nl-off", ""))  # no ?nearline tail: gate OFF
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        hub = f"root://{ep.host}:{ep.port}/"
        src = run.root / "src.bin"
        random_file(src, 200_000)

        assert run.call([XRDCP, "-f", src, f"{hub}f.bin"],
                        check=False).returncode == 0
        _demote(catalog, "/f.bin", 2)
        _ctl_set(catalog, "nearline.recall_ms", "5000")
        _ctl_set(catalog, "nearline.fail./f.bin", "1")

        got = run.root / "got.bin"
        t0 = time.monotonic()
        assert run.call([XRDCP, "-f", f"{hub}f.bin", got],
                        check=False).returncode == 0, \
            "gate-off export refused a read over inert demotion rows"
        assert time.monotonic() - t0 < 2.0, "gate-off export paid recall latency"
        assert sha256(got) == sha256(src)
        assert _residency(catalog, "/f.bin") == 2, "gate-off export touched rows"
