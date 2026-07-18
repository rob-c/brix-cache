"""Phase-83 F9 — eventual-consistency anomaly emulation over a live pblock lab.

With `lab=1` in the backend `?tail`, ctl rules turn the export into a
deterministic S3-consistency simulator: `anomaly.visibility_ms` makes a
freshly created path ENOENT to *other* opens/stats for the window,
`anomaly.list_lag_ms` makes readdir omit fresh entries, and
`anomaly.stale_stat_ms` makes stat serve the pre-update size/mtime after an
overwrite. State is the driver-owned `recent` event table; consultation is a
pure catalog-side read — the byte path is untouched. The tests prove: fresh
creations lag out of GET/ls and then converge (success); an overwrite's stat
serves the pre-update row for the window and then converges (error); and the
writer lane is exempt (a write-intent open of its own fresh file never sees
the phantom ENOENT — the S3 session monotonic-read guarantee) while a gate-off
export treats the identical ctl + event rows as inert (security-neg).
"""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import time

import pytest

from cmdscripts.live_common import LiveRun, random_file, sha256
from cmdscripts.pblock_live import XRDCP, XRDFS, pblock_lab_spec

pytestmark = pytest.mark.uses_lifecycle_harness


def _sql(catalog: Path, *stmts: tuple) -> None:
    conn = sqlite3.connect(str(catalog), timeout=10)
    try:
        for stmt, params in stmts:
            conn.execute(stmt, params)
        conn.commit()
    finally:
        conn.close()


def _ctl_set(catalog: Path, key: str, value: str) -> None:
    _sql(catalog,
         ("CREATE TABLE IF NOT EXISTS ctl("
          "  key TEXT PRIMARY KEY,"
          "  value TEXT NOT NULL DEFAULT '',"
          "  epoch INTEGER NOT NULL DEFAULT 0);", ()),
         ("INSERT INTO ctl(key, value, epoch) VALUES(?, ?, 1)"
          " ON CONFLICT(key) DO UPDATE SET value = excluded.value,"
          " epoch = epoch + 1;", (key, value)))


def _fake_recent_create(catalog: Path, path: str) -> None:
    """Plant a just-created event row by hand (the gate-off inertness probe)."""
    now_ms = int(time.time() * 1000)
    _sql(catalog,
         ("CREATE TABLE IF NOT EXISTS recent("
          "  path TEXT PRIMARY KEY,"
          "  created_ms INTEGER NOT NULL DEFAULT 0,"
          "  updated_ms INTEGER NOT NULL DEFAULT 0,"
          "  old_size INTEGER NOT NULL DEFAULT 0,"
          "  old_mtime INTEGER NOT NULL DEFAULT 0);", ()),
         ("INSERT INTO recent VALUES(?, ?, 0, 0, 0)"
          " ON CONFLICT(path) DO UPDATE SET"
          " created_ms = excluded.created_ms;", (path, now_ms)))


def _stat_size(run: LiveRun, host: str, path: str) -> int:
    proc = run.call([XRDFS, host, "stat", path], check=False)
    assert proc.returncode == 0, f"stat {path} failed: {proc.stderr}"
    for line in proc.stdout.splitlines():
        if line.strip().startswith("Size:"):
            return int(line.split()[1])
    raise AssertionError(f"no Size: line in stat output: {proc.stdout!r}")


def _need_bins() -> None:
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    if not XRDCP.exists():
        pytest.skip("xrdcp not built")


@pytest.mark.optin
@pytest.mark.timeout(150)
def test_anomaly_fresh_create_lags_then_converges(lifecycle) -> None:
    """(success) With visibility + list lag armed, a fresh PUT is ENOENT to
    other GETs and missing from ls for the window, then both converge to the
    real object — deterministic S3 read-after-write emulation."""
    _need_bins()
    with LiveRun("pblock_an_ok", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-an-ok", "?lab=1"))
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        host = f"root://{ep.host}:{ep.port}"
        src = run.root / "src.bin"
        random_file(src, 300_000)

        _ctl_set(catalog, "anomaly.visibility_ms", "2500")
        _ctl_set(catalog, "anomaly.list_lag_ms", "2500")

        assert run.call([XRDCP, "-f", src, f"{host}/f.bin"],
                        check=False).returncode == 0, \
            "the writer's own PUT must never see its visibility lag"

        got = run.root / "got.bin"
        assert run.call([XRDCP, "-f", f"{host}/f.bin", got],
                        check=False).returncode != 0, \
            "fresh create was immediately visible despite visibility lag"
        ls = run.call([XRDFS, host, "ls", "/"], check=False)
        assert ls.returncode == 0
        assert "f.bin" not in ls.stdout, \
            "fresh create was immediately listed despite list lag"

        # Convergence is anchored to the server-side event stamp, not this
        # process's clock — poll to a deadline instead of a fixed sleep.
        deadline = time.monotonic() + 8
        while run.call([XRDCP, "-f", f"{host}/f.bin", got],
                       check=False).returncode != 0:
            assert time.monotonic() < deadline, \
                "object never became visible after the window"
            time.sleep(0.3)
        assert sha256(got) == sha256(src), "converged bytes differ"
        while True:
            ls = run.call([XRDFS, host, "ls", "/"], check=False)
            if ls.returncode == 0 and "f.bin" in ls.stdout:
                break
            assert time.monotonic() < deadline, \
                "object never appeared in the listing after the window"
            time.sleep(0.3)


@pytest.mark.optin
@pytest.mark.timeout(150)
def test_anomaly_stale_stat_serves_pre_update_row(lifecycle) -> None:
    """(error) After an overwrite, stat serves the pre-update size for the
    stale window (S3 HEAD-after-overwrite), then converges to the new row —
    the wrong-but-deterministic answer callers must tolerate."""
    _need_bins()
    with LiveRun("pblock_an_stale", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-an-stale", "?lab=1"))
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        host = f"root://{ep.host}:{ep.port}"
        src1 = run.root / "src1.bin"
        src2 = run.root / "src2.bin"
        random_file(src1, 300_000)
        random_file(src2, 100_000)

        assert run.call([XRDCP, "-f", src1, f"{host}/f.bin"],
                        check=False).returncode == 0
        assert _stat_size(run, host, "/f.bin") == 300_000

        _ctl_set(catalog, "anomaly.stale_stat_ms", "2500")
        assert run.call([XRDCP, "-f", src2, f"{host}/f.bin"],
                        check=False).returncode == 0

        assert _stat_size(run, host, "/f.bin") == 300_000, \
            "stat served the new row inside the stale window"
        # The window is anchored to the overwrite's server-side close stamp —
        # poll for convergence rather than trusting a fixed sleep margin.
        deadline = time.monotonic() + 8
        while _stat_size(run, host, "/f.bin") != 100_000:
            assert time.monotonic() < deadline, \
                "stat never converged to the updated row"
            time.sleep(0.3)


@pytest.mark.optin
@pytest.mark.timeout(150)
def test_anomaly_writer_exempt_and_gate_off_inert(lifecycle) -> None:
    """(security-neg) The writer lane is exempt: with visibility armed, an
    overwrite PUT of its own still-invisible file succeeds (write-intent
    opens never see the phantom ENOENT — session monotonic read) while a
    plain GET still lags. And without `lab=1` in the tail, the identical ctl
    rules + a hand-planted fresh event row are inert — the simulator cannot
    be armed from the data plane."""
    _need_bins()
    with LiveRun("pblock_an_sec", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-an-sec", "?lab=1"))
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        host = f"root://{ep.host}:{ep.port}"
        src1 = run.root / "src1.bin"
        src2 = run.root / "src2.bin"
        random_file(src1, 200_000)
        random_file(src2, 250_000)

        _ctl_set(catalog, "anomaly.visibility_ms", "5000")
        assert run.call([XRDCP, "-f", src1, f"{host}/f.bin"],
                        check=False).returncode == 0
        assert run.call([XRDCP, "-f", src2, f"{host}/f.bin"],
                        check=False).returncode == 0, \
            "overwrite of the writer's own fresh file hit its visibility lag"
        got = run.root / "got.bin"
        assert run.call([XRDCP, "-f", f"{host}/f.bin", got],
                        check=False).returncode != 0, \
            "reader GET ignored the visibility lag"

    with LiveRun("pblock_an_off", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-an-off", ""))  # gate OFF
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        host = f"root://{ep.host}:{ep.port}"
        src = run.root / "src.bin"
        random_file(src, 200_000)

        assert run.call([XRDCP, "-f", src, f"{host}/f.bin"],
                        check=False).returncode == 0
        _ctl_set(catalog, "anomaly.visibility_ms", "5000")
        _ctl_set(catalog, "anomaly.stale_stat_ms", "5000")
        _ctl_set(catalog, "anomaly.list_lag_ms", "5000")
        _fake_recent_create(catalog, "/f.bin")

        got = run.root / "got.bin"
        assert run.call([XRDCP, "-f", f"{host}/f.bin", got],
                        check=False).returncode == 0, \
            "gate-off export hid a file over inert anomaly rows"
        assert sha256(got) == sha256(src)
        assert _stat_size(run, host, "/f.bin") == 200_000
        ls = run.call([XRDFS, host, "ls", "/"], check=False)
        assert ls.returncode == 0 and "f.bin" in ls.stdout, \
            "gate-off export lagged its listing"
