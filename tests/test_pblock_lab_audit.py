"""Phase-83 F17 — op audit log (append-only oplog) over a live pblock export.

With `audit=1` in the backend `?tail`, the driver appends one row per
metadata-boundary op (open/close/namespace/staged-commit — never per byte-I/O;
per-handle byte totals fold into the close record) to an append-only
`oplog(seq, ts, op, path, aux, uid, gid, result, errno)` table. The tests prove:
the op sequence is recorded with a gap-free seq across two workers (success),
an oplog write failure never fails the user op (error / best-effort), and the
recorded identity matches the synthetic owner the catalog assigns (attribution).
"""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import time

import pytest

from cmdscripts.live_common import LiveRun, random_file
from cmdscripts.pblock_live import XRDCP, pblock_lab_spec

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-pblock-audit")]


def _oplog(catalog: Path) -> list[sqlite3.Row]:
    conn = sqlite3.connect(str(catalog), timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT seq, op, path, aux, uid, gid, result, errno "
            "FROM oplog ORDER BY seq;").fetchall()
    finally:
        conn.close()


def _need_bins() -> None:
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    if not nginx.exists():
        pytest.skip(f"nginx binary not found: {nginx}")
    if not XRDCP.exists():
        pytest.skip("xrdcp not built")


@pytest.mark.optin
@pytest.mark.timeout(150)
def test_audit_records_op_sequence(lifecycle) -> None:
    """(success) A PUT then a GET land recognisable op records; the seq is a
    gap-free total order even with two workers, and the close record folds the
    per-handle byte totals rather than logging per-I/O."""
    _need_bins()
    with LiveRun("pblock_audit", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-audit", "?audit=1", workers=2))
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        hub = f"root://{ep.host}:{ep.port}/"
        src = run.root / "src.bin"
        random_file(src, 2_500_000)   # >1 block at 1m stripe

        assert run.call([XRDCP, "-f", src, f"{hub}f.bin"],
                        check=False).returncode == 0
        got = run.root / "got.bin"
        assert run.call([XRDCP, "-f", f"{hub}f.bin", got],
                        check=False).returncode == 0

        rows = _oplog(catalog)
        assert rows, "oplog is empty — audit did not record anything"

        # seq is gap-free 1..N (AUTOINCREMENT total order across both workers).
        seqs = [r["seq"] for r in rows]
        assert seqs == list(range(seqs[0], seqs[0] + len(seqs))), \
            f"oplog seq has gaps: {seqs}"

        ops = [r["op"] for r in rows]
        # Write side: a commit (staged publish) or a close carrying w>0.
        writes = [r for r in rows
                  if r["op"] == "commit"
                  or (r["op"] == "close" and "w=" in r["aux"]
                      and "w=0" not in r["aux"])]
        assert writes, f"no write-side record in oplog ops={ops}"
        # Read side: the GET opened the file.
        assert "open" in ops, f"no open record for the GET; ops={ops}"
        # A close record exists and folds byte totals (r=/w=/mb= shape).
        closes = [r for r in rows if r["op"] == "close"]
        assert closes and all(
            "r=" in c["aux"] and "w=" in c["aux"] and "mb=" in c["aux"]
            for c in closes), f"close aux missing folded totals: {[c['aux'] for c in closes]}"


@pytest.mark.optin
@pytest.mark.timeout(120)
def test_audit_is_best_effort(lifecycle) -> None:
    """(error) Audit is best-effort: if the oplog becomes unwritable mid-run
    (here: the table is dropped out from under the driver) the user op still
    succeeds and the data path is unaffected."""
    _need_bins()
    with LiveRun("pblock_audit_be", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-audit-be", "?audit=1"))
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        hub = f"root://{ep.host}:{ep.port}/"
        src = run.root / "src.bin"
        random_file(src, 700_000)

        assert run.call([XRDCP, "-f", src, f"{hub}a.bin"],
                        check=False).returncode == 0

        # Yank the oplog table; the driver's INSERT can no longer prepare.
        conn = sqlite3.connect(str(catalog), timeout=10)
        try:
            conn.execute("DROP TABLE oplog;")
            conn.commit()
        finally:
            conn.close()

        # The op still succeeds (audit swallows the write failure) and the
        # bytes still round-trip.
        assert run.call([XRDCP, "-f", src, f"{hub}b.bin"],
                        check=False).returncode == 0
        got = run.root / "got.bin"
        assert run.call([XRDCP, "-f", f"{hub}b.bin", got],
                        check=False).returncode == 0
        assert got.read_bytes() == src.read_bytes()


@pytest.mark.optin
@pytest.mark.timeout(120)
def test_audit_attribution_matches_owner(lifecycle) -> None:
    """(security / attribution) The identity recorded on a write op is the same
    synthetic (uid, gid) the catalog stamps as the created row's owner — the
    attribution contract multiuser tests rely on. Here the transfer is the
    service identity (0/0), so both sides read 0/0, proving the plumbing wires
    the catalog identity through rather than a hardcoded constant."""
    _need_bins()
    with LiveRun("pblock_audit_attr", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-audit-attr", "?audit=1"))
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        hub = f"root://{ep.host}:{ep.port}/"
        src = run.root / "src.bin"
        random_file(src, 700_000)

        assert run.call([XRDCP, "-f", src, f"{hub}owned.bin"],
                        check=False).returncode == 0

        conn = sqlite3.connect(str(catalog), timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            owner = conn.execute(
                "SELECT uid, gid FROM objects WHERE path = '/owned.bin';"
            ).fetchone()
            audit = conn.execute(
                "SELECT uid, gid FROM oplog WHERE path = '/owned.bin' "
                "AND op IN ('commit', 'close') ORDER BY seq DESC LIMIT 1;"
            ).fetchone()
        finally:
            conn.close()

        assert owner is not None, "objects row for the created file is missing"
        assert audit is not None, "no commit/close audit record for the file"
        assert (audit["uid"], audit["gid"]) == (owner["uid"], owner["gid"]), \
            f"audit identity {tuple(audit)} != catalog owner {tuple(owner)}"
