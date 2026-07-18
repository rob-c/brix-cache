"""Phase-83 F15 — mandatory byte-range/whole-file lease enforcement (pblock).

With `locks=1` in the backend `?tail`, the driver-owned
`locks(path, off, len, mode, owner, expires_at)` table becomes MANDATORY
enforcement: a live foreign whole-file lease (`len=0`) refuses conflicting
opens at open time, a live foreign range lease (`len>0`) denies overlapping
pwrites through the open-time snapshot, and the bypass routes — unlink and
rename of a leased path — are blocked too. Modes: 'W' excludes other writers,
'X' excludes everyone. Refusals are EAGAIN → kXR_FileLocked / HTTP 423.
Leases carry an `expires_at` deadline so a crashed client can never wedge the
export. Tests plant lease rows via sqlite3 (the standard ctl channel) with a
synthetic owner uid foreign to the wire identity (0).

The tests prove: a foreign whole-file 'W' lease refuses a second writer while
readers still pass, and a range 'W' lease admits the open but denies the
overlapping write (success); an expired lease frees the path and a
soon-to-expire one frees it exactly at expiry (error); and the lock cannot be
bypassed — 'X' refuses reads and unlink/rename of the leased name — while a
gate-off export treats identical rows as inert (security-neg).
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


FOREIGN_OWNER = 12345      # synthetic catalog uid; wire identity is 0


def _lock(catalog: Path, path: str, *, off: int = 0, length: int = 0,
          mode: str = "W", owner: int = FOREIGN_OWNER,
          ttl: float = 3600) -> None:
    """Plant a lease row (ttl in seconds from now; negative = already expired)."""
    conn = sqlite3.connect(str(catalog), timeout=10)
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS locks("
            "  path TEXT NOT NULL,"
            "  off INTEGER NOT NULL DEFAULT 0,"
            "  len INTEGER NOT NULL DEFAULT 0,"
            "  mode TEXT NOT NULL DEFAULT 'W',"
            "  owner INTEGER NOT NULL DEFAULT 0,"
            "  expires_at INTEGER NOT NULL DEFAULT 0);")
        conn.execute("INSERT INTO locks VALUES(?, ?, ?, ?, ?, ?)",
                     (path, off, length, mode, owner,
                      int(time.time() + ttl)))
        conn.commit()
    finally:
        conn.close()


def _unlock_all(catalog: Path, path: str) -> None:
    conn = sqlite3.connect(str(catalog), timeout=10)
    try:
        conn.execute("DELETE FROM locks WHERE path = ?", (path,))
        conn.commit()
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
def test_locks_whole_file_and_range_write_exclusion(lifecycle) -> None:
    """(success) Writer A's whole-file 'W' lease refuses writer B's PUT at
    open time (kXR_FileLocked) while a plain GET still passes ('W' excludes
    writers, not readers); released, B lands. A range 'W' lease admits the
    open but denies the overlapping write through the open-time snapshot."""
    _need_bins()
    with LiveRun("pblock_lk_ok", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-lk-ok", "?locks=1"))
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        host = f"root://{ep.host}:{ep.port}"
        src = run.root / "src.bin"
        src2 = run.root / "src2.bin"
        random_file(src, 300_000)
        random_file(src2, 200_000)

        assert run.call([XRDCP, "-f", src, f"{host}/f.bin"],
                        check=False).returncode == 0

        # Writer A takes a whole-file write lease.
        _lock(catalog, "/f.bin", length=0, mode="W")
        assert run.call([XRDCP, "-f", src2, f"{host}/f.bin"],
                        check=False).returncode != 0, \
            "PUT over a live foreign whole-file 'W' lease was admitted"
        got = run.root / "got.bin"
        assert run.call([XRDCP, "-f", f"{host}/f.bin", got],
                        check=False).returncode == 0, \
            "a 'W' lease must not refuse readers"
        assert sha256(got) == sha256(src)

        # Release → B proceeds.
        _unlock_all(catalog, "/f.bin")
        assert run.call([XRDCP, "-f", src2, f"{host}/f.bin"],
                        check=False).returncode == 0, \
            "PUT still refused after the lease was released"

        # A range 'W' lease admits the open; the overlapping pwrite is denied
        # by the open-time snapshot, so the upload dies mid-flight.
        _lock(catalog, "/f.bin", off=0, length=4096, mode="W")
        assert run.call([XRDCP, "-f", src, f"{host}/f.bin"],
                        check=False).returncode != 0, \
            "write overlapping a live foreign range lease was admitted"


@pytest.mark.optin
@pytest.mark.timeout(150)
def test_locks_expiry_frees_the_path(lifecycle) -> None:
    """(error) Leases are deadlines, not flags: an already-expired row is
    inert, and a live short-TTL lease refuses B only until `expires_at`
    passes — a crashed client can never wedge the export."""
    _need_bins()
    with LiveRun("pblock_lk_exp", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-lk-exp", "?locks=1"))
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        host = f"root://{ep.host}:{ep.port}"
        src = run.root / "src.bin"
        random_file(src, 200_000)

        # Already expired ⇒ inert from the first byte.
        _lock(catalog, "/f.bin", mode="X", ttl=-5)
        assert run.call([XRDCP, "-f", src, f"{host}/f.bin"],
                        check=False).returncode == 0, \
            "an expired lease refused the open"

        # Live for ~3s ⇒ refused now, admitted at expiry (deadline poll —
        # the window is anchored to the row's server-side expires_at).
        _lock(catalog, "/f.bin", mode="W", ttl=3)
        assert run.call([XRDCP, "-f", src, f"{host}/f.bin"],
                        check=False).returncode != 0, \
            "a live lease did not refuse the writer"
        deadline = time.monotonic() + 15
        while run.call([XRDCP, "-f", src, f"{host}/f.bin"],
                       check=False).returncode != 0:
            assert time.monotonic() < deadline, \
                "the lease never expired — a dead client wedged the export"
            time.sleep(0.5)


@pytest.mark.optin
@pytest.mark.timeout(150)
def test_locks_no_bypass_and_gate_off_inert(lifecycle) -> None:
    """(security-neg) The lease cannot be dissolved from the data plane: an
    'X' lease refuses reads AND the bypass routes — unlink and rename of the
    leased name — until released. And without `locks=1` in the tail, the
    identical rows are inert (enforcement cannot be armed via sqlite alone)."""
    _need_bins()
    with LiveRun("pblock_lk_sec", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-lk-sec", "?locks=1"))
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        host = f"root://{ep.host}:{ep.port}"
        src = run.root / "src.bin"
        random_file(src, 200_000)

        assert run.call([XRDCP, "-f", src, f"{host}/f.bin"],
                        check=False).returncode == 0

        _lock(catalog, "/f.bin", mode="X")
        got = run.root / "got.bin"
        assert run.call([XRDCP, "-f", f"{host}/f.bin", got],
                        check=False).returncode != 0, \
            "an 'X' lease must exclude readers too"
        assert run.call([XRDFS, host, "rm", "/f.bin"],
                        check=False).returncode != 0, \
            "unlink dissolved a live foreign lease"
        assert run.call([XRDFS, host, "mv", "/f.bin", "/g.bin"],
                        check=False).returncode != 0, \
            "rename dissolved a live foreign lease"
        # The object survived every bypass attempt.
        _unlock_all(catalog, "/f.bin")
        assert run.call([XRDCP, "-f", f"{host}/f.bin", got],
                        check=False).returncode == 0
        assert sha256(got) == sha256(src)

    with LiveRun("pblock_lk_off", None) as run:
        ep = lifecycle.start(pblock_lab_spec("lc-pblock-lk-off", ""))  # no ?locks tail: gate OFF
        time.sleep(1)
        catalog = Path(ep.data_root) / "catalog.db"
        host = f"root://{ep.host}:{ep.port}"
        src = run.root / "src.bin"
        random_file(src, 200_000)

        assert run.call([XRDCP, "-f", src, f"{host}/f.bin"],
                        check=False).returncode == 0
        _lock(catalog, "/f.bin", mode="X")      # hand-planted, gate off
        got = run.root / "got.bin"
        assert run.call([XRDCP, "-f", f"{host}/f.bin", got],
                        check=False).returncode == 0, \
            "gate-off export enforced hand-planted lock rows"
        assert sha256(got) == sha256(src)
        assert run.call([XRDCP, "-f", src, f"{host}/f.bin"],
                        check=False).returncode == 0
        assert run.call([XRDFS, host, "mv", "/f.bin", "/g.bin"],
                        check=False).returncode == 0, \
            "gate-off export refused a rename over inert rows"
