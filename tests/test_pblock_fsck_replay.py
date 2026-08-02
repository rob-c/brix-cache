"""Phase-83 F17 (deferred half) — ``pblock-fsck --replay``.

Re-executes a source catalog's ``oplog`` audit table against a FRESH export's
catalog and diffs the reproduced namespace against the source's own
``objects`` table (projection: path, is_dir, size, uid, gid).  Pure-Python:
the oplog and source catalog are forged directly with sqlite3 in the exact
shapes the driver writes (schema from ``pblock_ctl.c::pblock_audit_init`` /
``sd_pblock_catalog.c``), so no fleet or nginx is involved.

3-test ritual:
  success      — a create/mkdir/rename/copy/unlink trace replays to a
                 byte-identical namespace (exit 0, FINDINGS 0);
  error        — a crash-truncated source (objects table lost a committed
                 row the oplog proves) yields REPLAY-DIFF findings (exit 1);
                 a source without an oplog is a clear refusal (exit 2);
  security-neg — replay refuses a non-fresh target catalog (exit 3), refuses
                 an unknown target schema version (exit 3), and counts an
                 unknown op verb as a finding instead of silently dropping it.
"""

from __future__ import annotations

import sqlite3
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FSCK_SRC = REPO_ROOT / "tools/pblock-fsck/pblock-fsck.c"

OBJECTS_DDL = """
CREATE TABLE IF NOT EXISTS objects(
  path TEXT PRIMARY KEY,
  parent TEXT NOT NULL,
  is_dir INTEGER NOT NULL,
  blob_id TEXT NOT NULL DEFAULT '',
  size INTEGER NOT NULL DEFAULT 0,
  block_size INTEGER NOT NULL DEFAULT 0,
  mtime INTEGER NOT NULL DEFAULT 0,
  ctime INTEGER NOT NULL DEFAULT 0,
  mode INTEGER NOT NULL DEFAULT 0,
  uid INTEGER NOT NULL DEFAULT 0,
  gid INTEGER NOT NULL DEFAULT 0,
  xform TEXT NOT NULL DEFAULT '');
"""

OPLOG_DDL = """
CREATE TABLE IF NOT EXISTS oplog(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  op TEXT NOT NULL,
  path TEXT NOT NULL DEFAULT '',
  aux TEXT NOT NULL DEFAULT '',
  uid INTEGER NOT NULL DEFAULT 0,
  gid INTEGER NOT NULL DEFAULT 0,
  result INTEGER NOT NULL DEFAULT 0,
  errno INTEGER NOT NULL DEFAULT 0);
"""


@pytest.fixture(scope="module")
def fsck(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Compile the standalone oracle once for the module (same recipe as
    test_pblock_lab_crash.py — the tool's contract is single-file cc)."""
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


def _parent_of(path: str) -> str:
    if path == "/":
        return ""
    head = path.rsplit("/", 1)[0]
    return head or "/"


class SourceCatalog:
    """Forge a source catalog: an oplog (what the driver logged) plus the
    objects end-state (what the driver's catalog held when it was copied)."""

    def __init__(self, path: Path):
        self.path = path
        self.db = sqlite3.connect(path)
        self.db.executescript(OBJECTS_DDL + OPLOG_DDL)
        self._ts = 1000

    def log(self, op: str, path: str = "", aux: str = "",
            uid: int = 0, gid: int = 0, result: int = 0, err: int = 0):
        self._ts += 1
        self.db.execute(
            "INSERT INTO oplog(ts, op, path, aux, uid, gid, result, errno)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (self._ts, op, path, aux, uid, gid, result, err))

    def obj(self, path: str, is_dir: int = 0, size: int = 0,
            uid: int = 0, gid: int = 0):
        self.db.execute(
            "INSERT OR REPLACE INTO objects"
            " (path, parent, is_dir, size, uid, gid) VALUES(?,?,?,?,?,?)",
            (path, _parent_of(path), is_dir, size, uid, gid))

    def close(self):
        self.db.commit()
        self.db.close()


def _replay(fsck: Path, target_root: Path,
            source: Path) -> subprocess.CompletedProcess:
    target_root.mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        [str(fsck), str(target_root), "--replay", str(source)],
        capture_output=True, text=True, timeout=60)


def _namespace(catalog: Path):
    with sqlite3.connect(catalog) as db:
        return sorted(db.execute(
            "SELECT path, parent, is_dir, size, uid, gid FROM objects"))


# ---------------------------------------------------------------- success --

def test_full_trace_replays_to_identical_namespace(fsck, tmp_path):
    """mkdir + plain write (open/close) + staged commit + copy + rename +
    unlink replay to the source's exact namespace projection."""
    src = SourceCatalog(tmp_path / "source.db")

    src.log("mkdir", "/d", uid=7, gid=8)
    src.obj("/d", is_dir=1, uid=7, gid=8)

    src.log("open", "/d/a.bin", "flags=577", uid=7, gid=8)
    src.log("close", "/d/a.bin", "r=0 w=700000 mb=131072", uid=7, gid=8)
    src.obj("/d/a.bin", size=700000, uid=7, gid=8)

    src.log("staged_open", "/d/b.bin", uid=7, gid=8)
    src.log("commit", "/d/b.bin", "w=1234", uid=7, gid=8)
    src.obj("/d/b.bin", size=1234, uid=7, gid=8)

    src.log("copy", "/d/c.bin", "cow=1 w=1234", uid=7, gid=8)
    src.obj("/d/c.bin", size=1234, uid=7, gid=8)

    # rename the whole directory: descendants must follow (subtree reparent).
    src.log("rename", "/d", "/e")
    for row in list(src.db.execute("SELECT path FROM objects")):
        p = row[0]
        if p == "/d" or p.startswith("/d/"):
            np = "/e" + p[len("/d"):]
            src.db.execute(
                "UPDATE objects SET path=?, parent=? WHERE path=?",
                (np, _parent_of(np), p))

    src.log("unlink", "/e/c.bin", uid=7, gid=8)
    src.db.execute("DELETE FROM objects WHERE path='/e/c.bin'")
    src.close()

    proc = _replay(fsck, tmp_path / "fresh", src.path)
    assert proc.returncode == 0, f"replay diverged:\n{proc.stdout}{proc.stderr}"
    assert "FINDINGS 0" in proc.stdout
    assert "REPLAY applied=6 noop=2 skipped=0 unknown=0" in proc.stdout
    assert _namespace(tmp_path / "fresh/catalog.db") == _namespace(src.path)


def test_failed_and_readonly_ops_change_nothing(fsck, tmp_path):
    """result!=0 rows and pure-read closes (w=0) must not perturb the
    namespace: a failed mkdir creates nothing, a read-only close of an
    already-created file never shrinks it."""
    src = SourceCatalog(tmp_path / "source.db")
    src.log("close", "/f.bin", "r=0 w=4096 mb=4096", uid=1, gid=2)
    src.obj("/f.bin", size=4096, uid=1, gid=2)
    src.log("mkdir", "/nope", result=-1, err=17)      # EEXIST-style failure
    src.log("open", "/f.bin", "flags=1", uid=1, gid=2)
    src.log("close", "/f.bin", "r=4096 w=0 mb=4096", uid=1, gid=2)
    src.close()

    proc = _replay(fsck, tmp_path / "fresh", src.path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "skipped=1" in proc.stdout
    rows = _namespace(tmp_path / "fresh/catalog.db")
    assert rows == [("/f.bin", "/", 0, 4096, 1, 2)]


# ------------------------------------------------------------------ error --

def test_crash_truncated_source_yields_replay_diff(fsck, tmp_path):
    """The forensic leg: the oplog proves a commit the source's objects table
    lost (crash between audit write and catalog publish) — replay must
    surface exactly that row as a divergence, exit 1."""
    src = SourceCatalog(tmp_path / "source.db")
    src.log("close", "/kept.bin", "r=0 w=100 mb=100", uid=3, gid=3)
    src.obj("/kept.bin", size=100, uid=3, gid=3)
    src.log("commit", "/lost.bin", "w=555", uid=3, gid=3)
    # /lost.bin deliberately NOT in objects — the crash ate it.
    src.close()

    proc = _replay(fsck, tmp_path / "fresh", src.path)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "REPLAY-DIFF /lost.bin" in proc.stdout
    assert "FINDINGS 1" in proc.stdout
    assert "/kept.bin" not in proc.stdout        # converged rows stay quiet


def test_source_without_oplog_is_refused(fsck, tmp_path):
    """audit=1 was never on → no oplog table → clear error, exit 2."""
    plain = tmp_path / "no_oplog.db"
    with sqlite3.connect(plain) as db:
        db.executescript(OBJECTS_DDL)

    proc = _replay(fsck, tmp_path / "fresh", plain)
    assert proc.returncode == 2
    assert "no oplog" in proc.stderr


# ----------------------------------------------------------- security-neg --

def test_replay_refuses_non_fresh_target(fsck, tmp_path):
    """--replay is fail-closed on the fresh-export contract: a target catalog
    that already has namespace rows must be refused, untouched (exit 3)."""
    src = SourceCatalog(tmp_path / "source.db")
    src.log("mkdir", "/x")
    src.obj("/x", is_dir=1)
    src.close()

    used = tmp_path / "used"
    used.mkdir()
    with sqlite3.connect(used / "catalog.db") as db:
        db.executescript(OBJECTS_DDL)
        db.execute("INSERT INTO objects(path, parent, is_dir)"
                   " VALUES('/pre', '/', 1)")

    proc = _replay(fsck, used, src.path)
    assert proc.returncode == 3
    assert "non-empty" in proc.stderr
    assert _namespace(used / "catalog.db") == [("/pre", "/", 1, 0, 0, 0)]


def test_replay_refuses_unknown_target_schema(fsck, tmp_path):
    """Mutating-mode rule shared with --gc/--repair: an unknown catalog
    user_version on the TARGET is refused before any write (exit 3)."""
    src = SourceCatalog(tmp_path / "source.db")
    src.log("mkdir", "/x")
    src.close()

    future = tmp_path / "future"
    future.mkdir()
    with sqlite3.connect(future / "catalog.db") as db:
        db.execute("PRAGMA user_version = 99")

    proc = _replay(fsck, future, src.path)
    assert proc.returncode == 3
    assert "schema" in proc.stderr


def test_unknown_op_verb_is_a_finding_not_a_silent_drop(fsck, tmp_path):
    """Forward-compat fail-closed: an oplog from a newer driver with an op
    this tool doesn't know must be reported and fail the run, never silently
    skipped into a false 'reproduced' verdict."""
    src = SourceCatalog(tmp_path / "source.db")
    src.log("close", "/a.bin", "r=0 w=10 mb=10")
    src.obj("/a.bin", size=10)
    src.log("quantum_teleport", "/a.bin", "w=99")
    src.close()

    proc = _replay(fsck, tmp_path / "fresh", src.path)
    assert proc.returncode == 1
    assert "REPLAY-UNKNOWN-OP quantum_teleport" in proc.stdout
    assert "unknown=1" in proc.stdout
