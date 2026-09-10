"""`tools/diag/lock_scan.py` — the pre-upgrade lock inventory an operator runs.

WHY THIS FILE EXISTS: `docs/03-configuration/directives.md` tells an operator to
run this tool *before* switching an export to `brix_lock_enforcement strict`, and
until 2026-09-09 the tool was **gitignored** — absent from every fresh clone, and
invisible to every guard and every test. Exempting it in `.gitignore` immediately
found five complexity violations; decomposing those is the reason these tests
exist. The tool has no other coverage anywhere.

The contract pinned here is the one the docs promise:
  * exit 0 = no live locks, 1 = live locks found, 2 = usage/IO error;
  * a legacy v1 record is treated as already expired (its monotonic expiry is
    meaningless across a reboot) — the same rule `brix_lock_record_decode()`
    applies in `src/`;
  * expired records are counted, never listed;
  * **lock tokens are bearer secrets and are never printed.**
"""
import importlib.util
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.xdist_group("lock-scan-tool")

REPO = Path(__file__).resolve().parents[1]
TOOL = REPO / "tools" / "diag" / "lock_scan.py"
XATTR = "user.nginx_xrootd.lock"


def _load():
    spec = importlib.util.spec_from_file_location("brix_lock_scan", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lock_scan = _load()


def _xattrs_work(directory: Path) -> bool:
    probe = directory / ".xattr-probe"
    probe.write_text("x")
    try:
        os.setxattr(probe, XATTR, b"v=2")
        return True
    except OSError:
        return False
    finally:
        probe.unlink()


def _require_xattrs(directory: Path) -> None:
    if not _xattrs_work(directory):
        pytest.skip("filesystem does not support user xattrs")


def _record(token="tok-secret", expires=None, version=2, **extra) -> bytes:
    fields = {
        "v": version, "token": token, "owner": "alice",
        "expires": int(time.time()) + 3600 if expires is None else expires,
        "scope": "exclusive", "depth": "0", "null": "0",
    }
    fields.update(extra)
    return "|".join(f"{k}={v}" for k, v in fields.items()).encode()


def _run(*roots) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *[str(r) for r in roots]],
        capture_output=True, text=True, timeout=60, check=False)


# --- the tool is present at all ---------------------------------------------

def test_the_tool_ships_in_the_clone():
    """The whole point of the 2026-09-09 .gitignore exemption. A tool the docs
    tell an operator to run must be in `git ls-files`, not merely on disk."""
    assert TOOL.is_file()
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "tools/diag/lock_scan.py"],
        cwd=REPO, capture_output=True, text=True, check=False)
    assert tracked.returncode == 0, (
        "tools/diag/lock_scan.py is not tracked; a fresh clone cannot follow the "
        "upgrade procedure in docs/03-configuration/directives.md. "
        f"git said: {tracked.stderr.strip()}")


# --- decode(): success ------------------------------------------------------

def test_decode_reads_a_schema_v2_record():
    rec = lock_scan.decode(_record(expires=1893456000))
    assert rec["token"] == "tok-secret"
    assert rec["owner"] == "alice"
    assert rec["expires"] == 1893456000
    assert rec["scope"] == "exclusive"


def test_decode_ignores_unknown_keys():
    """Forward compatibility: a field a newer server writes must not break an
    older operator's scan."""
    raw = _record() + b"|unheard_of=1|another=x"
    assert lock_scan.decode(raw)["token"] == "tok-secret"


# --- decode(): error --------------------------------------------------------

def test_a_record_without_a_token_is_invalid():
    raw = b"v=2|owner=alice|expires=1893456000"
    assert lock_scan.decode(raw) is None


def test_an_unparseable_integer_becomes_zero():
    """The C decoder does not fail the record; neither may this one."""
    rec = lock_scan.decode(_record(expires="not-a-number"))
    assert rec["expires"] == 0


def test_undecodable_bytes_do_not_raise():
    assert lock_scan.decode(b"\xff\xfe|token=t|v=2|expires=0") is not None


def test_a_legacy_v1_record_is_forced_expired():
    """A v1 expiry is a monotonic clock reading — meaningless after a reboot. It
    must never be read as a far-future live lock."""
    rec = lock_scan.decode(_record(version=1, expires=99999999999))
    assert rec["expires"] == 0


# --- probe() / scan_root() --------------------------------------------------

def _plant(directory, name, **record) -> Path:
    """A file carrying one lock record; no record at all when none is given."""
    path = directory / name
    path.write_text("x")
    if record:
        os.setxattr(path, XATTR, _record(**record))
    return path


def test_probe_classifies_live_expired_and_absent(tmp_path):
    _require_xattrs(tmp_path)
    now = int(time.time())
    live = _plant(tmp_path, "live", expires=now + 3600)
    dead = _plant(tmp_path, "dead", expires=now - 1)
    bare = _plant(tmp_path, "bare")

    assert lock_scan.probe(bare, now) is None
    assert lock_scan.probe(dead, now) is lock_scan.EXPIRED
    assert lock_scan.probe(live, now)["owner"] == "alice"


def test_scan_root_finds_a_lock_on_the_root_itself(tmp_path):
    """A Depth: infinity collection lock on the export root covers everything
    beneath it, so the root must be probed — not just its children."""
    _require_xattrs(tmp_path)
    now = int(time.time())
    os.setxattr(tmp_path, XATTR, _record(expires=now + 3600))
    found = [path for path, _ in lock_scan.scan_root(str(tmp_path), now)
             if path is not None]
    assert found == [str(tmp_path)]


def test_scan_root_counts_expired_records_in_its_trailer(tmp_path):
    _require_xattrs(tmp_path)
    now = int(time.time())
    for index in range(3):
        _plant(tmp_path, f"dead{index}", expires=now - 1)
    results = list(lock_scan.scan_root(str(tmp_path), now))
    assert results[-1][0] is None and results[-1][1] == 3
    assert [path for path, _ in results[:-1]] == []


# --- exit statuses, as documented -------------------------------------------

def test_a_clean_export_exits_zero(tmp_path):
    assert _run(tmp_path).returncode == 0


def test_a_live_lock_exits_one(tmp_path):
    _require_xattrs(tmp_path)
    locked = tmp_path / "held"
    locked.write_text("x")
    os.setxattr(locked, XATTR, _record())
    done = _run(tmp_path)
    assert done.returncode == 1
    assert "LIVE lock" in done.stdout
    assert "1 live, 0 expired" in done.stdout


def test_a_missing_root_exits_two(tmp_path):
    done = _run(tmp_path / "nope")
    assert done.returncode == 2
    assert "not a directory" in done.stderr


def test_a_bad_root_is_refused_before_any_root_is_scanned(tmp_path):
    """Every root is validated up front: a typo in the second argument must not
    leave the operator with a half-finished report they may read as complete."""
    done = _run(tmp_path, tmp_path / "nope")
    assert done.returncode == 2
    assert done.stdout == ""


# --- security negative ------------------------------------------------------

def test_the_lock_token_is_never_printed(tmp_path):
    """A lock token is a bearer secret: whoever holds it can UNLOCK the
    resource. This tool's output goes into tickets, pastebins and terminal
    scrollback, so it prints owner/scope/depth/expiry and NEVER the token."""
    _require_xattrs(tmp_path)
    locked = tmp_path / "held"
    locked.write_text("x")
    os.setxattr(locked, XATTR, _record(token="opaquelocktoken:SUPERSECRET"))
    done = _run(tmp_path)
    assert done.returncode == 1
    assert "SUPERSECRET" not in done.stdout
    assert "SUPERSECRET" not in done.stderr
    assert "opaquelocktoken" not in done.stdout
    assert "owner=alice" in done.stdout      # the tool did read the record


def test_an_expired_lock_is_counted_but_not_listed(tmp_path):
    """The gate treats an expired record as absent. Listing it as a lock would
    push an operator into hand-editing xattrs — which the docs forbid."""
    _require_xattrs(tmp_path)
    lapsed = tmp_path / "lapsed"
    lapsed.write_text("x")
    os.setxattr(lapsed, XATTR, _record(expires=int(time.time()) - 1))
    done = _run(tmp_path)
    assert done.returncode == 0
    assert "LIVE" not in done.stdout
    assert "0 live, 1 expired" in done.stdout
