"""Pin the cross-worker isolation properties of official_interop_lib.

Round-6 fast-lane failures traced to shared-state leaks between xdist workers
running the same conf module; the durable fix is idempotent
harmonize_perms/chown_stock (a redundant chmod/chown from another worker's
start_pair must never bump ctime under a stat-parity test). The data roots
themselves are deliberately SHARED and fixed: the standing fleet pair exports
exactly ``data-interop-our``/``data-interop-off`` and several conf modules
raw-wire to the fixed fleet ports, so per-worker-suffixed roots desync seeding
from what those servers serve (round-7 regression: every seeded file 3011).

Round-11 addition: BOTH shared-tree deleters (_wipe_stale_working_files and
reset_to_seeded_tree) must judge staleness through _entry_is_stale — the
import-time gate plus an absolute freshness floor (_LIVE_FILE_GUARD_S). The
unconditional reset_to_seeded_tree deleted every other worker's in-flight
working file mid-lane (simultaneous 3011/FileNotFound on three workers), and
the floor protects against the WSL2 backwards clock steps / worker import
skew pushing a just-created file's mtime behind a worker's _IMPORT_TIME.
"""

import os
import time

import official_interop_lib as L


def test_data_roots_are_the_fixed_fleet_exports():
    assert L.FLEET_OUR_DATA == os.path.join(L.TEST_ROOT, "data-interop-our")
    assert L.FLEET_OFF_DATA == os.path.join(L.TEST_ROOT, "data-interop-off")
    assert L.FLEET_OUR_DATA != L.FLEET_OFF_DATA


def test_seed_file_is_create_once(tmp_path):
    f = tmp_path / "seeded.bin"
    L._seed_file(str(f), b"first")
    before = os.stat(f).st_mtime_ns
    L._seed_file(str(f), b"second")    # concurrent re-seed must be a no-op
    assert f.read_bytes() == b"first"
    assert os.stat(f).st_mtime_ns == before


def test_harmonize_perms_is_idempotent_no_ctime_bump(tmp_path):
    f = tmp_path / "seed.bin"
    f.write_bytes(b"x")
    L.harmonize_perms(str(f))
    before = os.stat(f).st_ctime_ns
    L.harmonize_perms(str(f))          # second run must be a pure no-op
    assert os.stat(f).st_ctime_ns == before, \
        "redundant harmonize_perms bumped ctime — stat-parity tests will flap"


def test_harmonize_perms_still_mirrors_a_divergent_mode(tmp_path):
    f = tmp_path / "locked.bin"
    f.write_bytes(b"x")
    os.chmod(f, 0o600)
    L.harmonize_perms(str(f))
    assert (os.stat(f).st_mode & 0o777) == 0o666, \
        "idempotence guard must not disable the actual mirroring"


def _backdate(path, seconds):
    old = time.time() - seconds
    os.utime(path, (old, old))


def test_entry_is_stale_flags_prior_run_leftovers(tmp_path):
    f = tmp_path / "leftover.bin"
    f.write_bytes(b"x")
    _backdate(f, 3600)                    # an hour old: predates _IMPORT_TIME
    assert L._entry_is_stale(str(f)) is True


def test_entry_is_stale_freshness_floor_beats_import_gate(tmp_path, monkeypatch):
    """A just-created file must be LIVE even when its mtime sits behind this
    worker's _IMPORT_TIME (WSL2 backwards clock step / worker import skew)."""
    f = tmp_path / "just_written.bin"
    f.write_bytes(b"x")
    # Simulate the skew: this worker's import time is "after" the file's mtime.
    monkeypatch.setattr(L, "_IMPORT_TIME", time.time() + 30)
    assert L._entry_is_stale(str(f)) is False, \
        "freshness floor must protect a just-created file from the import gate"
    # And a genuinely old leftover is still stale under the same skew.
    _backdate(f, L._LIVE_FILE_GUARD_S + 3600)
    assert L._entry_is_stale(str(f)) is True


def test_entry_is_stale_unstattable_entry_is_live(tmp_path):
    assert L._entry_is_stale(str(tmp_path / "vanished.bin")) is False, \
        "deleting on an unknown age is the exact failure mode being prevented"


def test_reset_to_seeded_tree_preserves_live_working_files(tmp_path):
    """Round-11 pin: reset_to_seeded_tree must never delete another worker's
    in-flight (this-run) working file from the shared roots — only genuinely
    stale prior-run leftovers — while still restoring the seeded tree."""
    root = tmp_path / "data-root"
    root.mkdir()
    live = root / "sizematrix_diff_our_5242880.bin"   # a round-11 victim name
    live.write_bytes(b"in-flight")
    stale = root / "seq_full_off_0.bin"
    stale.write_bytes(b"prior run")
    _backdate(stale, L._LIVE_FILE_GUARD_S + 3600)
    L.reset_to_seeded_tree(str(root))
    assert live.exists() and live.read_bytes() == b"in-flight", \
        "reset_to_seeded_tree deleted a live working file (round-11 regression)"
    assert not stale.exists(), "stale prior-run leftover must still be removed"
    assert (root / "hello.txt").exists(), "seeded tree must be restored"


def test_wipe_stale_working_files_preserves_live_files(tmp_path):
    root = tmp_path / "wipe-root"
    root.mkdir()
    live = root / "seq_t0_our_65536_100.bin"          # a round-11 victim name
    live.write_bytes(b"in-flight")
    stale = root / "pgw_old.bin"
    stale.write_bytes(b"prior run")
    _backdate(stale, L._LIVE_FILE_GUARD_S + 3600)
    L._wipe_stale_working_files(str(root))
    assert live.exists(), "janitor deleted a this-run file"
    assert not stale.exists(), "janitor must still reclaim prior-run leftovers"
