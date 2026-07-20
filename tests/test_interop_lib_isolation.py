"""Pin the cross-worker isolation properties of official_interop_lib.

Round-6 fast-lane failures traced to shared-state leaks between xdist workers
running the same conf module; the durable fix is idempotent
harmonize_perms/chown_stock (a redundant chmod/chown from another worker's
start_pair must never bump ctime under a stat-parity test). The data roots
themselves are deliberately SHARED and fixed: the standing fleet pair exports
exactly ``data-interop-our``/``data-interop-off`` and several conf modules
raw-wire to the fixed fleet ports, so per-worker-suffixed roots desync seeding
from what those servers serve (round-7 regression: every seeded file 3011).
"""

import os

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
