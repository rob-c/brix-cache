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
import importlib.util
import json
from types import SimpleNamespace

import pytest

import official_interop_lib as L


def _load_complete_interop_module():
    """Execute the real parent plus every continuation in an isolated namespace."""
    spec = importlib.util.spec_from_file_location('_interop_export_contract', L.__file__)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_suite_values():
    from brix_suite import settings_values

    spec = importlib.util.spec_from_file_location('_suite_storage_contract', settings_values.__file__)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _mapped_interop_environment(tmp_path, monkeypatch, shared_root):
    native = tmp_path / 'native-export'
    native.mkdir(mode=0o700)
    (native / '.brix-reference-native-export.json').write_text(json.dumps(
        dict(schema_version=1, shared_root=shared_root)))
    monkeypatch.setenv('TEST_REFERENCE_BRIX_DATA_ROOT', str(native))
    monkeypatch.setenv('TEST_REFERENCE_SHARED_ROOT', L.TEST_ROOT)
    return native


def test_interop_continuations_preserve_the_proven_native_export_mapping(tmp_path, monkeypatch):
    native = _mapped_interop_environment(tmp_path, monkeypatch, os.path.realpath(L.TEST_ROOT))
    module = _load_complete_interop_module()
    assert module.FLEET_OUR_DATA == str(native / 'data-interop-our')
    assert module.FLEET_OFF_DATA == os.path.join(L.TEST_ROOT, 'data-interop-off')


def test_complete_interop_module_refuses_another_lanes_native_export(tmp_path, monkeypatch):
    native = _mapped_interop_environment(tmp_path, monkeypatch, '/different/fixture-lane')
    with pytest.raises(ValueError, match='another fixture lane'):
        _load_complete_interop_module()
    assert list(native.iterdir()) == [native / '.brix-reference-native-export.json']


def test_complete_interop_module_retains_ordinary_native_paths_without_mapping(monkeypatch):
    monkeypatch.delenv('TEST_REFERENCE_BRIX_DATA_ROOT', raising=False)
    module = _load_complete_interop_module()
    assert module.FLEET_OUR_DATA == os.path.join(L.TEST_ROOT, 'data-interop-our')
    assert module.FLEET_OFF_DATA == os.path.join(L.TEST_ROOT, 'data-interop-off')


def test_main_and_compression_seeds_use_native_storage_in_the_remote_lane(tmp_path, monkeypatch):
    native = _mapped_interop_environment(tmp_path, monkeypatch, os.path.realpath(L.TEST_ROOT))
    values = _load_suite_values()
    assert values.DATA_ROOT == str(native / 'data')
    assert values.COMPRESS_DATA_ROOT == str(native / 'data-compress')
    assert values.TMP_DIR == os.path.join(L.TEST_ROOT, 'tmp')


def test_suite_storage_mapping_requires_the_correct_lane_marker(tmp_path, monkeypatch):
    _mapped_interop_environment(tmp_path, monkeypatch, '/different/fixture-lane')
    with pytest.raises(ValueError, match='another fixture lane'):
        _load_suite_values()


def test_ordinary_suite_main_and_compression_paths_are_unchanged(monkeypatch):
    monkeypatch.delenv('TEST_REFERENCE_BRIX_DATA_ROOT', raising=False)
    values = _load_suite_values()
    assert values.DATA_ROOT == os.path.join(L.TEST_ROOT, 'data')
    assert values.COMPRESS_DATA_ROOT == os.path.join(L.TEST_ROOT, 'data-compress')


@pytest.mark.parametrize('handoff', ['chown_stock', 'chown_brix'])
def test_non_root_interop_does_not_attempt_service_account_ownership(monkeypatch, handoff):
    """Both daemons retain the invoking identity; no inaccessible tree is walked."""
    monkeypatch.setattr(L.os, 'geteuid', lambda: 2101)
    monkeypatch.setattr(L.pwd, 'getpwnam', lambda name: pytest.fail('non-root account lookup'))
    monkeypatch.setattr(L, '_phase_chown_stock_1', lambda *args: pytest.fail('non-root ownership handoff'))
    getattr(L, handoff)('/fixture/no-traversal')


def test_root_reference_handoff_still_uses_the_selected_service_ids(monkeypatch):
    calls = []
    monkeypatch.setattr(L.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(L, '_nobody_ids', lambda: (65534, 65534))
    monkeypatch.setattr(L, '_expression_1', lambda path: False)
    monkeypatch.setattr(L, '_phase_chown_stock_1', lambda *args: calls.append(args))
    L.chown_stock('/fixture/stock')
    assert calls == [('/fixture/stock', 65534, 65534)]


def test_root_brix_handoff_still_uses_the_compiled_worker_identity(monkeypatch):
    from brix_suite import worker_identity

    calls = []
    monkeypatch.setattr(L.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(worker_identity, 'nginx_default_worker_user', lambda binary: 'selected-worker')
    monkeypatch.setattr(L.pwd, 'getpwnam', lambda name: SimpleNamespace(pw_uid=2109, pw_gid=2110))
    monkeypatch.setattr(L, '_expression_1', lambda path: False)
    monkeypatch.setattr(L, '_phase_chown_stock_1', lambda *args: calls.append(args))
    L.chown_brix('/fixture/brix')
    assert calls == [('/fixture/brix', 2109, 2110)]


def test_missing_reference_service_account_never_mutates_a_tree(monkeypatch):
    monkeypatch.setattr(L.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(L, '_nobody_ids', lambda: None)
    monkeypatch.setattr(L, '_phase_chown_stock_1', lambda *args: pytest.fail('missing identity handoff'))
    L.chown_stock('/fixture/stock')


def test_data_roots_are_the_fixed_fleet_exports():
    from lib_py.reference_host import reference_brix_data_root

    expected = reference_brix_data_root(os.path.join(L.TEST_ROOT, "data-interop-our"), L.TEST_ROOT)
    assert L.FLEET_OUR_DATA == expected
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
    # A full lane can outlive an hour. "One hour ago" is then THIS run, not
    # a prior-run fixture; the import-time guard correctly preserves it.
    old = min(time.time(), L._IMPORT_TIME) - seconds
    os.utime(path, (old, old))


def test_artificial_leftovers_predate_import_even_late_in_a_long_suite(tmp_path, monkeypatch):
    monkeypatch.setattr(L, '_IMPORT_TIME', time.time() - 3 * 3600)
    path = tmp_path / 'prior-run.bin'
    path.write_bytes(b'prior run')
    _backdate(path, 3600)
    assert path.stat().st_mtime < L._IMPORT_TIME
    assert L._entry_is_stale(str(path))


def test_an_hour_old_file_created_after_import_is_still_owned_by_this_run(tmp_path, monkeypatch):
    now = time.time()
    monkeypatch.setattr(L, '_IMPORT_TIME', now - 3 * 3600)
    path = tmp_path / 'slow-live-operation.bin'
    path.write_bytes(b'in flight')
    os.utime(path, (now - 3600, now - 3600))
    assert not L._entry_is_stale(str(path))


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
