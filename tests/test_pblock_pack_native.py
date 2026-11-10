"""Packed arena failures preserve stripes, reject damage, and retain recoverable rows."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def pack_binary(server_native_compile):
    wrappers = ['malloc', 'pread64', 'pwrite64', 'fstat64', 'flock',
                'brix_plat_fsync_data', 'brix_plat_anon_fd', 'sqlite3_prepare_v2']
    # The configured Linux SDK uses the large-file libc symbols. The real
    # calls retain this SDK's native off_t and stat layout.
    return server_native_compile('pblock-pack', 'tests/c/pblock_pack_native_test.c',
                                 ['-Wl,--wrap=' + name for name in wrappers])


def run_pack(binary, root, operation, case):
    (root / 'pblock.opts').write_text('pack=1\n')
    result = subprocess.run([str(binary), str(root), operation, case],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('fault', ['', 'read-eintr', 'read-short',
                                  'write-eintr', 'write-short'])
def test_pack_roundtrip_handles_interrupted_and_partial_io(pack_binary, tmp_path, fault):
    run_pack(pack_binary, tmp_path, 'roundtrip', fault)


@pytest.mark.parametrize('fault', ['allocation', 'read', 'write', 'sync', 'lock',
                                  'stat', 'catalog-insert'])
def test_failed_admission_keeps_complete_striped_source(pack_binary, tmp_path, fault):
    run_pack(pack_binary, tmp_path, 'admit-fail', fault)


@pytest.mark.parametrize('fault', ['allocation', 'read', 'write', 'anon'])
def test_failed_read_does_not_destroy_packed_record(pack_binary, tmp_path, fault):
    run_pack(pack_binary, tmp_path, 'read-fail', fault)


@pytest.mark.parametrize('damage', ['header', 'key', 'crc', 'size', 'missing',
                                   'short-header', 'short-body'])
def test_damaged_record_never_becomes_a_read_handle_or_stripes(pack_binary, tmp_path,
                                                             damage):
    run_pack(pack_binary, tmp_path, 'damaged', damage)


@pytest.mark.parametrize('fault', ['directory', 'write'])
def test_failed_materialization_keeps_verified_packed_copy(pack_binary, tmp_path, fault):
    run_pack(pack_binary, tmp_path, 'materialize-fail', fault)


def test_invalid_pack_inputs_and_disabled_materialization(pack_binary, tmp_path):
    run_pack(pack_binary, tmp_path, 'invalid', '')


@pytest.mark.parametrize('statement', ['DROP TABLE pack;',
    'UPDATE pack SET seg=0;', 'UPDATE pack SET off=-1;', 'UPDATE pack SET len=-1;'])
def test_catalog_damage_fails_closed_for_every_read_path(pack_binary, tmp_path, statement):
    run_pack(pack_binary, tmp_path, 'catalog-fail', statement)


def test_full_segment_rolls_and_reaps_only_the_unreferenced_segment(pack_binary, tmp_path):
    run_pack(pack_binary, tmp_path, 'rollover', '')
