"""Tier readiness requires every capability and operation promised by its role."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def tier_status_binary(server_native_compile):
    return server_native_compile('tier-status', 'tests/c/tier_status_native_test.c')


def run_status(binary, tmp_path, role, gap, driver='posix'):
    result = subprocess.run([str(binary), role, gap, driver, str(tmp_path)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('role,gaps', [
    ('backend', 'open pread stat fstat RANGE_READ'),
    ('cache', 'open pread stat staged_open staged_write staged_commit staged_abort '
              'unlink opendir readdir closedir getxattr setxattr RANGE_READ '
              'RANDOM_WRITE DIRS XATTR'),
    ('stage', 'open pread staged_open staged_write staged_commit staged_abort '
              'unlink getxattr setxattr RANDOM_WRITE XATTR'),
])
def test_each_missing_operation_or_capability_keeps_tier_inactive(
        tier_status_binary, tmp_path, role, gaps):
    for gap in gaps.split():
        run_status(tier_status_binary, tmp_path, role, gap)


@pytest.mark.parametrize('role', ['backend', 'cache', 'stage', 'nearline'])
@pytest.mark.parametrize('gap', ['ready', 'null-gap'])
def test_complete_driver_clears_stale_gap_details(tier_status_binary, tmp_path, role, gap):
    run_status(tier_status_binary, tmp_path, role, gap)


@pytest.mark.parametrize('gap', ['recall', 'NEARLINE'])
def test_nearline_backend_requires_recall_contract(tier_status_binary, tmp_path, gap):
    run_status(tier_status_binary, tmp_path, 'nearline', gap, 'tape')


@pytest.mark.parametrize('driver', ['pblock', 'xroot', 'tape', 's3'])
def test_missing_driver_slot_identifies_relevant_gap(tier_status_binary, tmp_path, driver):
    run_status(tier_status_binary, tmp_path, 'backend', 'open', driver)


@pytest.mark.parametrize('gap', ['null-config', 'null-probe', 'null-driver'])
def test_absent_configuration_cannot_report_ready(tier_status_binary, tmp_path, gap):
    run_status(tier_status_binary, tmp_path, 'backend', gap)
