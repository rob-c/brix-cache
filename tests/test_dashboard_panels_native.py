"""Dashboard panels retain counters and redact private fields under partial failures."""

import json
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def panels(server_native_compile):
    seams = ('json_object', 'json_array', 'brix_metrics_get_shm_zone', 'brix_fs_usage_stat',
             'brix_vfs_backend_export_count', 'brix_vfs_backend_export_info', 'brix_srv_snapshot')
    return server_native_compile('dashboard-panels', 'tests/c/dashboard_panels_native_test.c',
                                 ['-Wl,--wrap=' + name for name in seams])


def invoke(binary, panel, mode='live', redact=False, failure=0):
    result = subprocess.run([str(binary), panel, mode, str(int(redact)), str(failure)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout)


def test_cache_listener_filter_and_write_through_sums(panels):
    body = invoke(panels, 'cache')
    assert body['enabled'] is True and len(body['listeners']) == 1
    listener = body['listeners'][0]
    assert listener['port'] == 1094 and listener['auth'] == 'token'
    assert listener['occupancy_ratio'] == 0.75 and listener['bytes_available'] == 250
    assert body['write_through'] == {'enabled': True, 'dirty_handles': 6, 'flush_pending': 6,
        'flush_success_total': 12, 'flush_errors_total': 3, 'flush_bytes_total': 300}


@pytest.mark.parametrize('panel', ['cache', 'cvmfs'])
@pytest.mark.parametrize('mode', ['absent', 'null', 'sentinel'])
def test_unavailable_metric_zone_emits_disabled_shape(panels, panel, mode):
    body = invoke(panels, panel, mode)
    assert body['enabled'] is False
    assert body.get('listeners', body.get('repos')) == []


def test_cvmfs_duplicate_claims_emit_lowest_ready_slot_only(panels):
    body = invoke(panels, 'cvmfs')
    assert body['enabled'] is True and body['requests']['cas'] == 17
    assert len(body['repos']) == len(body['upstreams']) == 1
    assert body['repos'][0]['requests']['cas'] == 17
    assert body['upstreams'][0]['requests_total'] == 20
    assert body['upstreams'][0]['fill_duration_count'] == 7


def test_storage_census_distinguishes_local_capacity_and_remote_origin(panels):
    body = invoke(panels, 'storage')
    local, remote = body['exports']
    assert local['remote'] is False and local['bytes_total'] == 1000
    assert remote['remote'] is True and remote['staging'] is True
    assert remote['origin_host'] == 'private-origin.invalid' and 'bytes_total' not in remote
    assert list(body['io'].values()) == [{'bytes_read_total': 128, 'bytes_written_total': 64}]


@pytest.mark.parametrize('panel,field', [('cache', 'listeners'), ('storage', 'exports')])
def test_failed_filesystem_probe_does_not_fabricate_zero_capacity(panels, panel, field):
    body = invoke(panels, panel, 'stat-failed')
    assert body[field] and all('bytes_total' not in row for row in body[field])


def test_cluster_clamps_future_heartbeat_and_reports_drain_and_space_state(panels):
    body = invoke(panels, 'cluster')
    old, future = body['servers']
    assert old['heartbeat_age_ms'] == 900 and old['stale'] is True
    assert future['heartbeat_age_ms'] == 0 and future['stale'] is False
    assert future['draining'] is True and future['space_blocked'] is True


def test_transfer_detail_has_real_counts_and_stable_session_hash(panels):
    body = invoke(panels, 'transfer')
    assert body['id'] == 42 and body['bytes'] == 900
    assert body['counters'] == {'read_ops': 3, 'write_ops': 4, 'sync_ops': 5, 'close_ops': 6}
    assert len(body['session_hash']) == 8 and body['tpc']['remote_status'] == 206


@pytest.mark.parametrize('panel', ['cache', 'storage', 'cvmfs', 'cluster', 'transfer'])
@pytest.mark.parametrize('failure', range(9))
def test_anonymous_output_never_discloses_private_fields_even_on_allocation_failure(panels, panel, failure):
    body = invoke(panels, panel, redact=True, failure=failure)
    encoded = json.dumps(body)
    assert 'private' not in encoded and 'worker_pid' not in encoded
    assert 'origin_host' not in encoded and '"port"' not in encoded
