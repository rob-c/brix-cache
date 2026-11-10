"""Broker startup gates, reload cleanup and real double-fork fd confinement."""

import subprocess
import tempfile

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def broker_lifecycle(server_native_compile):
    names = ('brix_config_version_publish', 'geteuid', 'getpwnam', 'chown',
             'brix_idmap_init', 'fork', '_exit', 'brix_imp_broker_run')
    binary = server_native_compile('broker-lifecycle', 'tests/c/broker_lifecycle_native_test.c',
        ['-Wl,--wrap=' + name for name in names])
    def run(mode, result=0, maps=1, spawned=1):
        # Keep Unix socket paths below sun_path even with long pytest node names.
        with tempfile.TemporaryDirectory(prefix='c90-broker-') as directory:
            completed = subprocess.run([str(binary), mode, directory, str(result),
                str(maps), str(spawned)], capture_output=True, text=True, timeout=15)
        assert completed.returncode == 0, completed.stdout + completed.stderr
        return completed.stdout
    return run


@pytest.mark.parametrize('mode', ['normal', 'fallback', 'no-core', 'no-broker-user',
    'negative-min', 'chown-fail', 'serve-fail', 'stale', 'stale-invalid'])
def test_broker_has_only_owned_descriptors_and_the_worker_identity_gate(broker_lifecycle, mode):
    output = broker_lifecycle(mode)
    assert 'maps=1' in output
    assert 'chowns=1' in output


@pytest.mark.parametrize('mode', ['off', 'config-test'])
def test_inactive_or_validation_load_cannot_spawn_broker(broker_lifecycle, mode):
    assert 'chowns=0' in broker_lifecycle(mode, maps=0, spawned=0)


@pytest.mark.parametrize('mode', ['nonroot', 'missing-user', 'root-user', 'same-user', 'no-nobody'])
def test_unsafe_identity_is_rejected_before_mapping_or_socket(broker_lifecycle, mode):
    assert 'chowns=0' in broker_lifecycle(mode, result=-1, maps=0, spawned=0)


@pytest.mark.parametrize('mode', ['map-fail', 'socket-long', 'socket-parent',
                                 'root-missing', 'fork-fail'])
def test_startup_errors_cannot_publish_a_running_broker(broker_lifecycle, mode):
    broker_lifecycle(mode, result=-1, spawned=0)


@pytest.mark.parametrize('mode', ['seal-no-log', 'seal-no-file', 'seal-invalid-log', 'seal-stderr'])
def test_sealing_without_a_regular_logfile_drops_inherited_descriptors(broker_lifecycle, mode):
    broker_lifecycle(mode)
