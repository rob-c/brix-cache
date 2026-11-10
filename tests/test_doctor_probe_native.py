"""Doctor findings distinguish healthy, broken and inconclusive remote behavior."""

import os
from pathlib import Path
import subprocess
import sys
import zlib

import pytest

from brix_suite.client_build import client_make, client_run
from test_eos_discovery_native import private_diag_entry
from test_xrd_dispatch_native import private_link_command

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping and object instrumentation')


@pytest.fixture(scope='module')
def doctor_probe(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('doctor-probe'); binary = output / 'xrddiag'
    plan = client_make(root / 'client', '-n', 'xrddiag', f'BINDIR={output}',
                       capture_output=True, text=True, timeout=120)
    assert plan.returncode == 0, plan.stdout + plan.stderr
    command = private_link_command(plan.stdout, binary)
    index = command.index('apps/diag/xrddiag.o')
    command[index:index + 1] = [str(private_diag_entry(root, output)),
                               str(root / 'tests/c/doctor_probe_native_test.c')]
    seams = ('brix_stat', 'brix_dirlist', 'brix_file_open_read', 'brix_file_open_write',
        'brix_file_read', 'brix_file_write', 'brix_file_close', 'brix_mkdir', 'brix_rm',
        'brix_rmdir', 'brix_prepare', 'dx_connect_as', 'brix_close', 'brix_query_cksum', 'download_to_fd')
    command += ['-I.', *['-Wl,--wrap=' + name for name in seams]]
    result = client_run(root / 'client', command, cwd=root / 'client',
                        capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


def invoke(binary, operation, fault='normal', error=3010, checksum=None):
    digest = f'{zlib.adler32(b"abc"):08x}' if checksum is None else checksum
    env = dict(os.environ, BRIX_DOCTOR_FAULT=fault, BRIX_DOCTOR_ERROR=str(error), BRIX_DOCTOR_CHECKSUM=digest)
    result = subprocess.run([str(binary), operation], env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    fields, events, findings = {}, [], []
    for line in result.stdout.splitlines():
        key, value = line.split('=', 1)
        if key == 'event':
            events.append(value)
        elif key == 'finding':
            findings.append(value.split('|', 3))
        else:
            fields[key] = int(value)
    return fields, events, findings


@pytest.mark.parametrize('operation,event_list', [
    ('namespace', ['stat', 'list']), ('read', ['stat', 'open-read', 'read', 'close-read']),
    ('stage', ['prepare']), ('checksum', ['query-checksum', 'download']),
    ('write', ['mkdir', 'open-write', 'write', 'close-write', 'open-read', 'read', 'close-read', 'rm', 'rmdir'])])
def test_successful_probe_reports_health_after_its_complete_operation(doctor_probe, operation, event_list):
    state, events, findings = invoke(doctor_probe, operation)
    assert state['status'] == 0 and state['findings'] == 1 and events == event_list
    assert findings[0][0] == operation and findings[0][1] == '0'


@pytest.mark.parametrize('fault', ['empty', 'hidden'])
def test_namespace_with_no_visible_data_is_inconclusive(doctor_probe, fault):
    state, events, findings = invoke(doctor_probe, 'namespace', fault)
    assert state['status'] == 1 and events == ['stat', 'list']
    assert 'no visible files' in findings[0][3]


@pytest.mark.parametrize('operation,fault,events', [
    ('namespace', 'stat', ['stat']), ('namespace', 'list', ['stat', 'list']),
    ('read', 'stat', ['stat']), ('read', 'open-read', ['stat', 'open-read']),
    ('read', 'read', ['stat', 'open-read', 'read', 'close-read']), ('stage', 'prepare', ['prepare'])])
def test_failed_operation_is_classified_without_advancing_or_leaking_handles(doctor_probe, operation, fault, events):
    state, actual, findings = invoke(doctor_probe, operation, fault)
    assert state['findings'] == 1 and actual == events
    assert findings[0][2] == '3010' and 'fixture-private-data' not in findings[0][3]


def test_offline_read_warns_without_opening_or_recalling(doctor_probe):
    state, events, findings = invoke(doctor_probe, 'read', 'offline')
    assert state['offline'] == state['status'] == 1 and events == ['stat']
    assert 'offline' in findings[0][3]


@pytest.mark.parametrize('fault,events', [
    ('mkdir', ['mkdir']), ('open-write', ['mkdir', 'open-write', 'rmdir']),
    ('write', ['mkdir', 'open-write', 'write', 'close-write', 'rm', 'rmdir']),
    ('close-write', ['mkdir', 'open-write', 'write', 'close-write', 'rm', 'rmdir'])])
def test_write_error_reverses_only_the_mutations_it_owned(doctor_probe, fault, events):
    state, actual, findings = invoke(doctor_probe, 'write', fault)
    assert state['findings'] == 1 and actual == events and findings[0][2] == '3010'


@pytest.mark.parametrize('fault', ['open-read', 'read', 'short', 'corrupt'])
def test_write_readback_mismatch_is_a_failure_and_still_cleans_up(doctor_probe, fault):
    state, events, findings = invoke(doctor_probe, 'write', fault)
    assert state['status'] == 2 and events[-2:] == ['rm', 'rmdir']
    assert 'did not match' in findings[0][3]


def test_cleanup_failure_adds_a_warning_after_verified_write(doctor_probe):
    state, events, findings = invoke(doctor_probe, 'write', 'cleanup')
    assert state['status'] == 1 and state['findings'] == 2 and events[-1] == 'rmdir'
    assert 'could not be removed' in findings[-1][3]


@pytest.mark.parametrize('operation', ['forged', 'expired'])
@pytest.mark.parametrize('error,status', [(3010, 0), (3030, 0), (-4, 0), (-2, 1), (3005, 1)])
def test_invalid_token_probe_only_passes_for_authentication_rejection(doctor_probe, operation, error, status):
    state, events, _findings = invoke(doctor_probe, operation, 'connect', error)
    assert state['status'] == status and events == ['connect']


@pytest.mark.parametrize('operation', ['forged', 'expired'])
def test_accepted_invalid_token_is_reported_as_failure(doctor_probe, operation):
    state, events, findings = invoke(doctor_probe, operation)
    assert state['status'] == 2 and events == ['connect', 'close-session']
    assert 'ACCEPTED' in findings[0][3]


@pytest.mark.parametrize('fault,status,events', [
    ('connect', 1, ['connect']), ('anonymous', 0, ['connect', 'close-session']),
    ('normal', 2, ['connect', 'stat', 'close-session']),
    ('anon-open', 2, ['connect', 'stat', 'open-read', 'close-read', 'close-session']),
    ('anon-denied', 0, ['connect', 'stat', 'open-read', 'close-session'])])
def test_anonymous_probe_detects_served_metadata_or_data_after_advertised_auth(doctor_probe, fault, status, events):
    state, actual, _findings = invoke(doctor_probe, 'anon', fault)
    assert state['status'] == status and actual == events


@pytest.mark.parametrize('error,status', [(3010, 0), (3030, 0), (-4, 0), (3025, 1), (3005, 1)])
def test_readonly_export_does_not_claim_token_scope_was_verified(doctor_probe, error, status):
    state, events, _findings = invoke(doctor_probe, 'scope', 'mkdir', error)
    assert state['status'] == status and events == ['connect', 'mkdir', 'close-session']


def test_successful_readonly_token_mutation_is_a_failure_and_is_reversed(doctor_probe):
    state, events, _findings = invoke(doctor_probe, 'scope')
    assert state['status'] == 2 and events == ['connect', 'mkdir', 'rmdir', 'close-session']


@pytest.mark.parametrize('fault,status', [('anonymous', 0), ('authenticated', 0), ('normal', 1)])
def test_auth_posture_distinguishes_intentional_anonymous_from_missing_credential(doctor_probe, fault, status):
    state, events, _findings = invoke(doctor_probe, 'auth', fault)
    assert state['status'] == status and events == []


def test_checksum_mismatch_is_reported_against_locally_computed_bytes(doctor_probe):
    state, events, findings = invoke(doctor_probe, 'checksum', checksum='ffffffff')
    assert state['status'] == 2 and events == ['query-checksum', 'download']
    assert 'disagrees' in findings[0][3]


@pytest.mark.parametrize('fault,error,count', [('query', 3010, 0), ('query', 3013, 1), ('download', 3010, 0)])
def test_unavailable_checksum_is_never_reported_as_verified(doctor_probe, fault, error, count):
    state, _events, findings = invoke(doctor_probe, 'checksum', fault, error)
    assert state['findings'] == count
    assert all('matches read data' not in finding[3] for finding in findings)
