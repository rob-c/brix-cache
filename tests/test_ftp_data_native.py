"""FTP transfers must screen passive peers and observe final server completion."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')
EPSV = '229 Entering Extended Passive Mode (|||45678|)'
PASV = '227 Entering Passive Mode (192,0,2,1,178,110)'


@pytest.fixture(scope='module')
def ftp_data_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('ftp-data-native')
    return compile_client_contract(root, output, 'tests/c/ftp_data_native_test.c',
        ('brix_tcp_connect', 'brix_ftp_io_read', 'brix_ftp_io_write_all',
         'brix_copy_quit_requested', 'malloc', 'calloc', 'realloc'))


@pytest.fixture
def ftp_run(ftp_data_binary, tmp_path):
    def run(operation='retr', replies=None, payload='test payload', fault='', expected=0, allow=False):
        script = tmp_path / 'replies'
        if replies is None:
            replies = [EPSV, '150 starting transfer', '226 transfer complete']
        script.write_bytes(('\r\n'.join(replies) + '\r\n').encode())
        result = subprocess.run([str(ftp_data_binary), operation, str(script), payload,
            fault, str(expected)], env=dict(os.environ, BRIX_GSIFTP_ALLOW_OFFPEER=str(int(allow))),
            capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout
    return run


@pytest.mark.parametrize('operation', ['retr', 'stor', 'slurp'])
@pytest.mark.parametrize('payload', ['', 'payload with\nmultiple lines\n'])
@pytest.mark.parametrize('passive', [[EPSV], ['500 EPSV unavailable', PASV]])
def test_transfer_preserves_bytes_and_requires_completion(ftp_run, operation, payload, passive):
    output = ftp_run(operation, [*passive, '125 data already open', '250 complete'], payload)
    assert 'DIAL 192.0.2.1 45678' in output and 'RESULT 0' in output


@pytest.mark.parametrize('operation', ['retr', 'stor', 'slurp'])
@pytest.mark.parametrize('replies,message', [
    (['229 malformed'], 'malformed EPSV'),
    (['500 no EPSV', '227 malformed'], 'malformed PASV'),
    (['500 no EPSV', '500 no PASV'], 'passive mode refused'),
    (['229 Entering Extended Passive Mode (|||22|)'], 'refusing data channel'),
    (['500 no EPSV', '227 Entering Passive Mode (192,0,2,1,0,22)'], 'refusing data channel'),
])
def test_passive_refusals_never_dial(ftp_run, operation, replies, message):
    output = ftp_run(operation, replies, expected=-1, allow=True)
    assert message in output and 'DIAL ' not in output


@pytest.mark.parametrize('allow,target', [(False, '192.0.2.1'), (True, '198.51.100.2')])
def test_offpeer_address_defaults_to_control_peer(ftp_run, allow, target):
    replies = ['500 no EPSV', '227 Passive (198,51,100,2,178,110)', '150 start', '226 done']
    output = ftp_run(replies=replies, allow=allow)
    assert f'DIAL {target} 45678' in output


@pytest.mark.parametrize('operation', ['retr', 'stor', 'slurp'])
@pytest.mark.parametrize('code,status', [(550, -10), (500, -2)])
def test_preliminary_refusal_releases_data_socket(ftp_run, operation, code, status):
    output = ftp_run(operation, [EPSV, f'{code} refused'], expected=-1)
    assert f'RESULT -1 {status} ' in output


@pytest.mark.parametrize('operation', ['retr', 'stor', 'slurp'])
@pytest.mark.parametrize('final', ['451 backend write failed', '150 never completed', 'invalid'])
def test_completed_payload_is_not_success_without_final_reply(ftp_run, operation, final):
    output = ftp_run(operation, [EPSV, '150 start', final], expected=-1)
    assert 'RESULT -1' in output


@pytest.mark.parametrize('operation,fault', [
    ('retr', 'connect'), ('stor', 'connect'), ('slurp', 'connect'),
    ('retr', 'malloc'), ('stor', 'malloc'), ('slurp', 'realloc'),
    ('retr', 'cancel'), ('stor', 'cancel'), ('retr', 'sink'), ('stor', 'source'),
    ('retr', 'read'), ('slurp', 'read'), ('stor', 'write'),
])
def test_transport_callback_and_allocation_errors_release_owned_resources(ftp_run, operation, fault):
    output = ftp_run(operation, fault=fault, expected=-1)
    assert 'RESULT -1' in output


def test_empty_listing_allocation_failure_leaves_no_output(ftp_run):
    output = ftp_run('slurp', payload='', fault='calloc', expected=-1)
    assert 'out of memory' in output


@pytest.mark.parametrize('replies', [[], ['500 no EPSV'], [EPSV], [EPSV, '150 start']])
def test_control_peer_disconnect_at_each_stage(ftp_run, replies):
    output = ftp_run(replies=replies, expected=-1)
    assert 'RESULT -1' in output
