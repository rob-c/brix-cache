"""Blob downloads fail closed on unverifiable bytes and unsafe redirects."""

import hashlib
from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def blob(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    return compile_client_contract(root, tmp_path_factory.mktemp('oci-blob'),
        'tests/c/oci_blob_native_test.c', ('httpx_connect', 'brix_tls_client_free',
        'brix_write_full', 'malloc', 'read_resp_headers', 'regc_token_dance',
        'httpx_download_body', 'lseek', 'read', 'ftruncate', 'brix_oci_hash_init',
        'brix_oci_hash_update', 'brix_oci_hash_final'))


def invoke(binary, tmp_path, mode, expected=0, hops=1, algorithm='sha256', digest=None):
    target = tmp_path / 'blob'
    wanted = digest or algorithm + ':' + hashlib.new(algorithm, b'payload').hexdigest()
    result = subprocess.run([str(binary), mode, str(target), wanted, str(expected),
        str(hops)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return target.read_bytes(), result.stdout


@pytest.mark.parametrize('algorithm', ['sha256', 'sha512'])
@pytest.mark.parametrize('mode,hops', [('normal', 1), ('auth', 2), ('redirect', 2)])
def test_verified_download_preserves_bytes_and_closes_every_hop(blob, tmp_path, algorithm, mode, hops):
    data, _ = invoke(blob, tmp_path, mode, hops=hops, algorithm=algorithm)
    assert data == b'payload'


@pytest.mark.parametrize('mode', ['connect', 'send', 'allocation', 'headers', 'body',
    'seek', 'read', 'hash-init', 'hash-update', 'hash-final'])
def test_transport_and_integrity_engine_failures_never_report_success(blob, tmp_path, mode):
    _, output = invoke(blob, tmp_path, mode, expected=-1)
    assert 'error=' in output


@pytest.mark.parametrize('mode,expected,hops', [('no-challenge', -2, 1),
    ('auth-error', -2, 1), ('no-location', -5, 1), ('bad-location', -5, 1),
    ('downgrade', -5, 1), ('status', -5, 1), ('loop', -1, 5), ('name', -5, 0)])
def test_untrusted_replies_and_unbounded_paths_are_refused(blob, tmp_path, mode, expected, hops):
    data, _ = invoke(blob, tmp_path, mode, expected=expected, hops=hops)
    assert data == b''


def test_invalid_digest_never_opens_transport(blob, tmp_path):
    data, output = invoke(blob, tmp_path, 'normal', expected=-5, hops=0, digest='sha256:bad')
    assert data == b'' and 'invalid blob digest' in output


@pytest.mark.parametrize('mode,remaining', [('normal', b''), ('truncate', b'payload')])
def test_mismatch_scrubs_or_reports_failed_scrub_without_accepting_bytes(blob, tmp_path, mode, remaining):
    bad = 'sha256:' + '0' * 64
    data, output = invoke(blob, tmp_path, mode, expected=-4, digest=bad)
    assert data == remaining and 'blob digest mismatch' in output
