"""Health probes handle fragmented replies and fail closed on TLS/setup errors."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def health_probe(server_native_compile):
    wrappers = ('brix_hc_finish', 'ngx_handle_read_event', 'ngx_handle_write_event',
                'ngx_palloc', 'brix_outbound_start_tls')
    return server_native_compile('health-probe', 'tests/c/health_probe_native_test.c',
                                 ['-Wl,--wrap=' + name for name in wrappers])


def invoke(binary, mode, phase=2, status=0, body=0, finished=0, passed=0):
    result = subprocess.run([str(binary), mode, *map(str, (phase, status, body, finished, passed))],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('mode', ['normal', 'partial', 'stat', 'send-again'])
def test_login_starts_bounded_probe_without_premature_verdict(health_probe, mode):
    invoke(health_probe, mode)


@pytest.mark.parametrize('mode', ['send-error', 'write-event-error', 'read-event-error',
                                'alloc-error', 'timeout', 'read-eof'])
def test_probe_io_or_admission_error_reports_one_failure(health_probe, mode):
    invoke(health_probe, mode, finished=1)


@pytest.mark.parametrize('phase', [0, 1, 2, 3])
def test_protocol_error_is_never_reported_as_healthy(health_probe, phase):
    invoke(health_probe, 'normal', phase=phase, status=4003, finished=1)


@pytest.mark.parametrize('mode', ['normal', 'partial', 'body-again'])
def test_complete_successful_probe_accepts_fragmented_body(health_probe, mode):
    invoke(health_probe, mode, phase=3, body=8, finished=1, passed=1)


@pytest.mark.parametrize('mode,body', [('body-eof', 8), ('alloc-error', 8), ('normal', 4097)])
def test_truncated_or_oversized_body_cannot_pass(health_probe, mode, body):
    invoke(health_probe, mode, phase=3, body=body, finished=1)


@pytest.mark.parametrize('mode', ['tls-normal', 'deferred'])
def test_deferred_login_resumes_after_protocol_and_trust(health_probe, mode):
    invoke(health_probe, mode, phase=1, body=8)


@pytest.mark.parametrize('mode', ['tls-start-error', 'tls-handshake-error', 'tls-untrusted',
                                'tls-alloc-error', 'tls-send-error', 'deferred-alloc-error'])
def test_failed_tls_or_login_setup_cannot_mark_peer_healthy(health_probe, mode):
    invoke(health_probe, mode, phase=1, body=8, finished=1)


def test_disabled_deep_tls_probe_accepts_protocol_liveness(health_probe):
    invoke(health_probe, 'tls-disabled', phase=1, body=8, finished=1, passed=1)


def test_pending_read_never_reports_a_health_verdict(health_probe):
    invoke(health_probe, 'read-again', phase=3)
