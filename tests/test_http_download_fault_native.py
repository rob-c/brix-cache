"""Download framing preserves exact output and refuses incomplete peer responses."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping and object instrumentation')


@pytest.fixture(scope='module')
def download_probe(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    return compile_client_contract(root, tmp_path_factory.mktemp('http-download-fault'),
        'tests/c/http_download_fault_native_test.c', ('httpx_read_some', 'brix_write_full'))


def invoke(binary, tmp_path, wire, mode='normal', chunk=65536, resume=0):
    source = tmp_path / 'wire'; source.write_bytes(wire)
    output = tmp_path / 'download'
    result = subprocess.run([str(binary), str(source), str(output), mode,
        str(chunk), str(resume), '/' + 'x' * 4096], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    fields, diagnostic = result.stdout.split('\n', 1)
    return tuple(map(int, fields.split())), diagnostic, output.read_bytes()


@pytest.mark.parametrize('chunk', [1, 7, 4096, 65536])
@pytest.mark.parametrize('framing,body', [
    (b'Content-Length: 7\r\n', b'payload'), (b'', b'payload'),
    (b'Transfer-Encoding: chunked\r\n', b'3\r\npay\r\n4\r\nload\r\n0\r\n\r\n')])
def test_download_decodes_every_fragment_boundary(download_probe, tmp_path, chunk, framing, body):
    result, _, data = invoke(download_probe, tmp_path, b'HTTP/1.1 200 OK\r\n' + framing + b'\r\n' + body,
                             chunk=chunk)
    assert result == (0, 200, 7) and data == b'payload'


@pytest.mark.parametrize('status,diagnostic', [(401, 'HTTP 401'), (403, 'HTTP 403'),
    (404, 'not found'), (410, 'not found'), (500, 'server returned status 500')])
def test_error_status_never_publishes_peer_body(download_probe, tmp_path, status, diagnostic):
    wire = f'HTTP/1.1 {status} Error\r\nContent-Length: 6\r\n\r\nsecret'.encode()
    result, message, data = invoke(download_probe, tmp_path, wire)
    assert result == (-1, status, 0) and data == b''
    assert diagnostic in message


@pytest.mark.parametrize('framing,body,diagnostic,partial', [
    (b'Content-Length: 9', b'abc', 'body truncated', b'abc'),
    (b'Content-Length: -1', b'abc', 'invalid Content-Length', b''),
    (b'Content-Length: invalid', b'abc', 'invalid Content-Length', b''),
    (b'Content-Length: 999999999999999999999999', b'abc', 'invalid Content-Length', b''),
    (b'Transfer-Encoding: chunked', b'garbage\r\n', 'bad chunk size', b''),
    (b'Transfer-Encoding: chunked', b'-1\r\n', 'bad chunk size', b''),
    (b'Transfer-Encoding: chunked', b'5\r\nab', 'chunk truncated', b'ab')])
def test_malformed_or_incomplete_body_returns_exact_partial_count(download_probe, tmp_path,
                                                                  framing, body, diagnostic, partial):
    wire = b'HTTP/1.1 200 OK\r\n' + framing + b'\r\n\r\n' + body
    result, message, data = invoke(download_probe, tmp_path, wire, chunk=7)
    assert result == (-1, 200, len(partial)) and data == partial
    assert diagnostic in message


@pytest.mark.parametrize('wire', [b'', b'HTTP/1.1 200 OK\r\n', b'H' * 20000])
def test_truncated_or_excessive_headers_cannot_publish_data(download_probe, tmp_path, wire):
    result, message, data = invoke(download_probe, tmp_path, wire)
    assert result == (-1, 0, 0) and data == b''
    assert 'response headers too large/truncated' in message


@pytest.mark.parametrize('mode,message', [('read-error', 'fixture read failed'),
    ('send-error', 'fixture send failed'), ('write-error', 'local write:'),
    ('long-request', 'request too long')])
def test_transport_and_local_write_failure_remain_visible(download_probe, tmp_path, mode, message):
    result, diagnostic, data = invoke(download_probe, tmp_path,
        b'HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\npayload', mode)
    assert result[0] == -1 and result[2] == 0 and data == b''
    assert message in diagnostic


@pytest.mark.parametrize('status,expected,body', [(200, -1, b''), (206, 0, b'load')])
def test_resume_requires_partial_content(download_probe, tmp_path, status, expected, body):
    wire = f'HTTP/1.1 {status} OK\r\nContent-Length: 4\r\n\r\nload'.encode()
    result, _, data = invoke(download_probe, tmp_path, wire, resume=5)
    assert result == (expected, status, len(body)) and data == body
