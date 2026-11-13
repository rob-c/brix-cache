"""Real directory AIO jobs close their descriptor and preserve queued output."""

import struct
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def dirlist_aio(server_native_compile, tmp_path_factory):
    names = ('brix_queue_response_base', 'brix_release_read_buffer', 'brix_send_error', 'brix_aio_resume')
    binary = server_native_compile('dirlist-aio', 'tests/c/dirlist_aio_native_test.c',
                                  ['-Wl,--wrap=' + name for name in names])
    root = tmp_path_factory.mktemp('dirlist-aio')
    (root / 'file.txt').write_bytes(b'payload\n')
    (root / 'subdir').mkdir()
    (root / 'unsafe\nname').write_bytes(b'not a wire entry')
    def run(mode='normal', algorithm='names', empty=False):
        source = root / 'subdir' if empty else root
        result = subprocess.run([str(binary), mode, str(source), algorithm],
                                capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stdout + result.stderr
        lines = result.stdout.splitlines()
        wire = bytes.fromhex(lines[0][5:]) if lines[0].startswith('wire=') else b''
        return dict(item.split('=', 1) for item in lines[-1].split()), wire
    return run


@pytest.mark.parametrize('algorithm', ['names', 'stat', 'adler32', 'sha256'])
@pytest.mark.parametrize('mode', ['normal', 'queued'])
def test_real_directory_names_stats_and_checksums_keep_response_ownership(dirlist_aio, algorithm, mode):
    result, wire = dirlist_aio(mode, algorithm)
    assert result['queues'] == result['resumes'] == '1'
    assert result['error'] == result['errno'] == result['null'] == '0'
    assert result['released'] == str(int(mode == 'normal'))
    assert b'file.txt' in wire and b'subdir' in wire
    assert b'unsafe' not in wire
    assert struct.unpack('!2sHI', wire[:8]) == (b'\x42\x19', 0, len(wire) - 8)


@pytest.mark.parametrize('algorithm', ['names', 'stat', 'sha256'])
def test_empty_directory_still_queues_terminal_header(dirlist_aio, algorithm):
    result, wire = dirlist_aio(algorithm=algorithm, empty=True)
    body = b'' if algorithm == 'names' else b'.\n0 0 0 0\0'
    assert wire == struct.pack('!2sHI', b'\x42\x19', 0, len(body)) + body
    assert result['queues'] == result['resumes'] == result['released'] == '1'


@pytest.mark.parametrize('mode,code', [('bad-fd', 3000), ('overflow', 3008),
                                     ('fallback-message', 3010), ('custom-message', 3011)])
def test_worker_error_maps_to_protocol_and_releases_buffer(dirlist_aio, mode, code):
    result, wire = dirlist_aio(mode)
    assert wire == b'' and result['queues'] == '0'
    assert result['error'] == str(code)
    assert result['resumes'] == result['released'] == result['null'] == '1'


def test_destroyed_connection_does_not_resume_or_queue(dirlist_aio):
    result, wire = dirlist_aio('destroyed')
    assert wire == b''
    assert result['queues'] == result['resumes'] == result['released'] == result['error'] == '0'
