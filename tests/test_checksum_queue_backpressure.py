"""Real checksum-post bodies must not fall back to blocking on queue overflow."""
from pathlib import Path
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
import struct
import zlib

import pytest

from csource_scan import function_body
from test_platform_linux_native import native_compile


@pytest.fixture(scope='module')
def checksum_admission_binary(native_compile):
    """Use actual SDK types and production bodies; inject allocator/queue edges."""
    root = Path(__file__).resolve().parents[1]
    directory = root / 'src/protocols/root/query'
    signatures = (
        ('checksum_qcksum.c', 'brix_qcksum_handle_try_async',
         'static ngx_int_t brix_qcksum_handle_try_async(brix_qcksum_req_t *rq, '
         'int idx, const char *resolved, ngx_flag_t *handled)'),
        ('checksum_qcksum_path.c', 'brix_qcksum_try_async',
         'static ngx_int_t brix_qcksum_try_async(brix_qcksum_req_t *rq, '
         'brix_vfs_file_t *fh, int fd, ngx_flag_t *handled)'),
    )
    driver = (root / 'tests/c/checksum_queue_backpressure_test.c').read_text()
    bodies = '\n'.join(signature + function_body((directory / source).read_text(), name)
                       for source, name, signature in signatures)
    policy = (root / 'src/fs/vfs/vfs_policy.c').read_text()
    definition = ('brix_vfs_mutation_policy_t '
                  'brix_vfs_policy_from_write_enable(ngx_flag_t allow_write)')
    worker = (directory / 'checksum_qcksum_async.c').read_text()
    ownership = worker[:worker.index('\nvoid\nbrix_cksum_aio_thread(')]
    code = driver + '\n' + definition + function_body(
        policy, 'brix_vfs_policy_from_write_enable') + '\n' + ownership + '\n' + bodies
    return native_compile('checksum-admission', code,
                          extra=['-fsanitize=address,undefined',
                                 '-fno-sanitize-recover=all', '-fno-omit-frame-pointer'],
                          include_dirs=[directory])


@pytest.mark.parametrize('variant', ['path', 'handle'])
@pytest.mark.parametrize('case', ['posted', 'posted-readonly', 'posted-unset',
                                 'busy', 'busy-readonly', 'repeat-busy', 'no-pool', 'oom'])
def test_checksum_post_contract(checksum_admission_binary, variant, case):
    """Check ownership, policy retention, backpressure, and explicit sync mode."""
    result = subprocess.run([str(checksum_admission_binary), variant, case],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('case', ['reuse', 'resize-oom', 'active', 'overflow'])
def test_checksum_task_storage_is_bounded_and_lifetime_safe(checksum_admission_binary, case):
    """A slot survives failed growth and cannot be reset under an active worker."""
    result = subprocess.run([str(checksum_admission_binary), 'slot', case],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


def test_checksum_scan_queue_cannot_fall_through_to_event_loop():
    """The scan's busy arm returns retry before its explicit no-pool sync arm."""
    root = Path(__file__).resolve().parents[1]
    source = root / 'src/protocols/root/query/checksum_ckscan_dispatch.c'
    body = function_body(source.read_text(), 'brix_query_ckscan')
    queued = body.index('brix_aio_post_task(')
    retry = body.index('return brix_send_wait(ctx, c, 1);', queued)
    synchronous = body.rindex('return brix_ckscan_sync(')
    assert queued < retry < synchronous
    assert 'brix_query_checksum_task(' in body and 'using sync' not in body


@pytest.fixture
def gated_checksum_plugin(tmp_path):
    """Hold one trusted test-plugin worker, with an unconditional ten-second cap."""
    from test_release20_checksum_plugin import COMPAT, CONTRIB

    ready, release = tmp_path / 'entered', tmp_path / 'release'
    helper = '''
static int brix_test_checksum_gate(void)
{
    const struct timespec pause = {0, 5000000};
    FILE *marker = fopen(READY_PATH, "w");
    if (marker == NULL) { return -1; }
    if (fclose(marker) != 0) { return -1; }
    for (unsigned attempt = 0; attempt < 2000; attempt++) {
        if (access(RELEASE_PATH, F_OK) == 0) { return 0; }
        nanosleep(&pause, NULL);
    }
    return -1;
}
'''.replace('READY_PATH', json.dumps(str(ready))).replace(
        'RELEASE_PATH', json.dumps(str(release)))
    source = CONTRIB.read_text()
    anchor = 'static int\nfnv1a64_update('
    assert source.count(anchor) == 1
    source = source.replace(anchor, helper + '\n' + anchor, 1)
    anchor = '    for (i = 0; i < n; i++) {'
    assert source.count(anchor) == 1
    source = source.replace(anchor, '    if (n != 0 && brix_test_checksum_gate() != 0) '
                            '{ return -1; }\n' + anchor, 1)
    code, plugin = tmp_path / 'gated.c', tmp_path / 'gated.so'
    code.write_text('#include <stdio.h>\n#include <time.h>\n#include <unistd.h>\n' + source)
    result = subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-iquote', str(COMPAT),
                             '-o', str(plugin), str(code)], capture_output=True,
                            text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    plugin.chmod(0o644)
    return plugin, ready, release


def _wait_for_gate(ready, future):
    """Wait for actual worker entry, not a timing guess about queue admission."""
    deadline = time.monotonic() + 3
    while not ready.exists() and time.monotonic() < deadline:
        assert not future.done(), future.result() if future.done() else 'worker exited'
        time.sleep(0.005)
    assert ready.exists(), 'checksum worker did not enter the bounded gate'


def _checksum_request(sock, stream, subcode=3, handle=b'\0' * 4, path=b''):
    """Use the suite's wire framing and preserve retry/error status exactly."""
    import _test_session_bind_helpers as wire

    body = struct.pack('>H', subcode) + b'\0' * 2 + handle + b'\0' * 8
    return wire._send_req(sock, stream, 3001, body=body, payload=path)


def _assert_busy_checksum_contract(sock, stream, handle, pending):
    """Observe real retries and an independent health probe before release."""
    import _test_session_bind_helpers as wire

    forms = ({'path': b'/busy.bin'}, {'handle': handle},
             {'subcode': 6, 'path': b'adler32:/busy.bin'})
    for request in forms:
        status, response = _checksum_request(sock, stream, **request)
        assert status == wire.kXR_wait, (request, status, response)
        assert struct.unpack('>I', response[:4])[0] == 1
    status, response = _checksum_request(sock, stream, handle=b'\xff' * 4)
    assert status == wire.kXR_error and struct.unpack('>I', response[:4])[0] == 3004
    status, response = _checksum_request(sock, stream, subcode=7, path=b'chksum')
    assert status == wire.kXR_ok and b'fnv1a64' in response
    assert not pending.done(), 'health probe ran only after releasing the worker'


@pytest.mark.uses_lifecycle_harness
@pytest.mark.xdist_group('lc-r20-cks-plugin')
def test_live_busy_checksum_forms_retry_without_stalling_loop(
    lifecycle, gated_checksum_plugin, tmp_path,
):
    """Exercise path/handle/scan overflow, live health, refusal and later reuse."""
    import _test_session_bind_helpers as wire
    from test_release20_checksum_plugin import (
        REPO, TEMPLATE, _register, _spec, fnv1a64,
    )
    from settings import BIND_HOST

    plugin, ready, release = gated_checksum_plugin
    template = (REPO / 'tests/configs' / TEMPLATE).read_text()
    pool = 'thread_pool default threads=2 max_queue=256;'
    assert template.count(pool) == 1
    config = tmp_path / 'checksum-busy.conf'
    config.write_text(template.replace(pool, 'thread_pool default threads=1 max_queue=0;'))
    spec = _spec(plugin=_register(plugin), server='brix_checksum_default fnv1a64;')
    endpoint = lifecycle.start(replace(spec, template=str(config)))
    payload = b'bounded checksum queue regression\n'
    Path(endpoint.data_root, 'busy.bin').write_bytes(payload)
    wire.ANON_HOST = BIND_HOST
    active, _session, stream = wire._establish_primary(endpoint.port)
    retry, _session, retry_stream = wire._establish_primary(endpoint.port)
    active.settimeout(5)
    retry.settimeout(2)
    handle = wire._open_read(retry, retry_stream, '/busy.bin')
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(_checksum_request, active, stream, path=b'/busy.bin')
            try:
                _wait_for_gate(ready, pending)
                _assert_busy_checksum_contract(retry, retry_stream, handle, pending)
            finally:
                release.touch()
            expected = b'fnv1a64 ' + fnv1a64(payload).encode() + b'\0'
            assert pending.result(timeout=3) == (wire.kXR_ok, expected)
            assert _checksum_request(retry, retry_stream, handle=handle) == (wire.kXR_ok, expected)
    finally:
        release.touch()
        retry.close()
        active.close()


def _xattr_snapshot(path):
    """Read every attribute, including the independent preservation control."""
    return {name: os.getxattr(path, name) for name in os.listxattr(path)}


def _assert_checksum_cache_policy(path, before, writable, expected):
    """Verify cache persistence or exact metadata preservation after completion."""
    after = _xattr_snapshot(path)
    assert after['user.brix_policy_control'] == b'retained'
    if writable:
        assert after['user.XrdCks.adler32'].split()[0] == expected.split()[1].rstrip(b'\0')
    else:
        assert after == before, 'read-only checksum request mutated export metadata'


@pytest.mark.uses_lifecycle_harness
@pytest.mark.xdist_group('lc-r20-cks-plugin')
@pytest.mark.parametrize('writable', [True, False])
@pytest.mark.parametrize('variant', ['path', 'handle'])
def test_live_async_checksum_cache_retains_export_policy(lifecycle, writable, variant):
    """A writable export caches the digest; a read-only export remains unchanged."""
    import _test_session_bind_helpers as wire
    from test_release20_checksum_plugin import _spec
    from settings import BIND_HOST

    enabled = 'on' if writable else 'off'
    endpoint = lifecycle.start(_spec(server=f'brix_allow_write {enabled};'))
    payload = b'export checksum policy must survive offload\n'
    path = Path(endpoint.data_root, 'policy.bin')
    path.write_bytes(payload)
    os.setxattr(path, 'user.brix_policy_control', b'retained')
    before = _xattr_snapshot(path)
    wire.ANON_HOST = BIND_HOST
    sock, _session, stream = wire._establish_primary(endpoint.port)
    sock.settimeout(3)
    try:
        request = {'path': b'/policy.bin'}
        if variant == 'handle':
            request = {'handle': wire._open_read(sock, stream, '/policy.bin')}
        status, response = _checksum_request(sock, stream, **request)
        expected = f'adler32 {zlib.adler32(payload):08x}'.encode() + b'\0'
        assert (status, response) == (wire.kXR_ok, expected)
        assert path.read_bytes() == payload
        _assert_checksum_cache_policy(path, before, writable, expected)
    finally:
        sock.close()
