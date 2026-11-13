"""HTTP TPC push preserves overwrite semantics and closes registry lifecycles."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def push(server_native_compile):
    boundaries = ['webdav_resolve_stat', 'webdav_tpc_authorize',
        'webdav_tpc_post_thread_task', 'webdav_tpc_run_curl_push',
        'brix_tpc_registry_add', 'brix_tpc_registry_update', 'brix_tpc_registry_remove',
        'ngx_http_send_header', 'ngx_http_send_special']
    return server_native_compile('webdav-push', 'tests/c/webdav_push_native_test.c',
                                 [f'-Wl,--wrap={name}' for name in boundaries])


def invoke(binary, mode='normal', destination='https://destination.invalid/object',
           overwrite='absent', credential='absent'):
    result = subprocess.run([str(binary), mode, destination, overwrite, credential],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return {key: int(value) for key, value in
            (line.split('=', 1) for line in result.stdout.splitlines())}


@pytest.mark.parametrize('overwrite', ['absent', 'F', 'T'])
@pytest.mark.parametrize('credential', ['absent', 'none'])
@pytest.mark.parametrize('scheme', ['https', 'HTTPS'])
def test_sync_push_publishes_created_after_one_complete_transfer(push, overwrite, credential, scheme):
    result = invoke(push, destination=f'{scheme}://destination.invalid/object',
                    overwrite=overwrite, credential=credential)
    assert result == dict(rc=0, stats=1, auth=1, posts=1, adds=1, runs=1,
                         updates=1, removes=1, responses=1)


@pytest.mark.parametrize('mode,rc,counts', [
    ('missing', 404, (1, 0, 0, 0, 0, 0)),
    ('directory', 409, (1, 0, 0, 0, 0, 0)),
    ('denied', 403, (1, 1, 0, 0, 0, 0)),
    ('async', -4, (1, 1, 1, 0, 0, 0)),
    ('post-error', 500, (1, 1, 1, 0, 0, 0)),
    ('post-full', 503, (1, 1, 1, 0, 0, 0)),
    ('registry-full', 503, (1, 1, 1, 1, 0, 0)),
    ('transfer-error', 502, (1, 1, 1, 1, 1, 1)),
])
def test_terminal_outcomes_do_not_send_success_or_repeat_io(push, mode, rc, counts):
    result = invoke(push, mode)
    assert result['rc'] == rc and result['responses'] == 0
    assert tuple(result[key] for key in ('stats', 'auth', 'posts', 'adds', 'runs', 'removes')) == counts
    assert result['updates'] == result['removes']


@pytest.mark.parametrize('destination', ['', 'http://destination.invalid/x',
    'file:///etc/passwd', 'https://destination.invalid/x\r\nInjected: yes',
    'https://destination.invalid/\x7f'])
def test_invalid_destination_is_refused_before_local_access(push, destination):
    result = invoke(push, destination=destination)
    assert result['rc'] == 400
    assert not any(value for key, value in result.items() if key != 'rc')


@pytest.mark.parametrize('mode,credential', [('header-injection', 'none'), ('normal', 'unknown')])
def test_bad_forwarded_headers_and_credential_modes_stop_before_access(push, mode, credential):
    result = invoke(push, mode, credential=credential)
    assert result['rc'] == 400 and result['stats'] == 0 and result['posts'] == 0
