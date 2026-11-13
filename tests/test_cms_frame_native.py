"""CMS replies cannot target stale clients or retarget to untrusted managers."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def cms_frame(server_native_compile):
    wrappers = ('ngx_pcalloc', 'ngx_pnalloc', 'brix_pending_lookup', 'brix_pending_unlock',
        'brix_pending_remove', 'brix_cms_answer_selected', 'brix_schedule_read_resume',
        'ngx_brix_cms_disconnect', 'ngx_brix_cms_schedule', 'ngx_brix_cms_schedule_retry',
        'cms_node_exec_forward', 'cms_super_fan_down', 'cms_node_exec_prepare')
    binary = server_native_compile('cms-frame', 'tests/c/cms_frame_native_test.c',
                                  ['-Wl,--wrap=' + name for name in wrappers])
    def run(operation, mode='normal', host='192.0.2.8', argument=0):
        result = subprocess.run([str(binary), operation, mode, host, str(argument)],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        return {key: int(value) for key, value in
                (item.split('=') for item in result.stdout.split())}
    return run


@pytest.mark.parametrize('mode', ['normal', 'linear'])
def test_waiting_client_replies_restore_original_stream_and_resume(cms_frame, mode):
    result = cms_frame('wake', mode)
    assert result['unlocks'] == result['removes'] == result['answers'] == result['resumes'] == 1
    assert result['result'] == 0


@pytest.mark.parametrize('mode', ['missing', 'negative', 'absent-fd', 'linear-miss',
    'recycled', 'no-session', 'no-context', 'wrong-state'])
def test_stale_pending_client_cannot_receive_a_reply(cms_frame, mode):
    result = cms_frame('wake', mode)
    assert result['answers'] == result['resumes'] == 0
    assert result['removes'] == int(mode != 'missing')


@pytest.mark.parametrize('host', ['bad\nhost', 'https://example.invalid', '', 'bad host'])
def test_invalid_redirect_host_never_reaches_client(cms_frame, host):
    result = cms_frame('wake', host=host)
    assert result['removes'] == 1 and result['answers'] == result['resumes'] == 0


def test_failed_selected_answer_is_not_resumed(cms_frame):
    result = cms_frame('wake', 'answer-fail')
    assert result['answers'] == 1 and result['resumes'] == 0 and result['result'] == -1


@pytest.mark.parametrize('host', ['192.0.2.8', '2001:db8::8'])
@pytest.mark.parametrize('mode', ['normal', 'already'])
def test_login_retarget_preserves_configured_origin(cms_frame, host, mode):
    result = cms_frame('retarget', mode, host, 2)
    assert result['changed'] == result['disconnects'] == result['schedules'] == 1
    assert result['depth'] == 3


@pytest.mark.parametrize('mode', ['calloc', 'nalloc', 'short', 'truncated'])
def test_failed_or_incomplete_retarget_keeps_current_manager(cms_frame, mode):
    result = cms_frame('retarget', mode)
    assert result['changed'] == result['disconnects'] == result['schedules'] == 0


@pytest.mark.parametrize('host,depth', [('manager.fixture.invalid', 0), ('bad\nhost', 0),
                                      ('[2001:db8::8]', 0),
                                      ('192.0.2.8', 4)])
def test_retarget_requires_literal_address_and_bounded_chain(cms_frame, host, depth):
    result = cms_frame('retarget', host=host, argument=depth)
    assert result['changed'] == result['disconnects'] == 0 and result['depth'] == depth


@pytest.mark.parametrize('role,forwards,fans', [(0, 1, 0), (2, 0, 0),
                                            (3, 0, 1), (4, 0, 0), (5, 0, 0)])
def test_namespace_mutation_dispatch_obeys_parent_role(cms_frame, role, forwards, fans):
    result = cms_frame('forward', argument=role)
    assert result['forwards'] == forwards and result['fans'] == fans


@pytest.mark.parametrize('modifier,paused', [(0, 1), (4, 0), (8, 1), (12, 1)])
def test_status_suspend_wins_over_resume(cms_frame, modifier, paused):
    assert cms_frame('status', argument=modifier)['suspended'] == paused


@pytest.mark.parametrize('operation,key', [('prepare', 'prepares'), ('disconnect', 'disconnects')])
def test_remaining_lifecycle_dispatch(cms_frame, operation, key):
    assert cms_frame(operation)[key] == 1


def test_unknown_opcode_is_ignored(cms_frame):
    result = cms_frame('unknown')
    assert result['result'] == result['answers'] == result['forwards'] == result['disconnects'] == 0
