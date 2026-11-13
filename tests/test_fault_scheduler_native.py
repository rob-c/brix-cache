"""Fault commands preserve direction, reject bad input, and retire owned jobs."""

from pathlib import Path
import subprocess
import sys

import pytest

from brix_suite.client_build import client_make, client_run
from test_xrd_dispatch_native import private_link_command

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def fault_scheduler(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('fault-scheduler')
    binary = output / 'brix-fault-proxy'
    plan = client_make(root / 'client', '-n', 'brix-fault-proxy', f'BINDIR={output}',
                       capture_output=True, text=True, timeout=120)
    assert plan.returncode == 0, plan.stdout + plan.stderr
    command = private_link_command(plan.stdout.replace('\\\n', ' '), binary)
    command += ['-Dmain=brix_fault_unused_main', str(root / 'tests/c/fault_scheduler_native_test.c')]
    command += ['-Wl,--wrap=' + symbol for symbol in
                ('pthread_create', 'pthread_detach', 'usleep', 'rand_r', 'calloc', 'free')]
    # This target compiles its production sources at link time. Match the
    # coverage inventory so optimization cannot erase otherwise executable lines.
    if '--coverage' in command:
        command.append('-O0')
    result = client_run(root / 'client', command, cwd=root / 'client',
                        capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr

    def invoke(*arguments):
        result = subprocess.run([str(binary), *arguments], capture_output=True,
                                text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        return dict((key, int(value)) for key, value in
                    (line.split('=', 1) for line in result.stdout.splitlines()))
    return invoke


@pytest.mark.parametrize('job', ['heal', 'flap', 'ramp', 'chaos'])
@pytest.mark.parametrize('mode', ['create-error', 'superseded'])
def test_failed_or_superseded_job_cannot_mutate_state(fault_scheduler, job, mode):
    fault_scheduler('schedule', job, mode, '1')


@pytest.mark.parametrize('job', ['heal', 'flap', 'ramp'])
@pytest.mark.parametrize('value', ['0', '1'])
@pytest.mark.parametrize('mode', ['normal', 'cancel'])
def test_scheduler_completes_or_cancels_and_releases_ownership(fault_scheduler, job, value, mode):
    fault_scheduler('schedule', job, mode, value)


def test_ramp_allocation_failure_starts_no_job(fault_scheduler):
    fault_scheduler('schedule', 'ramp', 'allocation-error', '1')


@pytest.mark.parametrize('choice', range(8))
@pytest.mark.parametrize('value', ['0', '77'])
def test_chaos_selection_applies_exact_bounded_fault(fault_scheduler, choice, value):
    fault_scheduler('schedule', 'chaos', str(choice), value)


def test_chaos_cancellation_at_timer_boundary_emits_no_fault(fault_scheduler):
    fault_scheduler('schedule', 'chaos', 'cancel', '77')


@pytest.mark.parametrize('direction', ['up', 'down', 'both'])
@pytest.mark.parametrize('command,fields', [
    ('cl-te 9', {'add_cl': 1, 'add_te': 1, 'cl_val': 9}),
    ('te-cl 5', {'add_cl': 1, 'add_te': 1, 'cl_val': 5}),
    ('dup-cl 7', {'dup_cl': 1, 'dup_cl_val': 7}),
    ('obfuscate-te 2', {'obfuscate_te': 2}),
    ('obfuscate-te 0', {'obfuscate_te': 1}),
    ('obfuscate-te 4', {'obfuscate_te': 1}),
    ('naked-lf', {'naked_lf': 1}),
    ('inject-header X-Test hex:0041ff', {'inj_name_len': 6, 'inj_val_len': 3}),
    ('append hex:0041ff', {'append_len': 3}),
    ('header-hold 42 0 partial', {'hold_thresh': 42, 'hold_ms': 0, 'hold_partial': 1}),
    ('header-hold 24 12 whole', {'hold_thresh': 24, 'hold_ms': 12, 'hold_partial': 0}),
    ('body-hold 42 11 partial', {'body_hold_thresh': 42, 'body_hold_ms': 11, 'body_hold_partial': 1}),
    ('body-hold 24 0 whole', {'body_hold_thresh': 24, 'body_hold_ms': 0, 'body_hold_partial': 0}),
    ('strip-header Range', {'strip_len': 5}),
])
def test_http_commands_set_only_selected_direction(fault_scheduler, direction, command, fields):
    state = fault_scheduler('command', f'http {command} {direction}')
    for side in ['up', 'down']:
        for field, expected in fields.items():
            assert state[f'{side}.http.{field}'] == (expected if direction in [side, 'both'] else 0)


@pytest.mark.parametrize('command', ['inject-header', 'inject-header X',
    'inject-header X hex:gg', 'append hex:', 'append hex:0',
    'header-hold', 'header-hold 1', 'header-hold 0 1', 'header-hold 1 -1',
    'body-hold', 'body-hold 1', 'body-hold -1 1', 'body-hold 1 -1',
    'strip-header', 'unknown 1'])
def test_bad_http_command_cannot_arm_a_hold_or_payload(fault_scheduler, command):
    state = fault_scheduler('command', '!http ' + command)
    for side in ['up', 'down']:
        for field in ['hold_thresh', 'body_hold_thresh', 'append_len', 'inj_val_len', 'strip_len']:
            assert state[f'{side}.http.{field}'] == 0


@pytest.mark.parametrize('direction', ['up', 'down', 'both'])
@pytest.mark.parametrize('command,fields', [
    ('fragment 12', {'frag_max': (12, 0)}),
    ('set-type 21', {'set_type': (21, -1)}),
    ('drop-type 22', {'drop_type': (22, -1)}),
    ('inflate 40', {'inflate_len': (40, 0)}),
    ('flip', {'flip_payload': (1, 0)}),
    ('set-version 3 4', {'set_ver_major': (3, -1), 'set_ver_minor': (4, -1)}),
    ('alert 2 40', {'alert_level': (2, -1), 'alert_desc': (40, 0)}),
])
def test_tls_commands_preserve_opposite_direction(fault_scheduler, direction, command, fields):
    state = fault_scheduler('command', f'tls {command} {direction}')
    for side in ['up', 'down']:
        for field, (expected, default) in fields.items():
            assert state[f'{side}.tls.{field}'] == (expected if direction in [side, 'both'] else default)


@pytest.mark.parametrize('reset', ['http off', 'http', 'clear'])
def test_http_reset_removes_all_previously_armed_faults(fault_scheduler, reset):
    state = fault_scheduler('command', 'http append hex:0041 both',
                           'http header-hold 20 12 partial both', reset)
    assert all(value == 0 for key, value in state.items() if '.http.' in key)


@pytest.mark.parametrize('reset', ['tls off', 'tls', 'clear'])
def test_tls_reset_installs_disabled_sentinels(fault_scheduler, reset):
    state = fault_scheduler('command', 'tls alert 2 40 both', 'tls flip both', reset)
    baseline = fault_scheduler('command', 'clear')
    assert state == baseline


@pytest.mark.parametrize('direction', ['up', 'down', 'both'])
@pytest.mark.parametrize('once', [False, True])
def test_trigger_keeps_pattern_and_once_semantics(fault_scheduler, direction, once):
    verb = 'trigger-once' if once else 'trigger'
    state = fault_scheduler('command', f'{verb} {direction} hex:0041ff latency 7')
    for side in ['up', 'down']:
        assert state[f'{side}.trigger.len'] == (3 if direction in [side, 'both'] else 0)
        assert state[f'{side}.trigger.once'] == (int(once) if direction in [side, 'both'] else 0)


@pytest.mark.parametrize('op,number', [('set', 0), ('add', 1), ('sub', 2)])
@pytest.mark.parametrize('direction', ['up', 'down', 'both'])
def test_length_mangler_arms_exact_operation_and_offset(fault_scheduler, op, number, direction):
    state = fault_scheduler('command', f'mangle-len {direction} 19 {op} 11')
    for side in ['up', 'down']:
        active = direction in [side, 'both']
        for field, expected in [('active', 1), ('op', number), ('offset', 19), ('val', 11)]:
            assert state[f'{side}.mangle.{field}'] == (expected if active else 0)


@pytest.mark.parametrize('bad', ['trigger', 'trigger up', 'trigger up hex:',
    'trigger up hex:gg clear', 'trigger up hex: clear', 'mangle-len',
    'mangle-len up 1', 'mangle-len up 1 multiply 2', 'ramp latency 1', 'tls unknown'])
def test_invalid_attack_command_preserves_existing_configuration(fault_scheduler, bad):
    configured = ['trigger up hex:4142 latency 5', 'mangle-len both 4 add 9']
    before = fault_scheduler('command', *configured)
    after = fault_scheduler('command', *configured, '!' + bad)
    assert after == before


def test_trigger_and_mangle_off_disable_both_directions(fault_scheduler):
    state = fault_scheduler('command', 'trigger-once both hex:4142 clear',
                           'mangle-len both 4 add 9', 'trigger off', 'mangle-len off')
    for side in ['up', 'down']:
        assert state[f'{side}.trigger.len'] == state[f'{side}.mangle.active'] == 0
