"""Real namespace fault controls with normal exit and observable cleanup."""

from contextlib import contextmanager
import os
import select
import subprocess
import time

import pytest

from test_fault_proxy_control_unit import control_unit  # noqa: F401
from test_fault_proxy_privileged import netns, needs_root, _nsrun  # noqa: F401

pytestmark = [needs_root, pytest.mark.timeout(120)]


def command(process, text):
    """Read exactly one bounded reply from the finite driver's flushed pipe."""
    process.stdin.write((text + '\n').encode())
    process.stdin.flush()
    response = bytearray()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        ready, _, _ = select.select([process.stdout], [], [], 0.1)
        if not ready:
            continue
        chunk = os.read(process.stdout.fileno(), 16384)
        assert chunk, f'control driver exited: {process.poll()}'
        response.extend(chunk)
        if response.endswith(b'\0'):
            return response[:-1].decode()
    pytest.fail(f'control reply timed out: {text}')


@contextmanager
def armed(binary, namespace, iface='lo'):
    """Own one finite driver; EOF triggers production teardown and gcov flush."""
    process = subprocess.Popen(
        ['ip', 'netns', 'exec', namespace, str(binary),
         '--privileged-fixture', iface, '--stdin'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert 'priv on iface=' in command(process, 'priv status')
        yield process
    finally:
        process.stdin.close()
        try:
            status = process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise
        error = process.stderr.read().decode()
        process.stdout.close()
        process.stderr.close()
        assert status == 0, error


def qdisc(namespace):
    """Read the actual isolated interface's installed queuing discipline."""
    return _nsrun(namespace, 'tc', 'qdisc', 'show', 'dev', 'lo', check=True).stdout


def rules(namespace):
    """Read the actual namespace ruleset, including absence after cleanup."""
    return _nsrun(namespace, 'nft', 'list', 'ruleset', check=True).stdout


def install_combined_faults(process):
    """Arm independent real kernel effects before exercising their cleanup."""
    for text in ['priv mtu 600', 'priv netem delay 1', 'priv cut drop both']:
        assert command(process, text) == 'ok\n'


@pytest.mark.parametrize('setting,expected', [
    ('delay 10 2 20 normal', 'delay 10ms'),
    ('loss 1 10', 'loss 1%'), ('corrupt 1 10', 'corrupt 1%'),
    ('duplicate 1 10', 'duplicate 1%'), ('reorder 5 10', 'reorder 5%'),
    ('rate 1mbit', 'rate 1Mbit'), ('limit 123', 'limit 123'),
    ('loss-gemodel 1 10 20 0.1', 'loss gemodel'),
])
def test_netem_composition_and_independent_clear(control_unit, netns,
                                                setting, expected):
    """Each real qdisc feature composes with delay and can be removed alone."""
    with armed(control_unit, netns) as process:
        assert command(process, 'priv netem delay 10') == 'ok\n'
        assert command(process, f'priv netem {setting}') == 'ok\n'
        assert expected in qdisc(netns)
        assert 'netem[lo]:' in command(process, 'priv netem show')
        verb = setting.split()[0]
        assert command(process, f'priv netem {verb} off') == 'ok\n'
        assert command(process, 'priv netem clear') == 'ok\n'
        assert 'netem' not in qdisc(netns)
    assert 'netem' not in qdisc(netns)


@pytest.mark.parametrize('mode,verdict', [
    ('rst', 'reject with tcp reset'), ('drop', 'drop'),
    ('icmp-admin', 'admin-prohibited'), ('icmp-host', 'host-unreachable'),
    # nft renders its default ICMP port-unreachable verdict as bare "reject".
    ('icmp-net', 'no-route'), ('icmp-port', ' reject\n'),
])
@pytest.mark.parametrize('direction', ['up', 'down', 'both'])
def test_cut_rules_are_scoped_to_proxy_ports(control_unit, netns, mode,
                                            verdict, direction):
    """Every verdict affects only its selected side's known proxy ports."""
    with armed(control_unit, netns) as process:
        assert command(process, f'priv cut {mode} {direction}') == 'ok\n'
        table = rules(netns)
        assert verdict in table
        assert ('dport 24001' in table) == (direction != 'up')
        assert ('sport { 24002, 24003 }' in table) == (direction != 'down')
        assert command(process, 'priv uncut') == 'ok\n'
        assert 'brix_fault_proxy' not in rules(netns)
    assert 'brix_fault_proxy' not in rules(netns)


@pytest.mark.parametrize('cleanup', ['priv clear', 'eof'])
def test_all_kernel_state_is_restored(control_unit, netns, cleanup):
    """Explicit clear and normal exit both restore MTU, qdisc and nft state."""
    original = _nsrun(netns, 'cat', '/sys/class/net/lo/mtu', check=True).stdout
    with armed(control_unit, netns) as process:
        install_combined_faults(process)
        assert _nsrun(netns, 'cat', '/sys/class/net/lo/mtu').stdout == '600\n'
        assert 'nft=yes' in command(process, 'priv status')
        if cleanup != 'eof':
            assert command(process, cleanup) == 'ok\n'
            assert 'nft=no' in command(process, 'priv status')
    assert _nsrun(netns, 'cat', '/sys/class/net/lo/mtu').stdout == original
    assert 'brix_fault_proxy' not in rules(netns)
    assert 'netem' not in qdisc(netns)


@pytest.mark.parametrize('text', [
    'priv netem delay -1', 'priv netem loss 101', 'priv netem corrupt -1',
    'priv netem duplicate nope', 'priv netem loss-gemodel 1 bad',
    'priv netem rate 1mbit;id', 'priv netem limit -1', 'priv netem unknown',
    'priv cut', 'priv cut unknown', 'priv mtu', 'priv mtu 67',
    'priv mtu 65536', 'priv unknown', 'priv strip-opt wscale',
])
def test_rejected_operands_preserve_kernel_state(control_unit, netns, text):
    """Malformed commands cannot install or change privileged kernel state."""
    with armed(control_unit, netns) as process:
        before = (qdisc(netns), rules(netns), command(process, 'priv status'))
        assert command(process, text).startswith('err:'), text
        assert (qdisc(netns), rules(netns), command(process, 'priv status')) == before


@pytest.mark.parametrize('iface', ['missing_brix', 'lo;id', 'x' * 80])
def test_invalid_interface_cannot_arm(control_unit, netns, iface):
    """Nonexistent, hostile and oversized names fail before any mutation."""
    result = _nsrun(netns, str(control_unit), '--privileged-fixture', iface,
                    'priv cut drop both')
    assert result.returncode == 3
    assert 'invalid or nonexistent' in result.stderr
    assert 'brix_fault_proxy' not in rules(netns)


def test_missing_interface_refuses_interface_mutations(control_unit, netns):
    """Arming nft alone cannot implicitly select a host network interface."""
    with armed(control_unit, netns, iface='') as process:
        for text in ['priv netem delay 10', 'priv mtu 600']:
            assert 'no --priv-iface' in command(process, text)
    assert 'netem' not in qdisc(netns)


@pytest.mark.parametrize('text,expected', [
    ('priv frag-drop', 'frag-off'), ('priv first-not-syn-drop', 'ct state invalid'),
])
def test_special_verdict_is_removed_on_exit(control_unit, netns, text, expected):
    """Special packet verdicts install real rules and normal exit removes them."""
    with armed(control_unit, netns) as process:
        assert command(process, text) == 'ok\n'
        assert expected in rules(netns)
    assert 'brix_fault_proxy' not in rules(netns)
