"""Native CMS fixtures preserve ownership, host policy and real socket options."""
import ipaddress
import errno
import os
from types import SimpleNamespace

import pytest

from tools.ci import freebsd_pending_peer as peer


pytestmark = pytest.mark.xdist_group('lc-audit15o-cmswindows')


def _native(monkeypatch):
    monkeypatch.setattr(peer.sys, 'platform', 'freebsd15')
    monkeypatch.setattr(peer.os, 'geteuid', lambda: 0, raising=False)


@pytest.fixture
def commands(monkeypatch):
    _native(monkeypatch)
    calls = []
    token = 'brix-pending-' + 'aa' * 10
    monkeypatch.setattr(peer.secrets, 'token_hex', lambda size: 'aa' * size)
    monkeypatch.setattr(peer, '_unused_network', lambda: ipaddress.ip_network(
        '169.254.12.0/30'))  # net-literal-allow: isolated fixture model

    def run(*arguments):
        calls.append(arguments)
        if arguments[1:3] == ('epair', 'create'):
            return 'epair7a'
        if arguments[:3] == ('/usr/sbin/jail', '-i', '-c'):
            return '321'
        if arguments[0] == '/usr/sbin/jls':
            return f'name={token} host.hostname={token}'
        if arguments == ('/sbin/ifconfig', 'epair7a'):
            return f'epair7a:\n\tdescription: {token}\n'
        return ''

    monkeypatch.setattr(peer, '_run', run)
    return calls, run


def test_pending_peer_keeps_tcp_setting_inside_owned_jail(commands):
    calls, _ = commands
    with peer.pending_peer() as address:
        assert address == '169.254.12.2'  # net-literal-allow: fixture model
        assert ('/sbin/ifconfig', 'epair7a', 'destroy') not in calls
    settings = [call for call in calls if 'net.inet.tcp.blackhole=2' in call]
    assert settings == [('/usr/sbin/jexec', '321', '/sbin/sysctl',
                         'net.inet.tcp.blackhole=2')]
    assert calls[-3] == ('/usr/sbin/jail', '-r', '321')
    assert calls[-1] == ('/sbin/ifconfig', 'epair7a', 'destroy')


def test_child_failure_still_removes_owned_jail_and_interface(commands):
    calls, _ = commands
    with pytest.raises(ValueError, match='test child failed'):
        with peer.pending_peer():
            raise ValueError('test child failed')
    assert ('/usr/sbin/jail', '-r', '321') in calls
    assert calls[-1][-1] == 'destroy'


def test_partial_jail_setup_failure_still_destroys_owned_pair(commands, monkeypatch):
    calls, original = commands

    def fail(*arguments):
        if arguments[0] == '/usr/sbin/jail' and '-c' in arguments:
            raise OSError('injected jail refusal')
        return original(*arguments)

    monkeypatch.setattr(peer, '_run', fail)
    with pytest.raises(OSError, match='injected jail refusal'):
        with peer.pending_peer():
            pytest.fail('failed setup must not yield a peer')
    assert calls[-1] == ('/sbin/ifconfig', 'epair7a', 'destroy')


@pytest.mark.parametrize('host,uid', [('darwin', 0), ('freebsd15', 2101)])
def test_unprivileged_or_non_native_setup_creates_nothing(monkeypatch, host, uid):
    monkeypatch.setattr(peer.sys, 'platform', host)
    monkeypatch.setattr(peer.os, 'geteuid', lambda: uid, raising=False)
    monkeypatch.setattr(peer, '_run', lambda *args: pytest.fail('unexpected root command'))
    with pytest.raises(RuntimeError, match='root on native FreeBSD'):
        with peer.pending_peer():
            pytest.fail('unsupported setup must not yield')


@pytest.mark.parametrize('remove,identity', [
    (lambda: peer._destroy_interface('epair7a', 'ours'), 'description: foreign'),
    (lambda: peer._remove_jail(321, 'ours'), 'name=other host.hostname=other'),
])
def test_changed_resource_ownership_refuses_destructive_cleanup(monkeypatch, remove, identity):
    calls = []
    monkeypatch.setattr(peer, '_run', lambda *args: calls.append(args) or identity)
    with pytest.raises(RuntimeError, match='changed ownership'):
        remove()
    assert len(calls) == 1


def test_command_runs_with_its_own_non_root_account_groups(monkeypatch):
    recorded = []
    monkeypatch.setattr(peer.subprocess, 'run', lambda *args, **kw:
                        recorded.append((args, kw)) or SimpleNamespace(returncode=17))
    monkeypatch.setattr(peer.os, 'getgrouplist', lambda name, group: [2101, 2110], raising=False)
    account = SimpleNamespace(pw_uid=2101, pw_gid=2101, pw_dir='/home/test', pw_name='test')
    assert peer.run_as_user(account, ['pytest', 'tests'], 'peer') == 17
    options = recorded[0][1]
    assert (options['user'], options['group'], options['extra_groups']) == (2101, 2101, [2101, 2110])
    assert options['env']['BRIX_CMS_PENDING_HOST'] == 'peer'
    assert options['env']['HOME'] == '/home/test'


def test_root_child_is_refused_before_execution(monkeypatch):
    monkeypatch.setattr(peer.subprocess, 'run', lambda *args, **kw: pytest.fail('root child'))
    with pytest.raises(ValueError, match='non-root'):
        peer.run_as_user(SimpleNamespace(pw_uid=0), ['pytest'], 'peer')


def test_wheel_child_is_refused_before_execution(monkeypatch):
    monkeypatch.setattr(peer.os, 'getgrouplist', lambda *args: [2101, 0], raising=False)
    monkeypatch.setattr(peer.subprocess, 'run', lambda *args, **kw: pytest.fail('wheel child'))
    account = SimpleNamespace(pw_uid=2101, pw_gid=2101, pw_name='test')
    with pytest.raises(ValueError, match='wheel'):
        peer.run_as_user(account, ['pytest'], 'peer')


def test_network_lease_rejects_connected_subnet_overlap(monkeypatch):
    # net-literal-allow: overlap model for disconnected link-local /30 leases
    monkeypatch.setattr(peer, '_run', lambda *args:
                        'inet 169.254.0.1 netmask 0xfffffffc\n')
    choices = iter([0, 1])
    monkeypatch.setattr(peer.secrets, 'randbelow', lambda limit: next(choices))
    assert str(peer._unused_network()) == '169.254.0.4/30'


@pytest.mark.parametrize('address', ['', '127.0.0.1', '192.0.2.1', 'fe80::1'])  # net-literal-allow: reject non-isolated peer addresses
def test_cms_peer_refuses_missing_or_unconfined_address(monkeypatch, address):
    import test_audit15f_cms_node_legs as cms

    monkeypatch.setenv('BRIX_CMS_PENDING_HOST', address)
    monkeypatch.setattr(cms.socket, 'socket', lambda: pytest.fail('unconfined dial'))
    with pytest.raises(ValueError):
        cms.PendingPeer()


@pytest.mark.parametrize('result,ready,accepted', [
    (errno.EINPROGRESS, False, True), (errno.ECONNREFUSED, False, False),
    (errno.EINPROGRESS, True, False),
])
def test_cms_peer_independently_checks_pending_socket(monkeypatch, result, ready, accepted):
    import test_audit15f_cms_node_legs as cms

    class Probe:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def setblocking(self, enabled):
            assert enabled is False

        def connect_ex(self, address):
            assert ipaddress.ip_address(address[0]).is_link_local
            return result

    monkeypatch.setenv('BRIX_CMS_PENDING_HOST', '169.254.12.2')
    monkeypatch.setattr(cms.socket, 'socket', Probe)
    monkeypatch.setattr(cms.select, 'select', lambda *args: ([], [object()] if ready else [], []))
    if accepted:
        instance = cms.PendingPeer()
        assert instance.host == os.environ['BRIX_CMS_PENDING_HOST']
        instance.close()
    else:
        with pytest.raises(AssertionError):
            cms.PendingPeer()


@pytest.mark.parametrize('output,expected', [
    ('1234 5678 1 29000\n', [(':1234', ':5678', 'keepalive:29000')]),
    ('1234 5678 0 7200000\n', [(':1234', ':5678', 'bare')]),
    ('1234 5678 0 -1\n', [(':1234', ':5678', 'bare')]),
    ('1234 5678 1 -1\n', [(':1234', ':5678', 'keepalive:-1')]),
    ('', []),
])
def test_socket_observer_uses_option_flag_not_an_idle_timer(monkeypatch, output, expected):
    import _test_audit15f_helpers as helpers

    monkeypatch.setattr(helpers.subprocess, 'run', lambda *args, **kw:
                        SimpleNamespace(stdout=output))
    assert helpers._freebsd_established('observer') == expected


@pytest.mark.parametrize('output', ['0 5678 1 1', '1234 65536 1 1',
                                    '1234 5678 2 1', '1234 5678 1 -2147483649',
                                    '1234 5678 1 2147483648'])
def test_socket_observer_refuses_invalid_kernel_record(monkeypatch, output):
    import _test_audit15f_helpers as helpers

    monkeypatch.setattr(helpers.subprocess, 'run', lambda *args, **kw:
                        SimpleNamespace(stdout=output))
    with pytest.raises(AssertionError):
        helpers._freebsd_established('observer')


@pytest.mark.parametrize('available', [True, False])
def test_relay_observer_gate_checks_native_capability(monkeypatch, available):
    import test_audit16l_relay_flag_arms as relay

    monkeypatch.setattr(relay, 'socket_observation_available', lambda: available)
    if available:
        relay._needs_socket_observer()
    else:
        with pytest.raises(pytest.skip.Exception, match='native TCP socket observer'):
            relay._needs_socket_observer()


@pytest.mark.parametrize('reading', ['keepalive:29000', 'bare'])
def test_relay_preserves_native_observer_and_endpoint_filters(monkeypatch, reading):
    import test_audit16l_relay_flag_arms as relay

    calls = []
    observer = object()
    monkeypatch.setattr(relay, 'socket_timers', lambda **kwargs:
                        calls.append(kwargs) or reading)
    assert relay._pending_timer(local_port=1234, peer_port=5678, timeout=0,
                                observer=observer) == reading
    assert calls == [dict(local_port=1234, peer_port=5678, observer=observer)]


def test_relay_observation_failure_is_not_a_skip_or_bare_socket(monkeypatch):
    import test_audit16l_relay_flag_arms as relay

    def refuse(**kwargs):
        raise OSError(errno.EACCES, 'kernel observation refused')

    monkeypatch.setattr(relay, 'socket_timers', refuse)
    with pytest.raises(OSError, match='kernel observation refused'):
        relay._pending_timer(observer=object())
