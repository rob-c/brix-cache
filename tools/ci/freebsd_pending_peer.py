#!/usr/bin/env python3
"""Root-owned, disposable VNET peer for native pending-connect tests.

Only the new jail drops SYNs to closed ports. No bridge, default route,
host firewall, host TCP sysctl or persistent configuration is changed.
Run this wrapper as root; its command runs as the specified non-root user.
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import re
import secrets
import subprocess
import sys
from contextlib import contextmanager


def _run(*arguments):
    return subprocess.run(arguments, check=True, capture_output=True, text=True,
                          timeout=15).stdout.strip()


def _unused_network():
    """Refuse overlap with any existing interface's connected IPv4 network."""
    interfaces = _run('/sbin/ifconfig', '-a')
    addresses = re.findall(r'inet (\S+) netmask (0x[0-9a-fA-F]+)', interfaces)
    networks = [ipaddress.ip_network((address, str(ipaddress.IPv4Address(int(mask, 16)))),
                                     strict=False) for address, mask in addresses]
    # net-literal-allow: disconnected, link-local test-only epair subnet
    base = int(ipaddress.IPv4Address('169.254.0.0'))
    for _ in range(64):
        candidate = ipaddress.ip_network((base + secrets.randbelow(16384) * 4, 30))
        if not any(candidate.overlaps(existing) for existing in networks):
            return candidate
    raise RuntimeError('cannot lease an isolated link-local /30 without overlap')


def _destroy_interface(interface, token):
    description = _run('/sbin/ifconfig', interface)
    if f'description: {token}' not in description:
        raise RuntimeError('refusing to destroy an interface with changed ownership')
    _run('/sbin/ifconfig', interface, 'destroy')


def _remove_jail(jid, token):
    identity = _run('/usr/sbin/jls', '-j', str(jid), '-n', 'name', 'host.hostname')
    if identity.split() != [f'name={token}', f'host.hostname={token}']:
        raise RuntimeError('refusing to remove a jail with changed ownership')
    _run('/usr/sbin/jail', '-r', str(jid))


def _create_jail(interface, token):
    identifier = _run('/usr/sbin/jail', '-i', '-c', f'name={token}',
                      f'host.hostname={token}', 'path=/', 'persist', 'vnet',
                      f'vnet.interface={interface[:-1]}b')
    if not identifier.isdecimal():
        raise RuntimeError(f'jail did not return a numeric identifier: {identifier!r}')
    return int(identifier)


def _configure_peer(interface, jid, network):
    host, peer = str(network[1]), str(network[2])
    _run('/sbin/ifconfig', interface, 'inet', host + '/30', 'up')
    _run('/usr/sbin/jexec', str(jid), '/sbin/ifconfig', interface[:-1] + 'b',
         'inet', peer + '/30', 'up')
    _run('/usr/sbin/jexec', str(jid), '/sbin/sysctl', 'net.inet.tcp.blackhole=2')
    return peer


@contextmanager
def pending_peer():
    """Keep exact resource ownership through partial setup and child failure."""
    if not sys.platform.startswith('freebsd') or os.geteuid() != 0:
        raise RuntimeError('pending-peer setup requires root on native FreeBSD')
    network = _unused_network()
    token = 'brix-pending-' + secrets.token_hex(10)
    interface = _run('/sbin/ifconfig', 'epair', 'create', 'description', token)
    if re.fullmatch(r'epair[0-9]+a', interface) is None:
        raise RuntimeError(f'epair creation returned an invalid identity: {interface!r}')
    try:
        jid = _create_jail(interface, token)
        try:
            yield _configure_peer(interface, jid, network)
        finally:
            _remove_jail(jid, token)
    finally:
        _destroy_interface(interface, token)


def run_as_user(account, command, peer):
    """Use the account's own non-wheel groups, never root's inherited groups."""
    if account.pw_uid == 0:
        raise ValueError('the test command must run as a non-root user')
    groups = os.getgrouplist(account.pw_name, account.pw_gid)
    if 0 in groups:
        raise ValueError('the test account must not belong to wheel')
    environment = dict(os.environ, HOME=account.pw_dir, USER=account.pw_name,
                       LOGNAME=account.pw_name, BRIX_CMS_PENDING_HOST=peer)
    return subprocess.run(command, env=environment, user=account.pw_uid,
                          group=account.pw_gid, extra_groups=groups, check=False).returncode


def main(argv=None):
    import pwd  # Native CLI only; offline lifecycle tests also run on Windows.

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--user', required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('a test command is required after --')
    account = pwd.getpwnam(args.user)
    if account.pw_uid == 0:
        parser.error('--user must select a non-root account')
    with pending_peer() as peer:
        return run_as_user(account, command, peer)


if __name__ == '__main__':
    raise SystemExit(main())
