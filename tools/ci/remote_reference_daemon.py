"""Public-config adaptation for a disposable, independently sourced daemon.

Only control-directory and plugin *locations* may change. Export paths and
authentication rules retain their fixture meanings. Never inspect XRootD's
implementation or substitute BriX for this external oracle.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
from pathlib import Path
import re
import socket
import sys
import time

from tools.ci.remote_reference_policy import confined


def artifact(args):
    """Record the actual external server executable and its public linkage."""
    from lib_py.util import linked_libraries

    binary = args.xrootd.resolve(strict=True)
    linkage = linked_libraries(str(binary), check=True)
    if not re.search(r'libXrdServer[.\-]', linkage):
        raise ValueError('remote daemon is not linked to the independent XrdServer')
    with binary.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    guard = _bind_guard(args)
    return dict(path=str(binary), sha256=digest, network_adapter=dict(
        path=str(guard), sha256=hashlib.sha256(guard.read_bytes()).hexdigest(),
        mode='libc-bind-loopback-only-with-listener-attestation',
        changes_protocol_bytes=False, malicious_syscall_sandbox=False))


def _bind_guard(args):
    """The controller must explicitly select a private plain adapter library."""
    selected = getattr(args, 'daemon_bind_guard', None)
    if selected is None:
        raise ValueError('remote daemon requires an explicit loopback bind adapter')
    guard = Path(selected)
    info = guard.lstat()
    if not guard.is_file() or guard.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError('bind adapter must be an owner-controlled plain library')
    return guard.resolve(strict=True)


def environment(args, values):
    """Load the adapter only into the external daemon, never a client or BriX."""
    guard = str(_bind_guard(args))
    if sys.platform == 'darwin':
        values['DYLD_INSERT_LIBRARIES'] = guard
    else:
        values['LD_PRELOAD'] = guard
    return values


def prepare(hello, args, directory):
    """Preserve foreground argv, except for the owned adapted config pathname."""
    arguments = list(hello['argv'])
    index = _config_argument(arguments, args)
    source = confined(arguments[index], args.fixture_root)
    if source.stat().st_size > 256 * 1024:
        raise ValueError('reference config exceeds 256 KiB')
    text = source.read_text()
    adapted = directory / 'xrootd.cfg'
    adapted.write_text(_configuration(text, args, directory))
    arguments[index] = str(adapted)
    hello['daemon_port'] = _port(text, arguments)
    if _accepting(hello['daemon_port']):
        raise ValueError('remote reference port already has a listener')
    return [str(args.xrootd), *arguments]


def _config_argument(arguments, args):
    """Only a foreground unprivileged config rooted in the shared lab is valid."""
    if args.xrootd is None:
        raise ValueError('no independently selected remote daemon')
    if '-b' in arguments or '-R' in arguments:
        raise ValueError('remote reference must remain foreground and unprivileged')
    if arguments.count('-c') != 1:
        raise ValueError('remote daemon requires one explicit fixture config')
    for value in arguments:
        if value.startswith('/'):
            confined(value, args.fixture_root)
    return arguments.index('-c') + 1


def _port(text, arguments):
    """A public -p override takes precedence over xrd.port, without emulation."""
    if '-p' in arguments:
        return int(arguments[arguments.index('-p') + 1])
    values = re.findall(r'^\s*xrd\.port\s+([0-9]+)\s*$', text, re.MULTILINE)
    if len(values) != 1:
        raise ValueError('reference config requires one explicit TCP port')
    return int(values[0])


def _configuration(text, args, directory):
    """Relocate process-private control sockets, never exported fixture names."""
    lines = []
    for line in text.splitlines():
        fields = line.split()
        lines.append(_configuration_line(line, fields, args, directory))
    return '\n'.join(lines) + '\n'


def _configuration_line(line, fields, args, directory):
    """Keep semantics explicit; refuse external includes and foreign exports."""
    if not fields or fields[0].startswith('#'):
        return line
    name = fields[0]
    if name in ('all.adminpath', 'all.pidpath'):
        return name + ' ' + str(directory / 'control')
    if name == 'include':
        raise ValueError('remote config includes require an explicit expanded fixture')
    if name == 'oss.localroot':
        confined(fields[1], args.fixture_root)
    return line


def ready(hello, process, forward, owner):
    """Publish the reverse listener only after the actual daemon is accepting."""
    port = hello['daemon_port']
    deadline = time.monotonic() + 15
    while process.poll() is None and time.monotonic() < deadline:
        if _accepting(port):
            _attest_listeners(process.pid, port)
            forward.reverse(port, owner)
            hello['daemon_lease'] = owner
            return
        time.sleep(0.05)
    raise RuntimeError('independent remote daemon did not become ready')


def _attest_listeners(pid, port):
    """Publish readiness only for this process's real, exclusively local sockets."""
    listeners = _process_listeners(pid)
    if not any(address.port == port for address in listeners):
        raise RuntimeError('reference daemon owns no expected TCP listener')
    if not all(ipaddress.ip_address(address.ip).is_loopback for address in listeners):
        raise RuntimeError('reference daemon has a non-loopback listener')


def _process_listeners(pid):
    """Read this exact daemon's kernel socket table, not the host's port list."""
    import psutil

    process = psutil.Process(pid)
    inspect = getattr(process, 'net_connections', None)
    if inspect is None:
        inspect = process.connections
    return [item.laddr for item in inspect(kind='inet')
            if item.status == psutil.CONN_LISTEN]


def _accepting(port):
    """Readiness must observe the real process, not an already-created tunnel."""
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=0.1):  # net-literal-allow: owned reference-daemon readiness
            return True
    except OSError:
        return False


def retire(hello, forward):
    """Cancel only the reverse listener this exact daemon connection leased."""
    if 'daemon_lease' in hello:
        forward.retire(hello['daemon_port'], hello['daemon_lease'])
