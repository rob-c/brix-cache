"""Private SSH-stream bridge to independently installed official XRootD tools.

The controller forwards a 0600 Unix socket, never a public command listener.
This transport alone is not a full-suite result: native and remote-reference
reports must remain separate. Local-file CLI jobs require shared fixtures.
"""
from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import select
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

from tools.ci.remote_reference import official_provenance
from tools.ci import remote_reference_daemon as daemon
from tools.ci.remote_reference_policy import (
    client_environment, confined, fixture_command, fixture_create_command,
    forwarded_url, oracle_environment, worker_request,
)
from tools.ci.remote_reference_records import (
    WorkerRecords, bounded_worker_record as _bounded_worker_record,
    input_frames, worker_input_records as _worker_input_records,
)
from urllib.parse import unquote, urlsplit
from tools.logging_support import diagnostic


def send(stream, record, lock):
    """One bounded JSON frame; binary streams are chunked, never line-decoded."""
    content = json.dumps(record).encode() + b'\n'
    if len(content) > 8 * 1024 * 1024:
        raise ValueError('remote reference frame exceeds 8 MiB')
    with lock:
        stream.write(content)
        stream.flush()


def receive(stream):
    """EOF is distinct from a successful child exit or a truncated frame."""
    line = stream.readline(8 * 1024 * 1024 + 1)
    if not line:
        raise EOFError('remote reference transport closed before completion')
    if not line.endswith(b'\n') or len(line) > 8 * 1024 * 1024:
        raise ValueError('invalid remote reference frame')
    return json.loads(line)


class Forwards:
    """Lease forwards only on a controller-owned SSH master and private band."""

    def __init__(self, args):
        self.args = args
        self.destinations = set()
        self.reverse_ports = {}
        self.lock = threading.Lock()

    def __call__(self, host, port):
        if not self.args.port_start <= port < self.args.port_stop:
            raise ValueError('endpoint is outside this remote-reference port band')
        with self.lock:
            self._forward(host, port)

    def _forward(self, host, port):
        if port in self.reverse_ports:
            return
        destination = (host, port)
        if destination in self.destinations:
            return
        if len(self.destinations) >= 256:
            raise ValueError('remote-reference forward limit reached')
        target = f'[{host}]' if ':' in host else host
        self._control('forward', '-L', f'127.0.0.1:{port}:{target}:{port}')  # net-literal-allow: loopback-only lab transport
        self.destinations.add(destination)


    def _control(self, action, direction, specification):
        """An absent owned master is an error, never a fresh ambient SSH session."""
        command = ['ssh', '-F', str(self.args.ssh_config), '-S', str(self.args.control_path),
                   '-o', 'BatchMode=yes', '-O', action, direction, specification, self.args.ssh_target]
        subprocess.run(command, capture_output=True, timeout=15, check=True)

    def reverse(self, port, owner):
        """A healthy host reference daemon gets exactly one native loopback lease."""
        if not self.args.port_start <= port < self.args.port_stop:
            raise ValueError('reference daemon is outside the private port band')
        with self.lock:
            self._reverse(port, owner)

    def _reverse(self, port, owner):
        if port in self.reverse_ports or any(value[1] == port for value in self.destinations):
            raise ValueError('remote reference port role collision')
        self._control('forward', '-R', f'127.0.0.1:{port}:127.0.0.1:{port}')  # net-literal-allow: loopback-only reverse reference lease
        self.reverse_ports[port] = owner

    def retire(self, port, owner):
        """A stale process cannot cancel a replacement daemon's listener."""
        with self.lock:
            if self.reverse_ports.get(port) != owner:
                raise ValueError('remote reference lease owner mismatch')
            self._control('cancel', '-R', f'127.0.0.1:{port}:127.0.0.1:{port}')  # net-literal-allow: cancel this owned reverse lease only
            del self.reverse_ports[port]


def _request_environment(bundle, args, directory):
    """A fresh generation prevents a removed credential from remaining valid."""
    if bundle.get('shared'):
        _require_shared_fixture(args)
        if bundle['files'] or bundle['directories']:
            raise ValueError('shared credentials cannot also carry file contents')
        bundle = client_environment(bundle['values'], args.fixture_root)
    generation = Path(tempfile.mkdtemp(prefix='credentials-', dir=directory))
    return oracle_environment(bundle, args.fixture_root, generation, os.environ)


def _worker_input(data, process, args, directory, forward):
    """Transform only transport metadata; retain offsets and encoded bytes."""
    request = json.loads(data)
    bundle = request.pop('remote_environment', None)
    if bundle is not None:
        request['env'] = _request_environment(bundle, args, directory)
    if 'env' in request and bundle is None:
        raise ValueError('unmediated remote worker environment')
    _worker_files(request, args)
    worker_request(request, forward)
    process.stdin.write(_bounded_worker_record(json.dumps(request).encode() + b'\n'))
    process.stdin.flush()


def _input(stream, process, args, directory, forward, kind, errors):
    """Input EOF closes the owned child's stdin, never reports a test pass."""
    try:
        records = WorkerRecords()
        while _input_record(receive(stream), process, args, directory, forward, kind, records):
            pass
    except Exception as error:
        errors.append(type(error).__name__)
        process.terminate()
    finally:
        process.stdin.close()


def _input_record(record, process, args, directory, forward, kind, records):
    """Deliver one input frame; daemon stdin closure retains its control reader."""
    if record['kind'] == 'eof':
        records.finish()
        return _retain_daemon_control(process, kind)
    if record['kind'] != 'input':
        raise ValueError('invalid remote input kind')
    data = base64.b64decode(record['data'], validate=True)
    if kind == 'worker':
        for request in records.feed(data):
            _worker_input(request, process, args, directory, forward)
    else:
        process.stdin.write(data)
        process.stdin.flush()
    return True


def _retain_daemon_control(process, kind):
    """A foreground daemon's stdin EOF is not the end of its control lease."""
    if kind != 'daemon':
        return False
    process.stdin.close()
    return True


def _check_output_lease(deadline, cancelled):
    """Bound silent children by cancellation as well as wall-clock expiry."""
    if cancelled is not None and cancelled.is_set():
        raise ConnectionAbortedError('remote reference lease stopped')
    if time.monotonic() >= deadline:
        raise TimeoutError('remote reference session lease expired')


def _relay_output(process, stream, lock, deadline, cancelled=None):
    """Preserve stdout/stderr bytes separately, bounded by the session lease."""
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
        selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
        while selector.get_map():
            _check_output_lease(deadline, cancelled)
            for key, _ in selector.select(0.25):
                content = os.read(key.fileobj.fileno(), 65536)
                if not content:
                    selector.unregister(key.fileobj)
                    continue
                send(stream, dict(kind=key.data, data=base64.b64encode(content).decode()), lock)


def _command(hello, args, forward, directory=None):
    """Only pinned clients/worker, never caller-selected executables or a shell."""
    if hello['kind'] == 'worker':
        worker = Path(__file__).resolve().parents[2] / 'tests/brix_suite/clients/xrdcl/worker.py'
        return [str(args.client_python), '-u', str(worker)]
    if hello['kind'] == 'fixture':
        _require_shared_fixture(args)
        return fixture_command(hello, args)
    if hello['kind'] == 'fixture-create':
        _require_shared_fixture(args)
        return fixture_create_command(hello, args)
    if hello['kind'] == 'daemon':
        _require_shared_fixture(args)
        return daemon.prepare(hello, args, directory)
    if hello['kind'] != 'cli' or hello['tool'] not in ('xrdcp', 'xrdfs'):
        raise ValueError('unsupported remote reference operation')
    return _cli_command(hello, args, forward)


def _cli_command(hello, args, forward):
    """CLI jobs need a shared namespace; argv still never enters a shell."""
    arguments = hello['argv']
    if not all(isinstance(value, str) and '\x00' not in value for value in arguments):
        raise ValueError('invalid remote client argv')
    _require_shared_fixture(args)
    for value in arguments:
        _cli_value(value, hello['tool'], args.fixture_root, forward)
    if hello['tool'] == 'xrdfs':
        _xrdfs_authority(arguments, forward)
    return [str(getattr(args, hello['tool'])), *arguments]


def _cli_value(value, tool, root, forward):
    """Distinguish logical xrdfs paths from local xrdcp file arguments."""
    if value.startswith(('root://', 'roots://', 'xroot://')):
        forwarded_url(value, forward)
        return
    if tool == 'xrdcp':
        _local_file_argument(value, root)


def _xrdfs_authority(arguments, forward):
    """The official CLI also accepts a bare host:port as its first argument."""
    if arguments and '://' not in arguments[0]:
        forwarded_url('root://' + arguments[0], forward)


def _require_shared_fixture(args):
    """A controller-pinned native-written nonce proves the shared namespace."""
    proof = args.shared_fixture_proof
    if proof is None:
        raise ValueError('CLI execution requires verified shared fixtures')
    confined(proof, args.fixture_root)
    if proof.stat().st_size > 128 or proof.read_text() != args.shared_fixture_token:
        raise ValueError('shared fixture proof does not match the native lane')


def _local_file_argument(value, root):
    """File URLs and absolute paths cannot borrow files from the oracle host."""
    if value.startswith('file://'):
        parsed = urlsplit(value)
        if parsed.netloc not in ('', 'localhost') or parsed.query or parsed.fragment:
            raise ValueError('invalid shared local file URL')
        confined(unquote(parsed.path), root)
    elif value.startswith('/'):
        confined(value, root)
    elif '://' in value:
        raise ValueError('unsupported remote reference transfer protocol')
    elif not value.startswith('-'):
        confined(Path(root) / value, root)


def _worker_files(request, args):
    """Local CopyProcess jobs require the same explicit shared-fixture proof."""
    if (request.get('op'), request.get('method')) != ('cp_call', 'add_job'):
        return
    for name in ('source', 'target'):
        value = request.get('kwargs', {}).get(name)
        if isinstance(value, str) and not value.startswith(('root://', 'roots://', 'xroot://')):
            _require_shared_fixture(args)
            _local_file_argument(value, args.fixture_root)


def _stop_child(process):
    """Reap only this connection's process group before deleting credentials."""
    _signal_group(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _signal_group(process.pid, signal.SIGKILL)
    # A daemon can exit before its helpers; the owned session ID remains known.
    _signal_group(process.pid, signal.SIGKILL)
    process.wait(timeout=5)


def _signal_group(group, number):
    """An already-reaped owned group is harmless; other signalling errors are not."""
    try:
        os.killpg(group, number)
    except ProcessLookupError:
        pass


def _spawn(hello, args, directory, command):
    """Give each probe/client/daemon its isolated environment before exec."""
    environment = _request_environment(hello['environment'], args, directory)
    if hello['kind'] == 'daemon':
        environment = daemon.environment(args, environment)
    if hello.get('probe'):
        environment['XRDCL_IMPORT_PROBE'] = '1'
    working = {'cli': args.fixture_root}.get(hello['kind'], directory)
    return subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=environment, cwd=working, start_new_session=True)


def _publish_daemon(hello, process, forward, owner):
    """No reverse readiness listener is created for an ordinary client worker."""
    if hello['kind'] == 'daemon':
        daemon.ready(hello, process, forward, owner)


def connection(peer, args, forward, cancelled=None):
    """Every connection owns its worker, credential generations and teardown."""
    process = None
    hello = {}
    directory = Path(tempfile.mkdtemp(prefix='oracle-', dir=args.private_root))
    lock = threading.Lock()
    try:
        with peer, peer.makefile('rwb') as stream:
            peer.settimeout(30)
            hello = receive(stream)
            if hello['fixture_root'] != str(args.fixture_root):
                raise ValueError('native fixture root does not match the leased lane')
            command = _command(hello, args, forward, directory)
            process = _spawn(hello, args, directory, command)
            _publish_daemon(hello, process, forward, directory.name)
            peer.settimeout(None)
            errors = []
            reader = threading.Thread(target=_input,
                args=(stream, process, args, directory, forward, hello['kind'], errors), daemon=True)
            reader.start()
            _relay_output(process, stream, lock, time.monotonic() + args.lease_seconds, cancelled)
            code = process.wait(timeout=5)
            diagnostic('INFO', __file__, 'remote_reference_child_exit',
                       f'kind={hello["kind"]} probe={bool(hello.get("probe"))} code={code} input_errors={len(errors)}')
            send(stream, dict(kind='exit', code=code if not errors else 125), lock)
    except Exception as error:
        diagnostic('ERROR', __file__, 'remote_reference_transport', type(error).__name__)
    finally:
        _retire_connection(process, hello, forward, directory)


def _retire_connection(process, hello, forward, directory):
    """Remove private credentials even when child or SSH-lease retirement fails."""
    try:
        if process is not None:
            _stop_child(process)
    finally:
        try:
            daemon.retire(hello, forward)
        finally:
            shutil.rmtree(directory)


class PeerLease:
    """Stop every owned connection on expiry or signal, then reap its children."""

    def __init__(self, args, forward):
        self.args, self.forward = args, forward
        self.peers = set()
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.stop_requested = False

    def register(self, peer):
        with self.lock:
            self.peers.add(peer)

    def run(self, peer):
        try:
            connection(peer, self.args, self.forward, self.stopped)
        finally:
            with self.lock:
                self.peers.discard(peer)

    def stop(self, _number=None, _frame=None):
        self.stopped.set()
        with self.lock:
            peers = list(self.peers)
        for peer in peers:
            self._disconnect(peer)

    def request_stop(self, _number=None, _frame=None):
        """Signal callbacks must not acquire a lock they may have interrupted."""
        self.stop_requested = True

    def _disconnect(self, peer):
        try:
            peer.shutdown(socket.SHUT_RDWR)
        except OSError:
            # A connection which already reaped its worker may have closed.
            pass


def _serve_connections(listener, args, forward, deadline):
    """Signal handlers belong only to this CLI lease and are always restored."""
    lease = PeerLease(args, forward)
    previous = {number: signal.signal(number, lease.request_stop) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        with ThreadPoolExecutor(max_workers=8) as workers:
            try:
                _accept_connections(listener, lease, workers, deadline)
            finally:
                lease.stop()
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def _accept_connections(listener, lease, workers, deadline):
    """Publish accepted peers before scheduling, including queued connections."""
    while not lease.stop_requested and time.monotonic() < deadline:
        try:
            peer, _ = listener.accept()
        except TimeoutError:
            continue
        lease.register(peer)
        workers.submit(lease.run, peer)


def serve(args):
    """Prove independent tools before binding an owner-private Unix socket."""
    repo = Path(__file__).resolve().parents[2]
    sys.path[:0] = [str(repo / 'tests'), str(repo / 'brixtest/src')]
    provenance = official_provenance(args, args.private_root)
    if args.xrootd is not None:
        provenance['server'] = daemon.artifact(args)
    (args.private_root / 'reference-provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    forward = Forwards(args)
    deadline = time.monotonic() + args.lease_seconds
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(args.socket))
        args.socket.chmod(0o600)
        listener.listen(8)
        listener.settimeout(0.5)
        try:
            _serve_connections(listener, args, forward, deadline)
        finally:
            args.socket.unlink(missing_ok=True)


def _stdin_chunks(stopped):
    """Cancellable raw reads never leave Python's buffered stdin locked at exit."""
    descriptor = sys.stdin.fileno()
    while not stopped.is_set():
        ready, _, _ = select.select([descriptor], [], [], 0.25)
        if not ready:
            continue
        data = os.read(descriptor, 65536)
        if not data:
            return
        yield data


def _client_frames(args, stopped):
    """Mediate complete worker requests before splitting transport-only bytes."""
    chunks = _stdin_chunks(stopped)
    if args.kind == 'worker':
        chunks = _worker_input_records(chunks)
    for data in chunks:
        if args.kind == 'worker':
            data = _bounded_worker_record(_client_request(data, args.fixture_root, args.shared_credentials))
        yield from input_frames(data)


def _client_input(stream, lock, args, peer, stopped):
    """Bundle only fixture credentials before the official worker sees env."""
    try:
        for frame in _client_frames(args, stopped):
            send(stream, frame, lock)
        if not stopped.is_set():
            send(stream, dict(kind='eof'), lock)
    except (OSError, ValueError) as error:
        # Closing the transport forces a worker/CLI error, never a fallback.
        if not stopped.is_set():
            diagnostic('ERROR', __file__, 'remote_reference_input', type(error).__name__)
            peer.shutdown(socket.SHUT_RDWR)


def _client_request(data, root, shared=False):
    """Keep per-operation credential changes in request order."""
    request = json.loads(data)
    environment = request.pop('env', None)
    if environment is not None:
        request['remote_environment'] = client_environment(environment, root, shared=shared)
    return json.dumps(request).encode() + b'\n'


def client(args):
    """Transparent binary stdout/stderr with a real remote child exit status."""
    hello = dict(kind=args.kind, fixture_root=str(args.fixture_root),
        probe=os.environ.get('XRDCL_IMPORT_PROBE') == '1',
        environment=client_environment(os.environ, args.fixture_root, shared=args.shared_credentials))
    if args.kind != 'worker':
        hello.update(tool=args.tool, argv=_client_argv(args.argv))
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(15)
        peer.connect(str(args.socket))
        peer.settimeout(None)
        with peer.makefile('rwb') as stream:
            lock = threading.Lock()
            send(stream, hello, lock)
            stopped = threading.Event()
            reader = threading.Thread(target=_client_input, args=(stream, lock, args, peer, stopped))
            reader.start()
            try:
                return _client_output(stream)
            finally:
                _stop_client_input(reader, stopped, peer)


def _client_output(stream):
    """Keep child exit status distinct from EOF and preserve both binary streams."""
    while True:
        record = receive(stream)
        if record['kind'] == 'exit':
            return record['code']
        output = {'stdout': sys.stdout.buffer, 'stderr': sys.stderr.buffer}[record['kind']]
        output.write(base64.b64decode(record['data'], validate=True))
        output.flush()


def _stop_client_input(reader, stopped, peer):
    """Release both an idle stdin poll and an in-flight owned socket write."""
    stopped.set()
    try:
        peer.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass  # The owned transport may already have closed after an error.
    reader.join(timeout=1)
    if reader.is_alive():
        raise RuntimeError('remote reference input reader did not stop')


def _client_argv(arguments):
    """Remove the relay delimiter, not the official tool's own delimiters."""
    return arguments[1:] if arguments[:1] == ['--'] else arguments


def _server_arguments(sub):
    """Controller-owned endpoints, tools and session bounds."""
    server = sub.choices['serve']
    for name in ('private-root', 'ssh-config', 'control-path', 'xrdcp', 'xrdfs', 'client-python'):
        server.add_argument('--' + name, type=Path, required=True)
    server.add_argument('--ssh-target', required=True)
    server.add_argument('--port-start', type=int, required=True)
    server.add_argument('--port-stop', type=int, required=True)
    server.add_argument('--lease-seconds', type=int, default=900)
    server.add_argument('--shared-fixture-proof', type=Path)
    server.add_argument('--shared-fixture-token')
    server.add_argument('--xrootd', type=Path)
    server.add_argument('--daemon-bind-guard', type=Path)


def _native_arguments(sub):
    """The native relay has no executable-selection argument."""
    native = sub.choices['client']
    native.add_argument('--kind', choices=('worker', 'cli', 'daemon', 'fixture', 'fixture-create'), default='worker')
    native.add_argument('--tool', choices=('xrdcp', 'xrdfs', 'xrootd'))
    native.add_argument('--shared-credentials', action='store_true',
                        help='read credentials from the independently proven shared fixture namespace')
    native.add_argument('argv', nargs=argparse.REMAINDER)


def _validate_server(parser, args):
    """Refuse broad listeners, unbounded leases and foreign socket namespaces."""
    if not 1 <= args.lease_seconds <= 14400:
        parser.error('lease must be between 1 and 14400 seconds')
    if not 1024 <= args.port_start < args.port_stop <= 65536:
        parser.error('invalid private port band')
    args.timeout = 30
    _validate_private_namespace(parser, args)


def _validate_private_namespace(parser, args):
    """The listener can neither overwrite foreign paths nor expose a shell."""
    info = args.private_root.stat()
    if not args.private_root.is_dir() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        parser.error('private root must have mode 0700')
    if args.socket.parent.resolve() != args.private_root.resolve():
        parser.error('socket must be inside the owner-private root')


def arguments(argv):
    """Select a constrained relay role; ordinary test runs never invoke it."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    for name in ('serve', 'client'):
        selected = sub.add_parser(name)
        selected.add_argument('--socket', type=Path, required=True)
        selected.add_argument('--fixture-root', type=Path, required=True)
    _server_arguments(sub)
    _native_arguments(sub)
    args = parser.parse_args(argv)
    if args.operation == 'serve':
        _validate_server(parser, args)
    return args


def main(argv=None):
    args = arguments(argv)
    try:
        return serve(args) if args.operation == 'serve' else client(args)
    except (OSError, ValueError, EOFError, subprocess.SubprocessError) as error:
        diagnostic('ERROR', __file__, 'remote_reference_transport', type(error).__name__)
        return 125


if __name__ == '__main__':
    raise SystemExit(main())
