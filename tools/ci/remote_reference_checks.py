"""Byte and refusal contracts driven only by the official external clients."""
from __future__ import annotations

import hashlib
import os
import subprocess
import time
import uuid
import zlib


def require_status(result):
    """Do not confuse a successful transport with a refused per-operation result."""
    status = result[0] if isinstance(result, tuple) else result
    assert status.ok, str(status)
    return result[1] if isinstance(result, tuple) else None


class ReferenceContext:
    """Own exactly one newly created remote namespace and its local artifacts."""

    def __init__(self, args, evidence, directory, client):
        self.args, self.evidence, self.directory, self.client = args, evidence, directory, client
        self.base = args.url.rstrip('/')
        self.fs = client.FileSystem(args.url)
        self.prefix = '/.brix-external-' + uuid.uuid4().hex
        self.owned = set()
        self.created = False
        self.payload = hashlib.shake_256(b'BriX external reference fixture').digest(evidence['fixture']['size'])

    def prepare(self):
        require_status(self.fs.mkdir(self.prefix, 0, 0o700))
        self.created = True
        assert hashlib.sha256(self.payload).hexdigest() == self.evidence['fixture']['sha256']

    def path(self, name):
        assert name and '/' not in name and name not in ('.', '..')
        return self.prefix + '/' + name

    def url(self, path):
        assert path.startswith('/')
        return self.base + '/' + path

    def file(self, path, flags=16):
        handle = self.client.File()
        require_status(handle.open(self.url(path), flags, 0o600))
        return handle

    def create(self, name, content):
        path = self.path(name)
        with self.file(path, 8 | 32) as handle:
            self.owned.add(path)
            require_status(handle.write(content, 0))
            require_status(handle.sync())
        return path

    def read(self, path, offset, length):
        with self.file(path) as handle:
            return require_status(handle.read(offset, length))

    def command(self, tool, arguments, *, success=True):
        result = subprocess.run([str(tool), *arguments], capture_output=True,
                                text=True, timeout=self.args.timeout)
        if success:
            assert result.returncode == 0, result.stderr[-3000:] + result.stdout[-1000:]
        else:
            assert result.returncode != 0, 'a required refusal unexpectedly succeeded'
        return result

    def cleanup(self):
        """Never recurse or delete names supplied by a server directory listing."""
        if not self.created:
            return
        for path in sorted(self.owned):
            assert path.startswith(self.prefix + '/')
            require_status(self.fs.rm(path))
        require_status(self.fs.rmdir(self.prefix))


def scalar_range(context, offset, length):
    expected = context.payload[offset:offset + length]
    assert context.read('/reference.bin', offset, length) == expected


def vector_ranges(context):
    ranges = [(1, 31), (4095, 129), (1048576, 257)]
    with context.file('/reference.bin') as handle:
        response = require_status(handle.vector_read(ranges))
        assert len(response.chunks) == len(ranges)
        for chunk, (offset, length) in zip(response.chunks, ranges):
            assert chunk.offset == offset and chunk.length == length
            assert bytes(chunk.buffer) == context.payload[offset:offset + length]


def handle_stat(context):
    with context.file('/reference.bin') as handle:
        metadata = require_status(handle.stat(force=True))
        assert metadata.size == len(context.payload)


def namespace_metadata(context):
    metadata = require_status(context.fs.stat('/reference.bin'))
    assert metadata.size == len(context.payload)
    listing = require_status(context.fs.dirlist('/'))
    assert 'reference.bin' in {entry.name for entry in listing}


def checksum(context):
    response = require_status(context.fs.query(3, '/reference.bin'))
    algorithm, digest = response.rstrip(b'\0').decode().strip().split()
    assert algorithm == 'adler32'
    assert int(digest, 16) == zlib.adler32(context.payload) & 0xffffffff


def cli_download(context, verified=False):
    destination = context.directory / ('verified.bin' if verified else 'download.bin')
    options = ['--cksum', 'adler32'] if verified else []
    context.command(context.args.xrdcp, [*options, context.url('/reference.bin'), str(destination)])
    assert destination.read_bytes() == context.payload


def cli_upload(context):
    source = context.directory / 'upload-source.bin'
    content = context.payload[:2 * 1024 * 1024 + 53]
    source.write_bytes(content)
    path = context.path('cli-upload')
    # The prefix was created exclusively, so cleanup cannot delete operator data.
    context.owned.add(path)
    context.command(context.args.xrdcp, [str(source), context.url(path)])
    assert context.read(path, 0, len(content)) == content


def cli_metadata(context):
    result = context.command(context.args.xrdfs, [context.args.url, 'stat', '/reference.bin'])
    assert str(len(context.payload)) in result.stdout
    result = context.command(context.args.xrdfs, [context.args.url, 'query', 'checksum', '/reference.bin'])
    assert 'adler32' in result.stdout.lower()
    assert f'{zlib.adler32(context.payload) & 0xffffffff:08x}' in result.stdout.lower()


def write_truncate(context, size):
    path = context.create('truncate-' + str(size), context.payload[:8192])
    with context.file(path, 32) as handle:
        require_status(handle.truncate(size))
        require_status(handle.sync())
        assert require_status(handle.stat(force=True)).size == size
    data = context.read(path, 0, min(size, 12288))
    expected = context.payload[:min(size, 8192)] + b'\0' * max(0, min(size, 12288) - 8192)
    assert data == expected


def sparse_write(context):
    path = context.path('sparse')
    content = b'offset-one-MiB-must-not-become-sixteen-TiB'
    with context.file(path, 8 | 32) as handle:
        context.owned.add(path)
        require_status(handle.write(content, 1048576))
        require_status(handle.sync())
    assert require_status(context.fs.stat(path)).size == 1048576 + len(content)
    assert context.read(path, 1048560, 16 + len(content)) == b'\0' * 16 + content


def rename_remove(context):
    source = context.create('rename-from', b'namespace-content')
    destination = context.path('rename-to')
    require_status(context.fs.mv(source, destination))
    context.owned.remove(source)
    context.owned.add(destination)
    assert context.read(destination, 0, 64) == b'namespace-content'
    require_status(context.fs.rm(destination))
    context.owned.remove(destination)
    status, _ = context.fs.stat(destination)
    assert not status.ok


def xattr_roundtrip(context):
    path = context.create('xattr', b'metadata')
    _xattr_mutation(context.fs.set_xattr(path, [('user.external-reference', 'native-roundtrip')]))
    response = require_status(context.fs.get_xattr(path, ['user.external-reference']))
    assert len(response) == 1
    name, value, status = response[0]
    assert _attribute_ok(status) and name == 'user.external-reference' and value == 'native-roundtrip'
    _xattr_mutation(context.fs.del_xattr(path, ['user.external-reference']))
    response = require_status(context.fs.get_xattr(path, ['user.external-reference']))
    assert len(response) == 1 and not _attribute_ok(response[0][2])


def _xattr_mutation(result, names=None):
    """A transport success must not hide a per-attribute mutation failure."""
    response = require_status(result)
    if names is None:
        assert len(response) == 1
    else:
        assert len(response) == len(names)
        assert {entry[0] for entry in response} == set(names)
    for entry in response:
        assert _attribute_ok(entry[-1]), str(entry[-1])


def xattr_batch(context):
    """Round-trip independent values and names, then list and remove the batch."""
    path = context.create('xattr-batch', b'extended metadata batch')
    values = dict(zip(('user.empty', 'user.spaces', 'user.lines', 'user.unicode', 'user.large'),
                      ('', 'a value with spaces', 'one\ntwo\tthree', 'HEP-\u03bc-data', 'a7' * 4096)))
    _xattr_mutation(context.fs.set_xattr(path, list(values.items())), values)
    response = require_status(context.fs.get_xattr(path, list(reversed(values))))
    _assert_attribute_values(response, values)
    response = require_status(context.fs.list_xattr(path))
    _assert_attribute_values(response, values)
    _xattr_mutation(context.fs.del_xattr(path, list(values)), values)
    remaining = require_status(context.fs.list_xattr(path))
    assert remaining == [], f'attributes after batch removal: {remaining!r}'


def _assert_attribute_values(response, expected):
    """Reject missing/duplicate names, internal-prefix leaks or partial success."""
    assert len(response) == len(expected), (
        f'attribute count: expected {len(expected)}, got {len(response)}')
    actual = {entry[0]: entry[1] for entry in response}
    assert actual == expected, ('attribute names or values differ; returned lengths: '
                                + str(_attribute_value_lengths(actual)))
    assert all(_attribute_ok(entry[-1]) for entry in response), 'per-attribute refusal in batch'


def _attribute_value_lengths(values):
    """Keep diagnostics bounded even for the largest legal attribute value."""
    return {name: len(value) for name, value in values.items()}


def _attribute_ok(status):
    """Bindings expose per-attribute statuses as public mappings or objects."""
    return status.get('ok', False) if isinstance(status, dict) else status.ok


def require_refusal(status, expected):
    """An expected server refusal is not a timeout, disconnect or client error."""
    assert not status.ok, 'a required refusal unexpectedly succeeded'
    assert status.errno in expected, str(status)


def refused_open(context, path, expected):
    with context.client.File() as handle:
        status, _ = handle.open(context.url(path), 16)
        require_refusal(status, expected)


def readonly_mutation(context):
    client = context.client
    filesystem = client.FileSystem(context.args.read_only_url)
    status, _ = filesystem.mkdir(context.prefix, 0, 0o700)
    require_refusal(status, (3025,))
    with client.File() as handle:
        status, _ = handle.open(context.args.read_only_url.rstrip('/') + '/' + context.path('readonly-denied'), 8 | 32, 0o600)
        require_refusal(status, (3025,))
    status, _ = context.fs.stat(context.path('readonly-denied'))
    require_refusal(status, (3011,))
    path = context.create('readonly-xattr', b'metadata gate')
    status, _ = filesystem.set_xattr(path, [('user.must-not-appear', 'refused')])
    require_refusal(status, (3025,))
    response = require_status(context.fs.list_xattr(path))
    assert response == [], 'read-only metadata request mutated the shared export'
    assert context.read(path, 0, 64) == b'metadata gate'


def missing_credentials(context):
    """A fresh client cannot borrow a previously authenticated pooled session."""
    from brix_suite.clients.xrdcl.worker_link import _shutdown_worker

    previous = {name: os.environ[name] for name in ('X509_USER_PROXY', 'X509_USER_CERT', 'X509_USER_KEY')}
    _shutdown_worker()
    for name in previous:
        os.environ[name] = str(context.directory / 'missing-test-proxy')
    try:
        with context.client.File() as handle:
            status, _ = handle.open(context.url('/reference.bin'), 16)
            _authentication_refused(status)
    finally:
        os.environ.update(previous)
        _shutdown_worker()
        context.fs = context.client.FileSystem(context.args.url)


def _authentication_refused(status):
    """Accept an explicit authentication failure, never a generic I/O error."""
    if status.errno in (3010, 3030):
        require_refusal(status, (3010, 3030))
        return
    assert not status.ok and status.code == 204 and 'Auth failed' in status.message, str(status)


def disallowed_auth_protocol(context):
    """Reach TLS, then refuse Unix auth where the server requires GSI.

    An unreadable client certificate only fails XrdCl's local TLS setup and
    proves nothing about the server. Keep the valid TLS identity here, but
    offer no permitted application authentication protocol.
    """
    from brix_suite.clients.xrdcl.worker_link import _shutdown_worker

    previous = os.environ['XrdSecPROTOCOL']
    _shutdown_worker()
    os.environ['XrdSecPROTOCOL'] = 'unix'
    try:
        with context.client.File() as handle:
            status, _ = handle.open(context.url('/reference.bin'), 16)
            _authentication_refused(status)
    finally:
        os.environ['XrdSecPROTOCOL'] = previous
        _shutdown_worker()
        context.fs = context.client.FileSystem(context.args.url)


def _basic_cases(context):
    """Keep the feature catalogue separate from parameterized boundary cases."""
    return [(name, lambda fn=check: fn(context)) for name, check in (
        ('vector-ranges', vector_ranges), ('handle-stat', handle_stat),
        ('namespace-metadata', namespace_metadata), ('checksum', checksum),
        ('cli-download', cli_download), ('cli-upload', cli_upload),
        ('cli-stat-and-checksum', cli_metadata),
        ('sparse-write', sparse_write), ('rename-remove', rename_remove),
        ('xattr-roundtrip-and-missing', xattr_roundtrip),
        ('xattr-batch-values-list-and-removal', xattr_batch))]


def _boundary_cases(context):
    """Exercise offsets and truncation without native-size or endian assumptions."""
    ranges = ((0, 250), (1, 31), (1000, 250), (4095, 8192),
              (65535, 129), (1048576, 4096), (4194300, 128))
    reads = [('scalar-range-' + str(offset), lambda o=offset, n=length: scalar_range(context, o, n))
             for offset, length in ranges]
    truncates = [('truncate-' + str(size), lambda n=size: write_truncate(context, n))
                 for size in (0, 1, 123, 4096, 10000, 1048576)]
    return reads + truncates


def cases(context):
    """Missing optional profiles are not manufactured as passing/skipped cases."""
    selected = _basic_cases(context) + _boundary_cases(context)
    selected += [('cli-checksum-verified-download', lambda: cli_download(context, True)),
                 ('missing-object-refusal', lambda: refused_open(context, context.path('absent'), (3011,))),
                 ('outside-export-refusal', lambda: refused_open(context, context.evidence['root'] + '/outside-sentinel', (3010, 3011)))]
    if context.args.read_only_url:
        selected.append(('read-only-mutations-refused', lambda: readonly_mutation(context)))
    if context.args.profile == 'gsi':
        selected.append(('missing-credentials-refused', lambda: missing_credentials(context)))
    if context.args.profile == 'gsi-tls':
        selected.append(('disallowed-auth-protocol-refused-over-tls', lambda: disallowed_auth_protocol(context)))
    return selected


def execute_case(name, check):
    started = time.monotonic()
    try:
        check()
        outcome, detail = 'passed', ''
    except AssertionError as error:
        outcome, detail = 'failed', str(error)
    except Exception as error:
        outcome, detail = 'errors', type(error).__name__ + ': ' + str(error)
    return dict(name=name, outcome=outcome, detail=detail[:4096],
                seconds=time.monotonic() - started)
