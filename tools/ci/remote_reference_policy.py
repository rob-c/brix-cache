"""Explicit credentials and endpoint policy for the optional remote oracle.

The bridge is a disposable test tool, not a general remote shell. Only the
fixture's credentials cross it; neither host may lend its operator credentials.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import ipaddress
import os
from pathlib import Path
import stat
from urllib.parse import urlsplit


def client_environment(environment, root, *, shared=False):
    """Capture bounded fixture credentials; never follow a link out of the lab."""
    selected = {key: value for key, value in environment.items() if credential_variable(key)}
    if shared:
        return dict(values=selected, files={}, directories=[], shared=True)
    files, directories = {}, []
    for name in credential_paths():
        value = selected.get(name)
        if value:
            _prefix, path = _credential_path_value(name, value)
            _capture_credentials(path, root, files, directories)
    return dict(values=selected, files=files, directories=directories)


def _capture_credentials(value, root, files, directories):
    """A CA directory is shallow; linked files still undergo confinement checks."""
    path = Path(value)
    if not path.exists():
        return
    confined(path, root)
    if path.is_dir():
        directories.append(value)
        for entry in path.iterdir():
            if entry.is_file():
                _credential_file(entry, root, files)
        return
    _credential_file(path, root, files)


def credential_variable(name):
    """Keep test-specific security controls, not arbitrary host process settings."""
    return name == 'KRB5CCNAME' or name.startswith(
        ('X509_', 'XrdSec', 'XRD_', 'BEARER_TOKEN', 'SCITOKENS_', 'KRB5_'))


def credential_paths():
    """The public client discovery paths whose contents must accompany a request."""
    return ('X509_USER_PROXY', 'X509_USER_CERT', 'X509_USER_KEY', 'X509_CERT_DIR',
            'XrdSecGSICERT', 'XrdSecGSIKEY', 'XrdSecGSICADIR', 'BEARER_TOKEN_FILE',
            'SCITOKENS_FILE', 'KRB5CCNAME', 'KRB5_CONFIG', 'KRB5_KTNAME', 'KRB5_CLIENT_KTNAME')


def _credential_path_value(name, value):
    """Preserve explicit FILE cache/keytab types; never borrow a host cache service."""
    if name not in ('KRB5CCNAME', 'KRB5_KTNAME', 'KRB5_CLIENT_KTNAME'):
        return '', value
    if value.startswith('FILE:'):
        return 'FILE:', value[5:]
    if not value.startswith('/') and ':' in value:
        raise ValueError('remote reference requires file-backed Kerberos credentials')
    return '', value


def confined(path, root):
    """Reject namespace and symlink escapes, including a nonexistent leaf's parent."""
    Path(path).resolve().relative_to(Path(root).resolve(strict=True))
    return Path(path)


def _credential_file(path, root, files):
    """Bound the whole credential bundle before allocating or transmitting it."""
    confined(path, root)
    if path.stat().st_size > 1024 * 1024:
        raise ValueError('individual fixture credential exceeds 1 MiB')
    with path.open('rb') as source:
        content = source.read(1024 * 1024 + 1)
    if len(content) > 1024 * 1024:
        raise ValueError('individual fixture credential exceeds 1 MiB')
    files[str(path)] = base64.b64encode(content).decode('ascii')
    if sum(len(value) for value in files.values()) > 4 * 1024 * 1024:
        raise ValueError('fixture credential bundle exceeds 4 MiB')


def _credential_destination(value, root, directory):
    """Native names become private copies, never paths on the oracle host."""
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('credential paths must be absolute and normalized')
    relative = path.relative_to(root)
    return directory / relative


def oracle_environment(bundle, root, directory, baseline):
    """Replace the complete security environment before each request."""
    environment = {key: value for key, value in baseline.items()
                   if not credential_variable(key)}
    values = bundle['values']
    _validate_bundle(bundle)
    _install_credentials(bundle, root, directory)
    environment.update(values)
    environment.update(HOME=str(directory), TMPDIR=str(directory))
    _map_credential_paths(values, environment, root, directory)
    return environment


def _validate_bundle(bundle):
    """The receiving host enforces the same namespace and size policy."""
    values = bundle['values']
    if not all(credential_variable(name) for name in values):
        raise ValueError('non-credential environment override')
    if sum(len(value) for value in bundle['files'].values()) > 4 * 1024 * 1024:
        raise ValueError('fixture credential bundle exceeds 4 MiB')


def _map_credential_paths(values, environment, root, directory):
    """Neither absent native paths nor default discovery may borrow host keys."""
    # Missing native files must stay missing, even if the operator has a file
    # with the same absolute name on the reference host.
    for name in credential_paths():
        value = values.get(name)
        if value:
            prefix, path = _credential_path_value(name, value)
            environment[name] = prefix + str(_credential_destination(path, root, directory))
    absent = str(directory / '.absent-operator-credentials')
    for name in ('X509_USER_PROXY', 'X509_USER_CERT', 'X509_USER_KEY', 'X509_CERT_DIR'):
        environment.setdefault(name, absent)
    for name in ('KRB5CCNAME', 'KRB5_KTNAME', 'KRB5_CLIENT_KTNAME'):
        environment.setdefault(name, 'FILE:' + absent)


def _install_credentials(bundle, root, directory):
    """Install only plain files/directories inside a per-worker 0700 namespace."""
    for value in bundle['directories']:
        _credential_destination(value, root, directory).mkdir(parents=True, exist_ok=True, mode=0o700)
    for value, encoded in bundle['files'].items():
        destination = _credential_destination(value, root, directory)
        content = base64.b64decode(encoded, validate=True)
        if len(content) > 1024 * 1024:
            raise ValueError('individual fixture credential exceeds 1 MiB')
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(content)


def forwarded_url(value, forward):
    """Only explicit numeric loopback lab endpoints may create SSH forwards."""
    parsed = urlsplit(value)
    if parsed.scheme not in ('root', 'roots', 'xroot'):
        raise ValueError('unsupported remote reference connection protocol')
    host = parsed.hostname
    if host == 'localhost':
        host = '127.0.0.1'  # net-literal-allow: explicit private SSH forward destination
    address = ipaddress.ip_address(host)
    if not address.is_loopback or parsed.port is None:
        raise ValueError('remote reference requires an explicit loopback lab endpoint')
    forward(str(address), parsed.port)
    return value


def worker_request(request, forward):
    """Keep URL.parse and payload bytes exact; rewrite only connection arguments."""
    selector = (request.get('op'), request.get('method'))
    connection = {('fs_new', None): _filesystem_urls,
                  ('file_call', 'open'): _open_urls,
                  ('cp_call', 'add_job'): _copy_urls}.get(selector)
    if connection:
        for value in connection(request):
            forwarded_url(value, forward)
    return request


def _filesystem_urls(request):
    """FileSystem construction takes its endpoint outside the method argv."""
    return [request['url']]


def _open_urls(request):
    """File.open supports the public positional and keyword URL forms."""
    args = request.get('args', [])
    return [args[0] if args else request['kwargs']['url']]


def _copy_urls(request):
    """Only the source/target of CopyProcess.add_job are connection endpoints."""
    values = request.get('kwargs', {})
    return [values[name] for name in ('source', 'target')
            if _remote_copy_url(values.get(name))]


def _remote_copy_url(value):
    """Local CopyProcess paths are validated by the shared-filesystem policy."""
    return isinstance(value, str) and value.startswith(('root://', 'roots://', 'xroot://'))


@contextmanager
def _fixture_descriptor(root, path):
    """Open only beneath the pinned root, without following any symlink."""
    relative = Path(path).relative_to(Path(root))
    if not Path(path).is_absolute() or '..' in relative.parts:
        raise ValueError('fixture inspection requires a confined absolute path')
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in relative.parts:
            child = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


def fixture_xattrs(root, path):
    """Inspect real oracle xattrs through a no-symlink, descriptor-confined walk."""
    with _fixture_descriptor(root, path) as descriptor:
        mode = os.fstat(descriptor).st_mode
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise ValueError('fixture inspection requires a plain file or directory')
        return _descriptor_xattrs(descriptor)


def fixture_stat(root, path):
    """Read actual backing-filesystem sizes, not SFTP's synthesized allocation."""
    with _fixture_descriptor(root, path) as descriptor:
        info = os.fstat(descriptor)
        return {name: getattr(info, name) for name in ('st_mode', 'st_size', 'st_blocks')}


def fixture_mkfifo(root, path, mode):
    """Create one new FIFO in an owned directory; never replace or follow names."""
    if type(mode) is not int or not 0 <= mode <= 0o777:
        raise ValueError('fixture FIFO mode must contain only permission bits')
    target = Path(path)
    if not target.name or target.name in ('.', '..'):
        raise ValueError('fixture FIFO requires a leaf name')
    with _fixture_descriptor(root, target.parent) as descriptor:
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise ValueError('fixture FIFO requires an owned parent directory')
        os.mkfifo(target.name, mode, dir_fd=descriptor)
    return {'created': True}


def _descriptor_xattrs(descriptor):
    """Bound real user-namespace metadata before base64 allocation or framing."""
    result, size = {}, 0
    names = os.listxattr(descriptor)
    if len(names) > 1024:
        raise ValueError('fixture xattr count exceeds 1024')
    for name in names:
        if not name.startswith('user.'):
            continue
        value = os.getxattr(descriptor, name)
        size += len(value)
        if len(value) > 65536 or size > 1024 * 1024:
            raise ValueError('fixture xattr content exceeds inspection bounds')
        result[name] = base64.b64encode(value).decode('ascii')
    return result


def fixture_command(hello, args):
    """Run one fixed read-only inspector, never caller-provided code or a shell."""
    values = hello['argv']
    operation = 'xattrs' if len(values) == 1 else values[0] if len(values) == 2 else None
    if operation not in ('xattrs', 'stat'):
        raise ValueError('fixture inspection requires xattrs/stat and exactly one path')
    path = values[-1]
    confined(path, args.fixture_root)
    function = 'fixture_xattrs' if operation == 'xattrs' else 'fixture_stat'
    code = ('import json,sys; from tools.ci.remote_reference_policy import ' + function + '; '
            'print(json.dumps(' + function + '(sys.argv[1],sys.argv[2])))')
    return [str(args.client_python), '-c', code, str(args.fixture_root), path]


def fixture_create_command(hello, args):
    """A separate exclusive-FIFO route, never part of the read-only inspector."""
    values = hello['argv']
    if len(values) != 2:
        raise ValueError('fixture FIFO creation requires one path and mode')
    path, mode = values
    confined(path, args.fixture_root)
    if not mode.isdecimal() or not 0 <= int(mode) <= 0o777:
        raise ValueError('invalid fixture FIFO permission bits')
    code = ('import json,sys; from tools.ci.remote_reference_policy import fixture_mkfifo; '
            'print(json.dumps(fixture_mkfifo(sys.argv[1],sys.argv[2],int(sys.argv[3]))))')
    return [str(args.client_python), '-c', code, str(args.fixture_root), path, mode]
