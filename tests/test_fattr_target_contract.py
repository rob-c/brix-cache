"""Native attribute target errors preserve vector framing and confinement."""
import os
import struct
import time

import pytest

from _test_conf_prepfattr_helpers import _fattr, _resp, _session
from ephemeral_port import free_port
from server_registry import NginxInstanceSpec
from settings import BIND_HOST


pytestmark = pytest.mark.uses_lifecycle_harness

_FATTR_LIST_WITH_DATA = 0x10
_FATTR_LIST_RECURSE = 0x20
_FATTR_RESPONSE_CAP = 256 * 1024
_FATTR_VALUE_MAX = 65536


@pytest.fixture
def attribute_target(lifecycle, tmp_path):
    """Keep the export and an attributed outside sentinel on the native filesystem."""
    root = tmp_path / 'export'
    root.mkdir()
    (root / 'directory').mkdir()
    os.setxattr(root / 'directory', 'user.U.project', b'cms')
    present = root / 'present'
    present.write_bytes(b'payload')
    os.setxattr(present, 'user.U.project', b'cms')
    (root / 'inside').symlink_to('present')
    outside = tmp_path / 'outside'
    outside.write_bytes(b'outside-sentinel')
    os.setxattr(outside, 'user.U.project', b'private-outside-value')
    (root / 'escape').symlink_to(outside)
    database = tmp_path / 'allow-authdb'
    database.write_text('u * / a\n')
    endpoint = lifecycle.start(NginxInstanceSpec(
        name='lc-fattr-target-contract', template='nginx_lc_acc_residual_stream.conf',
        protocol='root', readiness='root', port=free_port(BIND_HOST),
        data_root=str(root), template_values={'DATA_DIR': str(root),
            'AUTHDB_PATH': str(database), 'EXTRA_DIRECTIVES': ''},
        reason='native attribute vector errors never bypass confined target resolution'))
    return endpoint, root, outside


def _get(target, path, names):
    """Use the existing bounded raw-wire driver, without a reference binding."""
    endpoint, _root, _outside = target
    with _session(endpoint.port) as connection:
        return _fattr(connection, path, 1, len(names), names=names)


def _error_vector(names, code):
    """Pin the entire expected response, including every empty value slot."""
    records = b''.join(struct.pack('!H', code) + name.encode() + b'\0' for name in names)
    return bytes((len(names), len(names))) + records + b'\0\0\0\0' * len(names)


def _large_fattr_list(target, count):
    """Store protocol-maximum values, then request the value-bearing list."""
    endpoint, _root, _outside = target
    names = [f'large{index}' for index in range(count)]
    values = [bytes((65 + index,)) * _FATTR_VALUE_MAX for index in range(count)]
    connection = _session(endpoint.port)
    status, body = _fattr(connection, '/present', 3, count,
                          names=names, values=values)
    assert status == 0 and body[:2] == bytes((0, count)), (status, body[:16])
    status, body = _fattr(connection, '/present', 2, 0,
                          options=_FATTR_LIST_WITH_DATA)
    return connection, names, values, status, body


def _decode_fattr_list_values(body):
    """Decode every complete fattr record, rejecting truncation."""
    values = {}
    offset = 0
    while offset < len(body):
        name, value, offset = _decode_fattr_record(body, offset)
        values[name] = value
    return values


def _decode_fattr_record(body, offset):
    """Validate one name and length before slicing its bounded value."""
    end = body.find(b'\0', offset)
    assert end >= offset, "unterminated fattr list name"
    name = body[offset:end].decode('ascii')
    offset = end + 1
    assert offset + 4 <= len(body), "missing fattr list value length"
    value_len = struct.unpack('!I', body[offset:offset + 4])[0]
    offset += 4
    assert value_len <= len(body) - offset, "truncated fattr list value"
    return name, body[offset:offset + value_len], offset + value_len


def test_value_bearing_fattr_list_accepts_a_bounded_large_response(attribute_target):
    """Success: three maximum values fit and remain byte-exact."""
    connection, names, values, status, body = _large_fattr_list(
        attribute_target, 3)
    connection.close()
    assert status == 0, (status, body[:256])
    assert len(body) <= _FATTR_RESPONSE_CAP
    decoded = _decode_fattr_list_values(body)
    for name, value in zip(names, values):
        assert decoded[name] == value


def test_value_bearing_fattr_list_rejects_an_over_cap_response(attribute_target):
    """Error: four legal maximum values cannot overrun the fixed response."""
    connection, _names, _values, status, body = _large_fattr_list(
        attribute_target, 4)
    connection.close()
    assert status == 4003
    assert struct.unpack('!I', body[:4])[0] == 3002
    assert len(body) < _FATTR_RESPONSE_CAP


def test_over_cap_fattr_list_keeps_the_session_and_attributes_intact(attribute_target):
    """Security-negative: refusal is atomic and leaves the connection usable."""
    connection, names, values, status, body = _large_fattr_list(
        attribute_target, 4)
    assert status == 4003 and struct.unpack('!I', body[:4])[0] == 3002
    status, body = _fattr(connection, '/present', 2, 0)
    assert status == 0
    for name in names:
        assert name.encode() + b'\0' in body
    status, body = _fattr(connection, '/present', 1, 1, names=[names[-1]])
    connection.close()
    assert status == 0 and body.endswith(values[-1])


def test_value_bearing_list_reads_a_native_direct_attribute(attribute_target):
    """Direct native values use the bounded probe/read path and stay byte-exact."""
    endpoint, root, _outside = attribute_target
    value = bytes(range(256)) * 8
    os.setxattr(root / 'present', 'user.U.native-direct', value)
    with _session(endpoint.port) as connection:
        status, body = _fattr(connection, '/present', 2, 0,
                              options=_FATTR_LIST_WITH_DATA)
    assert status == 0
    assert _decode_fattr_list_values(body)['native-direct'] == value


def test_recursive_list_refuses_over_cap_without_partial_success(attribute_target):
    """Recursive enumeration rejects an oversized inventory and keeps the session."""
    endpoint, root, _outside = attribute_target
    bulk = root / 'bulk'
    bulk.mkdir()
    # Keep each native xattr name within the macOS limit as well as Linux's;
    # more entries still force the wire inventory beyond its 256 KiB cap.
    attr_name = 'a' * 100
    for index in range(800):
        name = f'f{index:04d}-' + ('x' * 230)
        target = bulk / name
        target.write_bytes(b'x')
        os.setxattr(target, 'user.U.' + attr_name, b'x')

    with _session(endpoint.port) as connection:
        status, body = _fattr(connection, '/bulk', 2, 0,
                              options=_FATTR_LIST_RECURSE)
        assert status == 4003
        assert struct.unpack('!I', body[:4])[0] == 3002
        status, body = _fattr(connection, '/present', 1, 1,
                              names=['project'])
    assert status == 0 and body.endswith(b'cms')


@pytest.mark.parametrize('path', ['/present', '/inside'])
def test_existing_attribute_remains_byte_exact(attribute_target, path):
    """Success: native metadata is returned with its complete declared value."""
    status, body = _get(attribute_target, path, ['project'])
    assert status == 0
    assert body == b'\0\x01\0\0project\0' + struct.pack('!I', 3) + b'cms'


@pytest.fixture
def ancestor_lock(attribute_target, request):
    """Lease a real root lock and remove exactly that fixture record on exit."""
    _endpoint, root, _outside = attribute_target
    if not request.param:
        yield None
        return
    key = 'user.nginx_xrootd.lock'
    record = (f'v=2|token=opaquelocktoken:ancestor|owner=fixture|'
              f'expires={int(time.time()) + 300}|scope=exclusive|depth=infinity|null=0').encode()
    os.setxattr(root, key, record)
    try:
        yield record
    finally:
        os.removexattr(root, key)


def _unlink_target(endpoint, link_name):
    """Send the repository's kXR_rm layout through the existing raw session."""
    with _session(endpoint.port) as connection:
        path = ('/' + link_name).encode()
        connection.sendall(struct.pack('!2sH16sI', b'\0\x03', 3014, b'\0' * 16, len(path)) + path)
        _sid, status, body = _resp(connection)
    return status, body


def _check_unlink_target_result(link, status, body, record):
    """Namespace removal stays independent of referents but respects ancestors."""
    if record is not None:
        assert status == 4003
        assert b'busy' in body.lower() or b'lock' in body.lower()
        assert link.is_symlink()
        assert os.getxattr(link.parent, 'user.nginx_xrootd.lock') == record
        return
    assert status == 0, (status, body)
    assert not os.path.lexists(link)


@pytest.mark.parametrize('link_name', ['inside', 'escape', 'dangling'])
@pytest.mark.parametrize('ancestor_lock', [False, True], indirect=True)
def test_unlink_checks_ancestors_without_following_link_target(attribute_target, link_name, ancestor_lock):
    """Remove only the link; an ancestor lock still forbids namespace mutation."""
    endpoint, root, outside = attribute_target
    link = root / link_name
    if link_name == 'dangling':
        link.symlink_to(outside.parent / 'missing-sentinel')
    status, body = _unlink_target(endpoint, link_name)
    _check_unlink_target_result(link, status, body, ancestor_lock)
    assert (root / 'present').read_bytes() == b'payload'
    assert outside.read_bytes() == b'outside-sentinel'
    assert os.getxattr(outside, 'user.U.project') == b'private-outside-value'


def test_missing_attribute_retains_its_distinct_status(attribute_target):
    """Error: a missing attribute is not confused with a missing target file."""
    status, body = _get(attribute_target, '/present', ['absent'])
    assert status == 0
    assert body == _error_vector(['absent'], 3027)


@pytest.mark.parametrize('path', ['/present', '/directory'])
def test_attribute_mutations_still_work_on_native_files(attribute_target, path):
    """The confined fd path preserves set, list and delete on ordinary targets."""
    endpoint, _root, _outside = attribute_target
    with _session(endpoint.port) as connection:
        status, body = _fattr(connection, path, 3, 1,
                              names=['new'], values=[b'value'])
        assert status == 0 and body == b'\0\x01\0\0new\0'
        status, body = _fattr(connection, path, 2, 0)
        assert status == 0 and b'new\0' in body and b'project\0' in body
        status, body = _fattr(connection, path, 0, 1, names=['new'])
        assert status == 0 and body == b'\0\x01\0\0new\0'
    status, body = _get(attribute_target, path, ['new'])
    assert status == 0 and body == _error_vector(['new'], 3027)


def test_write_only_target_never_needs_data_read_access(attribute_target):
    """Mutating an attribute does not read, truncate, or require reading the data."""
    endpoint, root, _outside = attribute_target
    target = root / 'present'
    target.chmod(0o200)
    try:
        with _session(endpoint.port) as connection:
            status, body = _fattr(connection, '/present', 3, 1,
                                  names=['new'], values=[b'value'])
            assert status == 0 and body == b'\0\x01\0\0new\0'
        status, body = _get(attribute_target, '/present', ['new'])
        assert status == 0 and body == _error_vector(['new'], 3010)
        target.chmod(0o600)
        assert os.getxattr(target, 'user.U.new') == b'value'
        target.chmod(0o200)
        with _session(endpoint.port) as connection:
            status, body = _fattr(connection, '/present', 0, 1, names=['new'])
            assert status == 0 and body == b'\0\x01\0\0new\0'
    finally:
        target.chmod(0o600)
    assert target.read_bytes() == b'payload'
    status, body = _get(attribute_target, '/present', ['new'])
    assert status == 0 and body == _error_vector(['new'], 3027)


def test_attribute_open_cannot_park_the_worker_on_a_fifo(attribute_target):
    """Opening metadata descriptors stays nonblocking for hostile special files."""
    _endpoint, root, _outside = attribute_target
    os.mkfifo(root / 'pipe', 0o600)
    status, body = _get(attribute_target, '/pipe', ['project'])
    assert status == 0 and body[:2] == b'\x01\x01'
    assert struct.unpack('!H', body[2:4])[0] != 0
    assert body[4:] == b'project\0\0\0\0\0'
    # The fixture has exactly one nginx worker. A blocking FIFO open would
    # also prevent this independent regular-file request from completing.
    assert _get(attribute_target, '/present', ['project']) == (
        0, b'\0\x01\0\0project\0' + struct.pack('!I', 3) + b'cms')


@pytest.mark.parametrize('path', ['/missing', '/directory/missing', '/absent/child'])
@pytest.mark.parametrize('names', [['project'], ['project', 'second']])
def test_missing_file_has_per_attribute_errors(attribute_target, path, names):
    """Missing targets retain the requested vector, not a request-level failure."""
    status, body = _get(attribute_target, path, names)
    assert status == 0
    assert body == _error_vector(names, 3011)
    _endpoint, root, outside = attribute_target
    assert not (root / path.lstrip('/')).exists()
    assert outside.read_bytes() == b'outside-sentinel'


@pytest.mark.parametrize('path', ['/../outside', '/escape', '/escape/missing'])
def test_attribute_targets_cannot_escape_the_export(attribute_target, path):
    """Outside targets carry only authorization errors, never their data."""
    status, body = _get(attribute_target, path, ['project'])
    # A probe can refuse the request first; otherwise the confined attribute
    # open must refuse every slot. Neither envelope may carry successful data.
    if status == 4003:
        assert struct.unpack('!I', body[:4])[0] == 3010
    else:
        assert status == 0 and body == _error_vector(['project'], 3010)
    assert b'private-outside-value' not in body
    _endpoint, _root, outside = attribute_target
    assert outside.read_bytes() == b'outside-sentinel'
    assert os.getxattr(outside, 'user.U.project') == b'private-outside-value'


@pytest.mark.parametrize('path', ['/present', '/missing'])
def test_malformed_attribute_vector_is_still_rejected(attribute_target, path):
    """Malformed names fail the request even when the target does not exist."""
    status, body = _get(attribute_target, path, [''])
    assert status == 4003 and struct.unpack('!I', body[:4])[0] == 3000


@pytest.mark.parametrize('subcode,values', [(0, []), (3, [b'forbidden'])])
def test_attribute_writes_cannot_follow_an_outside_symlink(attribute_target, subcode, values):
    """The same descriptor boundary protects mutations, not only value reads."""
    endpoint, _root, outside = attribute_target
    with _session(endpoint.port) as connection:
        status, body = _fattr(connection, '/escape', subcode, 1,
                              names=['project'], values=values)
    assert status == 0 and body == b'\x01\x01' + struct.pack('!H', 3010) + b'project\0'
    assert outside.read_bytes() == b'outside-sentinel'
    assert os.getxattr(outside, 'user.U.project') == b'private-outside-value'


@pytest.mark.parametrize('path', ['/present', '/missing'])
def test_denied_read_precedes_missing_target_handling(attribute_target, lifecycle, tmp_path, path):
    """Authorization refusals remain request-level errors even on missing files."""
    _endpoint, root, outside = attribute_target
    database = tmp_path / 'authdb'
    database.write_text('u * /allowed rl\n')
    endpoint = lifecycle.start(NginxInstanceSpec(
        name='lc-fattr-denied-target', template='nginx_lc_acc_residual_stream.conf',
        protocol='root', readiness='root', port=free_port(BIND_HOST), data_root=str(root),
        template_values={'DATA_DIR': str(root), 'AUTHDB_PATH': str(database),
                         'EXTRA_DIRECTIVES': ''},
        reason='attribute vector errors cannot bypass read authorization'))
    denied_target = endpoint, root, outside
    status, body = _get(denied_target, path, ['project'])
    assert status == 4003 and struct.unpack('!I', body[:4])[0] == 3010
    status, body = _get(denied_target, '/allowed/missing', ['project'])
    assert status == 0 and body == _error_vector(['project'], 3011)
