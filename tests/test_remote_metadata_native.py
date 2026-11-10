"""Remote metadata changes preserve fields and caller identity across failures."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def remote_metadata(server_native_compile):
    seams = ('open_read', 'close', 'get_meta', 'list_meta', 'set_meta', 'size', 'prefix_exists',
             'open_write', 'commit', 'abort', 'copy', 'delete', 'list_page')
    return server_native_compile('remote-metadata', 'tests/c/remote_metadata_native_test.c',
                                 [f'-Wl,--wrap=sd_s3_{name}' for name in seams])


def invoke(binary, action='set', fault='normal', identity='plain', name='user.color0',
           value='red', capacity=4096, flags='none'):
    result = subprocess.run([str(binary), action, fault, identity, name, value,
                             str(capacity), flags], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    fields, pairs = {}, {}
    for line in result.stdout.splitlines():
        key, value = line.split('=', 1)
        if key == 'pair':
            name, content = value.split(':', 1)
            assert name not in pairs
            pairs[name] = content
        else:
            fields[key] = value if key in ('hex', 'store-key') else int(value)
    return fields, pairs


@pytest.mark.parametrize('identity', ['plain', 'user', 'fallback'])
@pytest.mark.parametrize('action,name,pairs', [
    ('set', 'user.color0', {'color0': 'red'}),
    ('set', 'user.NEW', {'color0': 'blue', 'new': 'red'}),
    ('remove', 'user.color0', {}),
])
def test_metadata_rewrite_preserves_unrelated_fields_and_signing_identity(
        remote_metadata, identity, action, name, pairs):
    result, actual = invoke(remote_metadata, action, 'advisory', identity, name)
    assert result['rc'] == 0 and result['opens'] == result['closes'] == result['stores'] == 1
    assert result['store-key'] == '/bucket/object'
    assert actual == {**pairs, 'xrd-unixattr': 'v1 mode=0640 uid=123 gid=456'}


@pytest.mark.parametrize('identity', ['plain', 'user', 'fallback'])
@pytest.mark.parametrize('fault,opens,key', [('normal', 1, '/bucket/object'),
    ('marker', 2, '/bucket/object/'), ('advisory', 1, '/bucket/object')])
def test_chmod_retains_metadata_and_uses_directory_marker_only_after_absence(
        remote_metadata, identity, fault, opens, key):
    result, pairs = invoke(remote_metadata, 'chmod', fault, identity)
    assert result['rc'] == 0 and result['opens'] == result['closes'] == opens
    assert result['stores'] == 1 and result['store-key'] == key
    assert pairs['color0'] == 'blue' and 'mode=0600' in pairs['xrd-unixattr']
    if fault == 'advisory':
        assert 'uid=123' in pairs['xrd-unixattr'] and 'gid=456' in pairs['xrd-unixattr']


@pytest.mark.parametrize('action', ['get', 'list', 'set', 'remove', 'chmod', 'stat', 'mkdir', 'rename', 'unlink', 'copy'])
def test_denied_identity_never_uses_service_keys(remote_metadata, action):
    result, pairs = invoke(remote_metadata, action, identity='deny', name='/object')
    assert result['rc'] == -1 and result['errno'] == errno.EACCES
    assert result['opens'] == result['stores'] == result['prefixes'] == 0 and pairs == {}
    assert result['copies'] == result['deletes'] == result['writes'] == 0


@pytest.mark.parametrize('action', ['set', 'remove', 'chmod'])
@pytest.mark.parametrize('fault,error,closed', [
    ('open', errno.ENOMEM, 0), ('list', errno.EIO, 1), ('list-deny', errno.EACCES, 1),
    ('list-unsupported', errno.ENOTSUP, 1), ('get', errno.EIO, 1),
    ('get-deny', errno.EIO, 1), ('advisory-error', errno.EIO, 1),
    ('overfull', errno.E2BIG, 1), ('full-advisory', errno.E2BIG, 1),
    ('long-existing', errno.ERANGE, 1),
])
def test_incomplete_metadata_read_prevents_every_rewrite(remote_metadata, action, fault, error, closed):
    result, pairs = invoke(remote_metadata, action, fault, 'user')
    assert result['rc'] == -1 and result['errno'] == error
    assert result['opens'] == 1 and result['closes'] == closed
    assert result['stores'] == 0 and pairs == {}


@pytest.mark.parametrize('action', ['set', 'remove', 'chmod'])
@pytest.mark.parametrize('fault,error', [('store', errno.EIO), ('store-deny', errno.EACCES)])
def test_rewrite_failure_remains_visible_without_retry(remote_metadata, action, fault, error):
    result, _pairs = invoke(remote_metadata, action, fault)
    assert result['rc'] == -1 and result['errno'] == error
    assert result['opens'] == result['closes'] == result['stores'] == 1


@pytest.mark.parametrize('action,name,flags,error', [
    ('set', 'user.color0', 'create', errno.EEXIST),
    ('set', 'user.missing', 'replace', errno.ENODATA),
    ('remove', 'user.missing', 'none', errno.ENODATA),
])
def test_create_replace_and_remove_preconditions_cannot_drop_existing_metadata(
        remote_metadata, action, name, flags, error):
    result, pairs = invoke(remote_metadata, action, name=name, flags=flags)
    assert result['rc'] == -1 and result['errno'] == error
    assert result['stores'] == 0 and result['closes'] == 1 and pairs == {}


@pytest.mark.parametrize('action', ['set', 'remove'])
@pytest.mark.parametrize('name,error', [('system.secret', errno.ENOTSUP), ('user.', errno.ENOTSUP),
    ('user.' + 'a' * 160, errno.ERANGE)])
def test_unrepresentable_names_are_refused_before_origin_io(remote_metadata, action, name, error):
    result, _pairs = invoke(remote_metadata, action, name=name)
    assert result['rc'] == -1 and result['errno'] == error and result['opens'] == 0


@pytest.mark.parametrize('value,fault,error', [('a' * 2048, 'normal', errno.E2BIG),
    ('a\rb', 'normal', errno.ENOTSUP), ('a\nb', 'normal', errno.ENOTSUP),
    ('unused', 'binary', errno.ENOTSUP)])
def test_binary_and_header_injection_values_never_reach_origin(remote_metadata, value, fault, error):
    result, _pairs = invoke(remote_metadata, fault=fault, value=value)
    assert result['rc'] == -1 and result['errno'] == error and result['opens'] == 0


@pytest.mark.parametrize('action', ['set', 'chmod'])
def test_full_metadata_set_cannot_silently_discard_an_existing_attribute(remote_metadata, action):
    result, pairs = invoke(remote_metadata, action, 'full', name='user.extra')
    assert result['rc'] == -1 and result['errno'] == errno.E2BIG
    assert result['stores'] == 0 and pairs == {}


def test_non_user_names_in_listing_do_not_become_writable_headers(remote_metadata):
    result, pairs = invoke(remote_metadata, fault='ignored-names')
    assert result['rc'] == 0 and pairs == {'color0': 'red'}


def test_no_representable_chmod_fields_avoids_origin_requests(remote_metadata):
    result, pairs = invoke(remote_metadata, 'chmod', 'noop')
    assert result['rc'] == 0 and result['opens'] == result['stores'] == 0 and pairs == {}


@pytest.mark.parametrize('identity', ['plain', 'user', 'fallback'])
@pytest.mark.parametrize('action,count,payload', [('get', 4, b'blue'), ('list', 12, b'user.color0\0')])
@pytest.mark.parametrize('capacity', [-1, 0, 4096])
def test_metadata_reads_support_exact_bytes_and_size_probes(remote_metadata, identity, action, count, payload, capacity):
    result, _pairs = invoke(remote_metadata, action, identity=identity, capacity=capacity)
    assert result['rc'] == count and result['opens'] == result['closes'] == 1
    if capacity > 0:
        assert bytes.fromhex(result['hex']) == payload


@pytest.mark.parametrize('action,fault,error,closed', [
    ('get', 'open', errno.ENOMEM, 0), ('list', 'open', errno.ENOMEM, 0),
    ('get', 'get', errno.EIO, 1), ('get', 'get-deny', errno.EACCES, 1),
    ('get', 'absent', errno.ENODATA, 1), ('list', 'list', errno.EIO, 1),
    ('list', 'list-deny', errno.EACCES, 1), ('list', 'list-unsupported', errno.ENOTSUP, 1),
])
def test_read_errors_preserve_denial_and_release_handles(remote_metadata, action, fault, error, closed):
    result, _pairs = invoke(remote_metadata, action, fault)
    assert result['rc'] == -1 and result['errno'] == error and result['closes'] == closed


@pytest.mark.parametrize('action', ['get', 'list'])
def test_short_read_buffer_returns_range_error_without_partial_value(remote_metadata, action):
    result, _pairs = invoke(remote_metadata, action, capacity=2)
    assert result['rc'] == -1 and result['errno'] == errno.ERANGE and 'hex' not in result


@pytest.mark.parametrize('name', ['system.secret', 'user.'])
def test_non_user_xattr_read_is_absent_without_origin_access(remote_metadata, name):
    result, _pairs = invoke(remote_metadata, 'get', name=name)
    assert result['rc'] == -1 and result['errno'] == errno.ENODATA and result['opens'] == 0


@pytest.mark.parametrize('identity', ['plain', 'user', 'fallback'])
@pytest.mark.parametrize('fault,heads,prefixes,directory,size', [
    ('normal', 1, 0, 0, 1234), ('marker', 2, 0, 1, 0), ('implicit', 2, 1, 1, 0)])
def test_stat_distinguishes_objects_markers_and_implicit_directories(
        remote_metadata, identity, fault, heads, prefixes, directory, size):
    result, _pairs = invoke(remote_metadata, 'stat', fault, identity, name='/object')
    assert result['rc'] == 0 and result['dir'] == directory and result['reg'] == 1 - directory
    assert result['heads'] == result['closes'] == heads and result['prefixes'] == prefixes
    assert result['size'] == size


@pytest.mark.parametrize('name', ['NULL', '', '/'])
def test_export_root_stat_is_synthetic(remote_metadata, name):
    result, _pairs = invoke(remote_metadata, 'stat', name=name)
    assert result['rc'] == 0 and result['dir'] == 1 and result['opens'] == 0


@pytest.mark.parametrize('fault,error,heads,prefixes', [
    ('open', errno.ENOMEM, 0, 0), ('open-deny', errno.EACCES, 0, 0),
    ('head', errno.EIO, 1, 0), ('head-deny', errno.EACCES, 1, 0),
    ('marker-deny', errno.EACCES, 2, 0), ('prefix', errno.EIO, 2, 1),
    ('prefix-deny', errno.EACCES, 2, 1), ('missing', errno.ENOENT, 2, 1),
])
def test_stat_only_falls_back_after_authoritative_absence(remote_metadata, fault, error, heads, prefixes):
    result, _pairs = invoke(remote_metadata, 'stat', fault, name='/object')
    assert result['rc'] == -1 and result['errno'] == error
    assert result['heads'] == heads and result['prefixes'] == prefixes
    assert result['dir'] == result['reg'] == 0


@pytest.mark.parametrize('identity', ['plain', 'user', 'fallback'])
def test_mkdir_only_creates_a_zero_byte_marker_after_complete_absence(remote_metadata, identity):
    result, _pairs = invoke(remote_metadata, 'mkdir', 'missing', identity)
    assert result['rc'] == 0 and result['heads'] == 2 and result['prefixes'] == 1
    assert result['writes'] == result['commits'] == 1 and result['closes'] == 3
    assert result['aborts'] == 0


@pytest.mark.parametrize('fault,error,writes,commits,aborts', [
    ('normal', errno.EEXIST, 0, 0, 0), ('head-deny', errno.EACCES, 0, 0, 0),
    ('write-open', errno.EIO, 1, 0, 0), ('commit', errno.EIO, 1, 1, 1)])
def test_mkdir_failure_does_not_publish_or_leak_marker_handles(remote_metadata, fault, error, writes, commits, aborts):
    result, _pairs = invoke(remote_metadata, 'mkdir', fault)
    assert result['rc'] == -1 and result['errno'] == error
    assert (result['writes'], result['commits'], result['aborts']) == (writes, commits, aborts)


@pytest.mark.parametrize('identity', ['plain', 'user', 'fallback'])
@pytest.mark.parametrize('fault', ['normal', 'marker'])
def test_rename_file_or_empty_marker_keeps_identity_on_every_leg(remote_metadata, identity, fault):
    result, _pairs = invoke(remote_metadata, 'rename', fault, identity)
    assert result['rc'] == 0 and result['copies'] == result['deletes'] == 1
    assert result['opens'] == result['closes']


@pytest.mark.parametrize('fault,error,copies,deletes', [
    ('copy', errno.EIO, 1, 0), ('copy-deny', errno.EACCES, 1, 0),
    ('delete', errno.EIO, 1, 1), ('delete-deny', errno.EACCES, 1, 1),
    ('children', errno.ENOTSUP, 0, 0), ('children-error', errno.EIO, 0, 0),
    ('children-deny', errno.EACCES, 0, 0), ('missing', errno.ENOENT, 0, 0),
    ('head-deny', errno.EACCES, 0, 0)])
def test_rename_never_deletes_source_after_failed_copy_or_namespace_probe(remote_metadata, fault, error, copies, deletes):
    result, _pairs = invoke(remote_metadata, 'rename', fault, 'user')
    assert result['rc'] == -1 and result['errno'] == error
    assert result['copies'] == copies and result['deletes'] == deletes


@pytest.mark.parametrize('fault,error', [('normal', errno.EEXIST), ('head-deny', errno.EACCES)])
def test_exclusive_rename_refuses_existing_or_denied_destination(remote_metadata, fault, error):
    result, _pairs = invoke(remote_metadata, 'rename', fault, flags='create')
    assert result['rc'] == -1 and result['errno'] == error and result['copies'] == result['deletes'] == 0


@pytest.mark.parametrize('identity', ['plain', 'user', 'fallback'])
@pytest.mark.parametrize('flags', ['none', 'create'])
def test_unlink_uses_one_identity_scoped_object_or_marker_delete(remote_metadata, identity, flags):
    result, _pairs = invoke(remote_metadata, 'unlink', identity=identity, flags=flags)
    assert result['rc'] == 0 and result['deletes'] == 1 and result['opens'] == 0


@pytest.mark.parametrize('fault,error', [('delete', errno.EIO), ('delete-deny', errno.EACCES)])
def test_unlink_preserves_origin_denial_and_missing_errno_fallback(remote_metadata, fault, error):
    result, _pairs = invoke(remote_metadata, 'unlink', fault)
    assert result['rc'] == -1 and result['errno'] == error and result['deletes'] == 1


@pytest.mark.parametrize('identity', ['plain', 'user', 'fallback'])
@pytest.mark.parametrize('fault,bytes', [('normal', 1234), ('head-deny', 0)])
def test_copy_size_probe_uses_same_identity_and_does_not_undo_successful_copy(remote_metadata, identity, fault, bytes):
    result, _pairs = invoke(remote_metadata, 'copy', fault, identity)
    assert result['rc'] == 0 and result['bytes'] == bytes and result['copies'] == 1
    assert result['deletes'] == 0 and result['opens'] == result['closes'] == 1
