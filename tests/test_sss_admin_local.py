"""Exercise keytab administration using disposable, permission-checked files."""

import os
from pathlib import Path
import re
import stat
import subprocess
import time

import pytest

from brix_suite.client_build import client_snapshot


@pytest.fixture(scope='module')
def admin_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    binary = root / 'client/bin/xrdsssadmin-brix'
    return client_snapshot(root / 'client', binary,
                           tmp_path_factory.mktemp('sss-admin') / binary.name)


@pytest.fixture
def admin(admin_binary, tmp_path):
    keytab = tmp_path / 'keys'
    def invoke(*arguments, defaults=False, aliases=None):
        environment = dict(os.environ)
        for name in ('XRDC_SSS_KEYTAB', 'XrdSecSSSKT', 'XrdSecsssKT'):
            environment.pop(name, None)
        environment.update(aliases or {})
        options = [] if defaults else ['--keytab', str(keytab)]
        return subprocess.run([str(admin_binary), *options, *arguments],
            env=environment, capture_output=True, text=True, timeout=10)
    return invoke, keytab


def key_line(identifier, expiry=0):
    return f'0 u:fixture g:test N:{identifier} k:{"ab" * 32} n:fixture e:{expiry}\n'


def write_keys(path, text):
    path.write_text(text)
    path.chmod(0o600)


def test_add_defaults_follow_largest_id_and_keep_private_permissions(admin):
    invoke, path = admin
    write_keys(path, key_line(8) + key_line(2))
    result = invoke('add')
    assert result.returncode == 0 and 'added key id=9 (32-byte)' in result.stdout
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    listing = invoke('list')
    assert listing.returncode == 0 and '3 key(s)' in listing.stdout
    assert 'user=anybody' in listing.stdout and 'group=anygroup' in listing.stdout
    assert 'ab' * 32 not in listing.stdout


@pytest.mark.parametrize('length,expected', [(16, 16), (128, 128), (0, 32), (129, 32), (-1, 32)])
def test_install_key_fields_length_and_expiry(admin, length, expected):
    invoke, path = admin
    before = int(time.time())
    result = invoke('install', '--id', '17', '--user', 'alice', '--group', 'analysis',
                    '--name', 'node', '--keylen', str(length), '--lifetime', '2')
    assert result.returncode == 0, result.stderr
    listing = invoke('list')
    assert listing.returncode == 0
    assert all(value in listing.stdout for value in ('id=17', 'user=alice', 'group=analysis',
                                                    'name=node', f'keylen={expected}'))
    expiry = int(re.search(r'exp=(\d+)', listing.stdout)[1])
    assert before + 172800 <= expiry <= int(time.time()) + 172800
    key = re.search(r' k:([0-9a-fA-F]+)', path.read_text())[1]
    assert len(key) == 2 * expected and key not in listing.stdout + listing.stderr


def test_delete_removes_all_matching_ids_and_preserves_other_entries(admin):
    invoke, path = admin
    write_keys(path, key_line(3) + key_line(5) + key_line(3) + key_line(8))
    result = invoke('del', '--id', '3')
    assert result.returncode == 0 and 'removed 2 key(s)' in result.stdout
    assert path.read_text() == key_line(5).replace(' e:0', '') + key_line(8).replace(' e:0', '')
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize('arguments', [('del',), ('del', '--id', '-1'), ('del', '--id', '99')])
def test_delete_refusals_leave_keytab_unchanged(admin, arguments):
    invoke, path = admin
    write_keys(path, key_line(7))
    before = path.read_bytes()
    result = invoke(*arguments)
    assert result.returncode == 1 and path.read_bytes() == before


def test_full_keytab_cannot_be_overwritten_by_add(admin):
    invoke, path = admin
    write_keys(path, ''.join(key_line(index) for index in range(64)))
    before = path.read_bytes()
    result = invoke('add')
    assert result.returncode == 1 and 'keytab full' in result.stderr
    assert path.read_bytes() == before


def unsafe_keytab(path, target, kind):
    if kind == 'symlink':
        path.symlink_to(target)
    elif kind == 'directory':
        path.mkdir()
    else:
        write_keys(path, key_line(7) if kind == 'public-mode' else '0 N:7 k:not-hex\n')
        if kind == 'public-mode':
            path.chmod(0o644)


@pytest.mark.parametrize('command', [('list',), ('add',), ('del', '--id', '7')])
@pytest.mark.parametrize('kind', ['symlink', 'public-mode', 'directory', 'malformed'])
def test_unsafe_keytab_is_refused_without_mutation(admin, tmp_path, command, kind):
    invoke, path = admin
    target = tmp_path / 'target'
    write_keys(target, key_line(7))
    unsafe_keytab(path, target, kind)
    before = target.read_bytes()
    result = invoke(*command)
    assert result.returncode == 1 and result.stdout == ''
    assert target.read_bytes() == before


@pytest.mark.parametrize('name', ['XRDC_SSS_KEYTAB', 'XrdSecSSSKT', 'XrdSecsssKT'])
def test_default_alias_points_to_explicit_temporary_keytab(admin, name):
    invoke, path = admin
    result = invoke('install', defaults=True, aliases={name: str(path)})
    assert result.returncode == 0 and path.is_file()


def test_canonical_alias_takes_precedence(admin, tmp_path):
    invoke, path = admin
    other = tmp_path / 'untouched'
    result = invoke('install', defaults=True,
                    aliases={'XRDC_SSS_KEYTAB': str(path), 'XrdSecSSSKT': str(other)})
    assert result.returncode == 0 and path.is_file() and not other.exists()


def test_expired_keys_and_comments_are_omitted_from_listing(admin):
    invoke, path = admin
    write_keys(path, '# fixture\n\n' + key_line(2, 1) + key_line(4))
    result = invoke('list')
    assert result.returncode == 0 and '1 key(s)' in result.stdout
    assert 'id=4' in result.stdout and 'id=2' not in result.stdout


@pytest.mark.parametrize('arguments', [(), ('unknown',), ('add', 'extra'), ('--keylen',),
                                     ('--user',), ('--id',), ('--unknown',)])
def test_usage_errors_never_create_keytab(admin, arguments):
    invoke, path = admin
    result = invoke(*arguments)
    assert result.returncode == 2 and not path.exists()
