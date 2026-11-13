"""Subject maps and identity audit views preserve exact names and caller bounds."""

import json
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def identity_audit(server_native_compile):
    return server_native_compile('identity-audit', 'tests/c/identity_audit_native_test.c',
                                 ['-Wl,--wrap=malloc', '-Wl,--wrap=ngx_pnalloc'])


def invoke(binary, operation, mode, first, second, size):
    result = subprocess.run([str(binary), operation, mode, str(first), second, str(size)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.mark.parametrize('subject', ['alice', 'https://issuer.example/subject', 'account:17'])
@pytest.mark.parametrize('capacity', [0, 1, 5, 6, 256])
def test_map_copies_username_with_documented_bounded_truncation(identity_audit, tmp_path, subject, capacity):
    path = tmp_path / 'map.json'; path.write_text(json.dumps({subject: 'alice'}))
    expected = '0\n' + 'alice'[:capacity - 1] if capacity else '-1\n'
    assert invoke(identity_audit, 'map', 'normal', path, subject, capacity) == expected


@pytest.mark.parametrize('content', ['{', '{}', '{"alice":7}', '{"alice":null}', '[]'])
def test_missing_or_nonstring_mapping_does_not_produce_an_identity(identity_audit, tmp_path, content):
    path = tmp_path / 'map.json'; path.write_text(content)
    assert invoke(identity_audit, 'map', 'normal', path, 'alice', 256) == '-1\n'


@pytest.mark.parametrize('mode,path,subject', [('allocation', 'map.json', 'alice'),
    ('normal', 'absent.json', 'alice'), ('normal', '', 'alice'),
    ('normal', '<null>', 'alice'), ('normal', 'map.json', '<null>')])
def test_unusable_map_or_missing_subject_fails_closed(identity_audit, tmp_path, mode, path, subject):
    (tmp_path / 'map.json').write_text('{"alice":"alice"}')
    selected = tmp_path / path if path.endswith('.json') else path
    assert invoke(identity_audit, 'map', mode, selected, subject, 256) == '-1\n'


@pytest.mark.parametrize('method,label', [(0, 'NONE'), (1, 'GSI'), (2, 'TOKEN'),
    (4, 'SSS'), (8, 'S3KEY'), (16, 'UNIX'), (32, 'KRB5'), (3, 'GSI'), (24, 'S3KEY')])
@pytest.mark.parametrize('dn,subject', [('', ''), ('/CN=Alice', 'subject-17')])
def test_audit_description_uses_exact_identity_and_method_priority(identity_audit, method, label, dn, subject):
    assert invoke(identity_audit, 'describe', 'normal', dn, subject, method) == f'dn={dn} sub={subject} method={label}'


@pytest.mark.parametrize('mode', ['null-pool', 'allocation'])
def test_audit_allocation_failure_has_no_partial_string(identity_audit, mode):
    assert invoke(identity_audit, 'describe', mode, '/CN=Alice', 'subject-17', 2) == ''


def test_absent_identity_is_described_as_unauthenticated(identity_audit):
    assert invoke(identity_audit, 'describe', 'null-id', 'unused', 'unused', 2) == 'dn= sub= method=NONE'
