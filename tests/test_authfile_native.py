"""Authorization database parsing is atomic and grants only matching identities."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def authfile_binary(server_native_compile):
    return server_native_compile('authfile-native', 'tests/c/authfile_native_test.c',
                                 ['-Wl,--wrap=ngx_pnalloc'])


def authorize(binary, root, text, *, identity=('alice', 'worker.site.test', '-', '-', '-'),
              path='/data/item', space='', decode=False, missing=False, fail_at=0):
    database = root / 'authdb'
    if not missing:
        database.write_text(text)
    result = subprocess.run([str(binary), str(database), space, str(int(decode)),
                             *identity, path, str(fail_at)], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    status, privileges, count = map(int, result.stdout.split())
    return None if status == -1 else (privileges, count)


@pytest.mark.parametrize('record,identity', [
    ('u alice', ('alice', '-', '-', '-', '-')),
    ('g team', ('alice', '-', '-', '-', 'team')),
    ('o org', ('alice', '-', 'org', '-', '-')),
    ('r production', ('alice', '-', '-', 'production', '-')),
    ('h worker.site.test', ('alice', 'worker.site.test', '-', '-', '-')),
    ('h .site.test', ('alice', 'worker.site.test', '-', '-', '-')),
    ('u *', ('*', '-', '-', '-', '-')),
])
def test_named_categories_match_the_right_identity(authfile_binary, tmp_path,
                                                   record, identity):
    rule = record + ' /data rl\n'
    assert authorize(authfile_binary, tmp_path, rule, identity=identity) == (40, 1)
    assert authorize(authfile_binary, tmp_path, rule, identity=identity,
                     path='/private/item') == (0, 1)


@pytest.mark.parametrize('privileges,bits', [('a', 511), ('d', 1), ('i', 2), ('k', 4),
    ('l', 8), ('n', 16), ('r', 32), ('w', 64), ('rl-w', 40), ('a-rw', 415)])
def test_privilege_grants_and_denials_survive_parse(authfile_binary, tmp_path,
                                                 privileges, bits):
    assert authorize(authfile_binary, tmp_path,
                      f'u alice /data {privileges}\n') == (bits, 1)


@pytest.mark.parametrize('path,expected', [('/private/item', 0), ('/data/item', 32),
                                        ('///private/item', 0), ('private/item', 0)])
def test_first_matching_prefix_and_canonical_denial(authfile_binary, tmp_path,
                                                 path, expected):
    text = 'u alice /private -a / r\n'
    assert authorize(authfile_binary, tmp_path, text, path=path) == (expected, 1)


@pytest.mark.parametrize('path,expected', [('/users/alice/file', 32),
    ('/users/bob/file', 0), ('/users/alice', 0), ('/different/alice/file', 0)])
def test_fungible_template_substitutes_only_authenticated_name(authfile_binary,
                                                              tmp_path, path, expected):
    assert authorize(authfile_binary, tmp_path, 't home /users/@=/ r\nu = home\n',
                      path=path) == (expected, 2)


@pytest.mark.parametrize('index', range(5))
@pytest.mark.parametrize('rule_kind', ['s', 'x'])
def test_compound_identity_requires_every_selector(authfile_binary, tmp_path,
                                                  index, rule_kind):
    identity = ['alice', 'worker.site.test', 'org', 'role', 'team']
    text = '= job u alice h .site.test o org r role g team\n' + rule_kind + ' job /data rw\n'
    assert authorize(authfile_binary, tmp_path, text, identity=identity) == (96, 2)
    identity[index] = 'unrelated'
    assert authorize(authfile_binary, tmp_path, text, identity=identity) == (0, 2)


def test_exclusive_rule_order_and_unused_definition(authfile_binary, tmp_path):
    text = ('= unused u nobody\n= first u alice\n= second u alice\n'
            'x first /data r\nx second /data a\nu alice /data a\n')
    assert authorize(authfile_binary, tmp_path, text) == (32, 6)


def test_inclusive_rules_combine_grants_with_denials(authfile_binary, tmp_path):
    text = ('= first u alice\n= second h worker.site.test\n'
            's first /data rw\ns second /data l-w\n')
    assert authorize(authfile_binary, tmp_path, text) == (40, 4)


@pytest.mark.parametrize('path,decode,expected', [('/data with space/item', True, 32),
    ('/data with space/item', False, 0), ('/data%20with%20space/item', False, 32),
    ('/data%20with%20space/item', True, 0)])
def test_uri_decoding_is_an_explicit_parser_setting(authfile_binary, tmp_path,
                                                   path, decode, expected):
    assert authorize(authfile_binary, tmp_path, 'u alice /data%20with%20space r\n',
                      path=path, decode=decode) == (expected, 1)


@pytest.mark.parametrize('path', ['/data%', '/data%2', '/data%GG'])
def test_malformed_percent_escapes_stay_literal(authfile_binary, tmp_path, path):
    assert authorize(authfile_binary, tmp_path, f'u alice {path} r\n',
                      path=path + '/item', decode=True) == (32, 1)


@pytest.mark.parametrize('rule', ['u Alice_Smith /data r\n',
                                '= person u Alice_Smith\ns person /data r\n'])
def test_spacechar_applies_to_user_selectors(authfile_binary, tmp_path, rule):
    identity = ('Alice Smith', '-', '-', '-', '-')
    count = len(rule.splitlines())
    assert authorize(authfile_binary, tmp_path, rule, identity=identity,
                      space='_') == (32, count)
    assert authorize(authfile_binary, tmp_path, rule, identity=identity) == (0, count)


@pytest.mark.parametrize('ending', ['\n', '\r\n'])
def test_comments_continuations_and_eof_record(authfile_binary, tmp_path, ending):
    text = '# comment' + ending + 'u alice \\' + ending + '\t/data r # trailing'
    assert authorize(authfile_binary, tmp_path, text) == (32, 1)


@pytest.mark.parametrize('record', ['g team', 'h host', 'h .site.test', 'n netgroup',
    'o org', 'r role', 't template', 'u alice', 'u *', 'u ='])
def test_duplicate_named_records_reject_entire_generation(authfile_binary, tmp_path,
                                                         record):
    text = record + ' /data r\n' + record + ' /private a\n'
    assert authorize(authfile_binary, tmp_path, text) is None


@pytest.mark.parametrize('selector', ['u', 'g', 'h', 'o', 'r'])
def test_duplicate_compound_selector_is_rejected(authfile_binary, tmp_path, selector):
    text = f'= job {selector} first {selector} second\ns job /data a\n'
    assert authorize(authfile_binary, tmp_path, text) is None


@pytest.mark.parametrize('text', [
    'uu alice /data r\n', 'q alice /data r\n', 'u\n', 'u alice\n',
    'u alice /data\n', 'u alice /data q\n', 'u alice /data r--w\n',
    'u alice \\ r\n', 'u alice missing-template\n',
    '= job u\n', '= job\n', '= job unknown value\n', '= job z value\n',
    '= job u alice\n= job u bob\n', 's missing /data r\n', 'x missing /data r\n',
    '= job u alice\ns job /data r\nx job /data a\n',
    '= job u alice\ns job\n',
])
def test_malformed_records_never_publish_a_partial_generation(authfile_binary,
                                                             tmp_path, text):
    assert authorize(authfile_binary, tmp_path, 'u * /data r\n' + text) is None


@pytest.mark.parametrize('text', ['', '# comment only\n', '\n\r\n\t'])
def test_empty_database_is_valid_and_denies_everything(authfile_binary, tmp_path, text):
    assert authorize(authfile_binary, tmp_path, text) == (0, 0)


def test_missing_database_is_a_load_failure(authfile_binary, tmp_path):
    assert authorize(authfile_binary, tmp_path, '', missing=True) is None


def test_oversized_database_is_not_read_as_rules(authfile_binary, tmp_path):
    assert authorize(authfile_binary, tmp_path, '#' * (1024 * 1024 + 1)) is None


@pytest.mark.parametrize('fail_at', range(1, 11))
def test_allocation_failure_cannot_hide_a_later_invalid_rule(authfile_binary,
                                                           tmp_path, fail_at):
    text = 'u * /data r\nu * /data -r\n'
    assert authorize(authfile_binary, tmp_path, text, fail_at=fail_at) is None


@pytest.mark.parametrize('fail_at', range(11))
def test_allocation_failure_cannot_drop_a_later_deny(authfile_binary, tmp_path, fail_at):
    text = 'u alice /data r\ng team /data -r\n'
    decision = authorize(authfile_binary, tmp_path, text,
                         identity=('alice', '-', '-', '-', 'team'), fail_at=fail_at)
    assert decision in (None, (0, 2))
