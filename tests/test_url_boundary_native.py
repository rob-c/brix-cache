"""URL parsers bound host/user/path fields and preserve scheme-specific metadata."""

from pathlib import Path
import subprocess

import pytest

from test_xrd_dispatch_native import compile_client_contract


@pytest.fixture(scope='module')
def url_probe(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    return compile_client_contract(root, tmp_path_factory.mktemp('url-boundary'),
                                   'tests/c/url_boundary_native_test.c')


def invoke(binary, parser, value):
    result = subprocess.run([str(binary), parser, value], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.splitlines()


@pytest.mark.parametrize('scheme', ['root', 'roots', 'xroot', 'xroots'])
@pytest.mark.parametrize('suffix,path,single', [('', '', 0), ('/one', '/one', 1), ('//one', '/one', 0)])
def test_root_scheme_retains_user_port_and_slash_semantics(url_probe, scheme, suffix, path, single):
    assert invoke(url_probe, 'url', scheme + '://alice@origin.invalid:1245' + suffix) == (
        ['0', 'origin.invalid', '1245', path, 'alice', str(single)])


@pytest.mark.parametrize('scheme,tls,s3,port', [('http', 0, 0, 80), ('https', 1, 0, 443),
    ('dav', 0, 0, 80), ('davs', 1, 0, 443), ('s3', 0, 1, 80), ('s3s', 1, 1, 443)])
@pytest.mark.parametrize('host,expected', [('origin.invalid', 'origin.invalid'), ('[::1]', '::1')])  # net-literal-allow: parser input and expected IPv6 bracket removal
def test_web_scheme_preserves_ipv6_and_security_flags(url_probe, scheme, tls, s3, port, host, expected):
    assert invoke(url_probe, 'web', scheme + '://' + host) == (
        ['0', expected, str(port), '/', str(tls), str(s3)])


@pytest.mark.parametrize('scheme,gsi,port', [('ftp', 0, 21), ('gsiftp', 1, 2811)])
@pytest.mark.parametrize('suffix,path', [('', '/'), ('//one', '/one'), ('/one', '/one')])
def test_ftp_scheme_preserves_gsi_and_normalized_path(url_probe, scheme, gsi, port, suffix, path):
    assert invoke(url_probe, 'ftp', scheme + '://origin.invalid' + suffix) == (
        ['0', 'origin.invalid', str(port), path, str(gsi)])


@pytest.mark.parametrize('parser,value', [('url', ''), ('url', '<null>'),
    ('url', 'unknown://host'), ('url', 'root://'), ('url', 'root://[unfinished'),
    ('endpoint', ''), ('endpoint', ':1'), ('endpoint', 'host:0'),
    ('endpoint', 'host:65536'), ('endpoint', 'file:///tmp/value'),
    ('web', '<null>'), ('web-null', 'https://host'), ('web', 'root://host'),
    ('web', 'http://[]'), ('web', 'http://[unfinished'), ('web', 'http://:80'),
    ('web', 'http://host:0'), ('web', 'http://host:65536'),
    ('ftp', '<null>'), ('ftp-null', 'ftp://host'), ('ftp', 'https://host'),
    ('ftp', 'ftp://'), ('ftp', 'ftp://host:65536')])
def test_invalid_or_missing_url_parts_are_rejected(url_probe, parser, value):
    assert invoke(url_probe, parser, value)[0] == '-1'


@pytest.mark.parametrize('parser,prefix', [('url', 'root://'), ('endpoint', ''),
                                         ('web', 'http://'), ('ftp', 'gsiftp://')])
def test_oversized_host_is_rejected_without_truncation(url_probe, parser, prefix):
    assert invoke(url_probe, parser, prefix + 'x' * 1024)[0] == '-1'


@pytest.mark.parametrize('parser,prefix', [('url', 'root://host/'), ('url', 'file://'),
    ('url', ''), ('web', 'https://host/'), ('ftp', 'gsiftp://host/')])
def test_oversized_path_is_rejected_without_truncation(url_probe, parser, prefix):
    assert invoke(url_probe, parser, prefix + 'x' * 32768)[0] == '-1'


def test_root_user_truncation_retains_nul_and_complete_host(url_probe):
    user_capacity = int(invoke(url_probe, 'sizes', '')[0].split()[2])
    user = 'u' * (user_capacity + 10)
    fields = invoke(url_probe, 'url', 'root://' + user + '@origin.invalid')
    assert fields == ['0', 'origin.invalid', '1094', '', user[:user_capacity - 1], '0']


@pytest.mark.parametrize('value,expected', [('<null>', '0 0 0'), ('https://host', '1 0 0'),
    ('gsiftp://host', '0 1 0'), ('block://disk', '0 0 1'), ('/dev/disk', '0 0 1'),
    ('root://host', '0 0 0')])
def test_classification_does_not_confuse_transport_families(url_probe, value, expected):
    assert invoke(url_probe, 'classify', value) == [expected]
