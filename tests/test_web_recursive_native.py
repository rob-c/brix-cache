"""Recursive web copies preserve tree shape and reject unsafe listed paths."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def recursive_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('web-recursive-native')
    return compile_client_contract(root, output, 'tests/c/web_recursive_native_test.c',
        ('brix_webdav_list', 'brix_s3_list', 'brix_webdav_mkcol', 'copy_web_leaf_retry'))


@pytest.fixture
def recursive_run(recursive_binary, tmp_path):
    def run(paths, source='https://source.test/tree/', destination=None,
            mode='normal', expected=0, fault=''):
        listing = tmp_path / 'listing'
        listing.write_text(''.join(path + '\n' for path in paths))
        environment = dict(os.environ, BRIX_COPY_LIST=str(listing), BRIX_COPY_FAULT=fault,
            BEARER_TOKEN='environment-token', AWS_ACCESS_KEY_ID='environment-access',
            AWS_SECRET_ACCESS_KEY='environment-secret', AWS_DEFAULT_REGION='environment-region',
            X509_USER_PROXY=str(tmp_path / 'no-proxy'))
        result = subprocess.run([str(recursive_binary), source,
            str(destination or tmp_path / 'destination'), mode, str(expected)],
            env=environment, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout
    return run


def source_paths(scheme):
    if scheme.startswith('s3'):
        return 'tree/child/file', '/bucket/tree/'
    return '/tree/child/file', '/tree/'


@pytest.mark.parametrize('scheme', ['http', 'https', 'dav', 'davs', 's3', 's3s'])
def test_preserves_nested_tree(recursive_run, tmp_path, scheme):
    remote, prefix = source_paths(scheme)
    output = recursive_run([remote], source=scheme + '://source.test' + prefix)
    data = (tmp_path / 'destination/child/file').read_text()
    assert data.startswith(scheme + '://source.test:') and data.endswith(remote)
    assert output.count('COPY ') == 1


@pytest.mark.parametrize('source,paths', [
    ('https://source.test/tree/', ['/tree', '/unrelated/nested/file/']),
    ('s3://source.test/bucket/tree///', ['tree', 'different/file/']),
    ('s3://source.test/bucket', ['one/two/file']),
])
def test_prefix_self_and_outside_prefix_fallback(recursive_run, tmp_path, source, paths):
    output = recursive_run(paths, source=source)
    assert output.count('COPY ') == 1
    assert len(list((tmp_path / 'destination').rglob('file'))) == 1


@pytest.mark.parametrize('source,prefix', [
    ('https://source.test/tree', '/tree/'), ('s3://source.test/bucket/tree', 'tree/'),
])
@pytest.mark.parametrize('relative', ['../escape', 'nested/../../escape', '/escape'])
def test_untrusted_listing_cannot_escape_destination(recursive_run, tmp_path, source, prefix, relative):
    output = recursive_run([prefix + relative], source=source, expected=-1)
    assert 'COPY ' not in output and 'RESULT -1' in output
    assert not (tmp_path / 'escape').exists()


@pytest.mark.parametrize('mode', ['dry', 'normal'])
def test_filters_and_dry_run_precede_destination_creation(recursive_run, tmp_path, mode):
    paths = ['/tree/secret.omit'] if mode == 'normal' else ['/tree/nested/kept']
    output = recursive_run(paths, mode=mode, destination='https://dest.test/new/base')
    assert 'COPY ' not in output
    assert not (tmp_path / 'destination').exists()
    if mode == 'dry':
        assert 'MKCOL ' not in output and '[dry-run] copy ' in output


@pytest.mark.parametrize('destination,collections', [
    ('https://dest.test/new/base///', ['/new/base', '/new/base/child', '/new/base/child/sub']),
    ('s3://dest.test/bucket/prefix/', []),
])
def test_web_destination_builds_parents_in_order(recursive_run, destination, collections):
    output = recursive_run(['/tree/child/sub/file'], destination=destination, mode='credentials')
    actual = [line.split()[1] for line in output.splitlines() if line.startswith('MKCOL ')]
    assert actual == collections
    assert output.count('COPY ') == 1 and 'option-token' in output


@pytest.mark.parametrize('fault,expected_copy', [('list', False), ('mkcol', False), ('transfer', True)])
@pytest.mark.parametrize('scheme', ['https', 's3'])
def test_remote_failures_propagate_without_unrelated_copy(recursive_run, fault, expected_copy, scheme):
    prefix = 'tree/' if scheme == 's3' else '/tree/'
    source = scheme + '://source.test' + ('/bucket/tree' if scheme == 's3' else '/tree')
    output = recursive_run([prefix + 'child/file'], source=source,
        destination='https://dest.test/new', fault=fault, expected=-1)
    assert ('COPY ' in output) == expected_copy


@pytest.mark.parametrize('scheme', ['https', 's3'])
@pytest.mark.parametrize('mode,credential', [('null', 'environment'), ('credentials', 'option')])
def test_credentials_and_default_connection_policy(recursive_run, scheme, mode, credential):
    source = scheme + '://source.test' + ('/bucket/tree' if scheme == 's3' else '/tree')
    output = recursive_run([], source=source, mode=mode)
    assert credential in output
    assert ('verify=1' if mode == 'null' else 'verify=0') in output


@pytest.mark.parametrize('source', ['not-a-url', 'https://', 'https://source.test:bad/tree'])
def test_invalid_source_never_lists_or_copies(recursive_run, source):
    output = recursive_run([], source=source, expected=-1)
    assert 'LIST ' not in output and 'COPY ' not in output


def test_oversized_s3_bucket_is_rejected_after_listing(recursive_run):
    output = recursive_run([], source='s3://source.test/' + 'b' * 256, expected=-1)
    assert 'invalid S3 bucket' in output and 'COPY ' not in output


def test_leaf_failure_does_not_prevent_remaining_files(recursive_run):
    output = recursive_run(['/tree/a', '/tree/b'], fault='transfer', expected=-1, mode='silent')
    assert output.count('COPY ') == 2 and '2 recursive WebDAV transfer(s) failed' in output


def test_local_parent_creation_error_is_reported(recursive_run, tmp_path):
    blocker = tmp_path / 'blocker'
    blocker.write_text('preserved')
    recursive_run(['/tree/child/file'], destination=blocker, expected=-1)
    assert blocker.read_text() == 'preserved'
