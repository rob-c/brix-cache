"""Paginated listings cannot publish partial results after provider or bounds errors."""

from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def listing_binary(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    names = ('realloc', 'strdup', 'brix_http_urlencode', 'brix_s3_sign_v4_q',
             'brix_http_req', 'brix_http_resp_free')
    return compile_client_contract(root, tmp_path_factory.mktemp('web-listing'),
                                   'tests/c/web_listing_native_test.c', names)


@pytest.fixture
def listing(listing_binary, tmp_path):
    def run(operation='s3', mode='normal', path='/bucket/prefix with space', pages=('',), status=200):
        body = tmp_path / 'pages'
        body.write_text('\n<page-break/>\n'.join(pages))
        result = subprocess.run([str(listing_binary), operation, mode, path, str(body), str(status)],
                                capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, result.stdout + result.stderr
        lines = result.stdout.splitlines()
        summary = next(line for line in lines if line.startswith('RESULT '))
        return tuple(map(int, summary.split()[1:])), [line[5:] for line in lines if line.startswith('ITEM ')], lines
    return run


def continuation(token):
    return '<IsTruncated>true</IsTruncated><NextContinuationToken>' + token + '</NextContinuationToken>'


@pytest.mark.parametrize('mode', ['normal', 'unsigned'])
def test_s3_pages_keep_exact_keys_and_sorted_encoded_continuation(listing, mode):
    summary, items, lines = listing(mode=mode, pages=('<Key>first</Key>' + continuation('a+/='), '<Key>second</Key>'))
    assert summary == (0, 0, 2, 2, 2) and items == ['first', 'second']
    assert lines[0] == 'REQUEST GET /bucket?list-type=2&prefix=prefix%20with%20space'
    assert lines[1] == 'REQUEST GET /bucket?continuation-token=a%2B%2F%3D&list-type=2&prefix=prefix%20with%20space'


@pytest.mark.parametrize('mode,pages', [('normal', ('',)), ('null-body', ('ignored',)),
                                     ('normal', ('<Key>unterminated',))])
def test_empty_or_incomplete_tag_stream_does_not_invent_keys(listing, mode, pages):
    summary, items, _ = listing(mode=mode, path='/bucket', pages=pages)
    assert summary == (0, 0, 1, 1, 0) and items == []


@pytest.mark.parametrize('mode,path', [('normal', 'unrooted'), ('normal', '/' + 'b' * 256 + '/prefix'),
                                    ('encode-error', '/bucket/prefix'), ('sign-error', '/bucket')])
def test_invalid_or_unsigned_request_is_refused_before_transport(listing, mode, path):
    summary, items, _ = listing(mode=mode, path=path)
    assert summary[0] == -1 and summary[2:] == (0, 0, 0) and items == []


@pytest.mark.parametrize('mode', ['array-oom', 'item-oom', 'second-item-oom', 'transport', 'second-transport'])
def test_page_or_accumulator_failure_cannot_return_partial_listing(listing, mode):
    summary, items, _ = listing(mode=mode, pages=('<Key>a</Key><Key>b</Key>' + continuation('next'), '<Key>c</Key>'))
    assert summary[0] == -1 and summary[4] == 0 and items == []
    assert summary[2] == (2 if mode == 'second-transport' else 1)
    assert summary[3] == summary[2] - int('transport' in mode)


@pytest.mark.parametrize('body', ['<Key>' + 'k' * 4096 + '</Key>', continuation('x' * 8192), continuation('%' * 4096)])
def test_oversized_key_or_token_never_becomes_truncated_output(listing, body):
    summary, items, _ = listing(pages=(body,))
    assert summary[0] == -1 and summary[4] == 0 and items == []
    assert summary[2:] == (1, 1, 0)


def test_repeated_continuation_stops_at_finite_page_budget(listing):
    summary, items, _ = listing(mode='runaway', pages=(continuation('same'),))
    assert summary[0] == -1 and summary[2:] == (100000, 100000, 0) and items == []


def test_entry_budget_bounds_server_controlled_listing_growth(listing):
    summary, items, _ = listing(mode='unsigned', pages=('<Key>entry</Key>' * 200001,))
    assert summary == (0, 0, 1, 1, 200000) and items == ['entry'] * 200000


@pytest.mark.parametrize('operation,status', [('s3', 403), ('dav', 401), ('mkcol', 500),
                                           ('delete', 404), ('delete', 403), ('move', 410), ('move', 502)])
def test_http_refusal_is_not_list_or_mutation_success(listing, operation, status):
    summary, items, _ = listing(operation=operation, status=status)
    assert summary[0] == -1 and summary[2:] == (1, 1, 0) and items == []


@pytest.mark.parametrize('operation,status', [('mkcol', 200), ('mkcol', 201), ('mkcol', 301), ('mkcol', 405),
    ('delete', 200), ('delete', 202), ('delete', 204), ('move', 200), ('move', 201), ('move', 204)])
@pytest.mark.parametrize('mode', ['normal', 'anonymous'])
def test_documented_mutation_successes_keep_authentication_policy(listing, operation, status, mode):
    assert listing(operation=operation, mode=mode, status=status)[0] == (0, 0, 1, 1, 0)


@pytest.mark.parametrize('mode', ['normal', 'anonymous'])
def test_webdav_list_preserves_plus_and_skips_collections_and_missing_hrefs(listing, mode):
    body = ('<D:response><D:href>/tree/</D:href><D:collection/></D:response>'
        '<D:response><D:href>/tree/a+b%20c</D:href></D:response>'
        '<D:response><D:href>https://origin.test/tree/file</D:href></D:response>'
        '<D:response>missing href</D:response><D:response><D:href>broken</D:response>')
    summary, items, _ = listing(operation='dav', mode=mode, pages=(body,), status=207)
    assert summary == (0, 0, 1, 1, 2) and items == ['/tree/a+b c', '/tree/file']


@pytest.mark.parametrize('mode', ['wrong-protocol', 'array-oom', 'item-oom', 'transport'])
def test_webdav_failed_listing_leaves_no_partial_result(listing, mode):
    summary, items, _ = listing(operation='dav', mode=mode,
        pages=('<D:response><D:href>/file</D:href></D:response>',), status=207)
    assert summary[0] == -1 and summary[4] == 0 and items == []
