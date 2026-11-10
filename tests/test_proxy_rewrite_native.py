"""Production proxy rewrites preserve wire framing and request ownership."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from cmdscripts.object_unit_layout import NGX_SRC
from test_platform_linux_native import native_compile  # noqa: F401

pytestmark = pytest.mark.skipif(sys.platform != 'linux',
                               reason='allocator failure uses GNU link wrapping')


@pytest.fixture(scope='module')
def rewrite_binary(native_compile):
    """Link production rewrites and nginx allocation with one failure seam."""
    driver = Path(__file__).parent / 'c/proxy_rewrite_test.c'
    return native_compile('proxy-rewrite', driver.read_text(),
        ['src/net/proxy/forward_rewrite_helpers.c',
         'tests/c/ngx_link_stubs.c',
         str(NGX_SRC / 'src/os/unix/ngx_alloc.c')],
        ['-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections',
         '-Wl,--wrap=ngx_alloc', '-fsanitize=address,undefined'])


def rewrite(binary, operation, strip, add, payload, fail=False):
    """Return actual bytes and identity after native header/bounds assertions."""
    environment = dict(os.environ)
    if fail:
        environment['BRIX_TEST_ALLOC_FAIL'] = '1'
    result = subprocess.run([str(binary), operation, strip, add, payload],
                            env=environment, capture_output=True, text=True,
                            timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    size, same, encoded = result.stdout.strip().split(':')
    body = bytes.fromhex(encoded)
    assert int(size) == 24 + len(body)
    return body, bool(int(same))


@pytest.mark.parametrize('strip,add,payload,expected,same', [
    ('/public', '/store', '/public/file?x=1', '/store/file?x=1', False),
    ('/a', '/longer/prefix', '/a/file', '/longer/prefix/file', False),
    ('/a', '/b', '/a/file', '/b/file', True),
    ('/a', '', '/a/file', '/file', False),
    ('/a', '', '/a', '', False),
    ('', '/b', '/a/file', '/a/file', True),
    ('/longer', '/b', '/a', '/a', True),
    ('/a', '/b', '/c/file', '/c/file', True),
    ('/a', '/b', '', '', True),
    ('/a', '/b', '/a/file\nopaque-tail', '/b/file\nopaque-tail', True),
    ('/a', '/目标', '/a/δ', '/目标/δ', False),
])
def test_single_path_rewrites_only_the_configured_prefix(rewrite_binary, strip,
                                                       add, payload, expected, same):
    """Prefix growth, shrinkage and no-match all retain a valid request frame."""
    assert rewrite(rewrite_binary, 'single', strip, add, payload) == (expected.encode(), same)


@pytest.mark.parametrize('payload,expected', [
    ('/a/one\n/a/two\n', '/long/one\n/long/two\n'),
    ('/a/one\n/other\n/a/two', '/long/one\n/other\n/long/two'),
    ('\n/a\n\n', '\n/long\n\n'),
    ('/a', '/long'), ('/a\n', '/long\n'),
    ('/a/δ\n/elsewhere', '/long/δ\n/elsewhere'),
])
def test_prepare_rewrites_each_path_and_preserves_newlines(rewrite_binary,
                                                          payload, expected):
    """Mixed and empty lines preserve order, boundaries and the final newline."""
    assert rewrite(rewrite_binary, 'prepare', '/a', '/long', payload) == (expected.encode(), False)


@pytest.mark.parametrize('strip,payload', [('', '/a/one'), ('/a', ''),
                                          ('/a', '/b/one\n/cabandoned')])
def test_prepare_no_match_retains_original_buffer(rewrite_binary, strip, payload):
    """No configured/matching prefix makes no allocation or ownership transfer."""
    assert rewrite(rewrite_binary, 'prepare', strip, '/long', payload) == (payload.encode(), True)


@pytest.mark.parametrize('operation', ['single', 'prepare'])
@pytest.mark.parametrize('add', ['', '/expanded/prefix'])
def test_allocation_failure_preserves_complete_original_request(rewrite_binary,
                                                               operation, add):
    """Failed replacement cannot free, truncate or partly rewrite caller data."""
    payload = '/a/one\n/a/two'
    assert rewrite(rewrite_binary, operation, '/a', add, payload,
                   fail=True) == (payload.encode(), True)


@pytest.mark.parametrize('operation', ['single', 'prepare'])
def test_encoded_prefix_cannot_match_literal_policy(rewrite_binary, operation):
    """This byte-level transform never adds implicit percent decoding."""
    payload = '/%61/private\n/not-a-match'
    assert rewrite(rewrite_binary, operation, '/a', '/store', payload) == (payload.encode(), True)
