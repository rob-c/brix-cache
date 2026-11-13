"""Kerberos cache precedence and TGT expiry use isolated real cache files."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from test_xrd_dispatch_native import compile_client_contract

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='GNU link wrapping')


@pytest.fixture(scope='module')
def krb5_cache(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    return compile_client_contract(root, tmp_path_factory.mktemp('krb5-cache'),
        'tests/c/krb5_cache_native_test.c', ('krb5_init_context', 'krb5_cc_start_seq_get',
                                          'krb5_cc_get_type', 'krb5_cc_get_name'))


def invoke(binary, tmp_path, source, contents, mode, expected=0):
    cache = 'FILE:' + str(tmp_path / 'private.ccache')
    config = tmp_path / 'krb5.conf'
    config.write_text('[libdefaults]\n default_realm = EXAMPLE.TEST\n'
                      ' default_ccache_name = ' + cache + '\n dns_lookup_kdc = false\n')
    environment = dict(os.environ, KRB5_CONFIG=str(config), KRB5CCNAME=cache)
    result = subprocess.run([str(binary), cache, source, contents, mode, str(expected)],
                            env=environment, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('source', ['explicit', 'environment', 'default'])
@pytest.mark.parametrize('contents', ['empty', 'service', 'tgt'])
def test_cache_selection_and_tgt_expiry_are_exact(krb5_cache, tmp_path, source, contents):
    invoke(krb5_cache, tmp_path, source, contents, 'normal')


@pytest.mark.parametrize('mode', ['cursor', 'no-type', 'no-name'])
def test_optional_metadata_failure_preserves_usable_principal(krb5_cache, tmp_path, mode):
    invoke(krb5_cache, tmp_path, 'explicit', 'tgt', mode)


@pytest.mark.parametrize('mode', ['context', 'bad-type', 'missing'])
def test_failed_or_wrong_cache_cannot_supply_credentials(krb5_cache, tmp_path, mode):
    invoke(krb5_cache, tmp_path, 'explicit', 'tgt', mode, expected=-1)
