"""Replay existing CRL policy fixtures through the production native oracle."""

import os
from pathlib import Path
import subprocess
import tempfile

import pytest

import clauses
import x509forge
from cmdscripts.c_auth_units import X509_POLICY_SOURCES
from test_platform_linux_native import native_compile


@pytest.fixture(scope='module')
def crl_oracle_binary(native_compile):
    """Link the existing oracle and real trust cores with configured nginx flags."""
    return native_compile(
        'crl-oracle', '/* Main is provided by the existing native oracle. */',
        ['tests/c/x509_oracle.c', *X509_POLICY_SOURCES], ['-lssl', '-lcrypto'])


@pytest.mark.parametrize('identifiers', [
    ('CRL-001', 'CRL-013', 'CRL-016'),
    ('CRL-004', 'CRL-077', 'CRL-078', 'CRL-080', 'CRL-081'),
    ('CRL-074', 'CRL-075'),
], ids=['valid-or-missing', 'competing-revocations', 'delta-policy'])
def test_crl_selection(crl_oracle_binary, identifiers):
    """Preserve valid, revocation-refusal and mode-specific delta contracts."""
    selected = [item for item in clauses.ALL_CLAUSES if item.id in identifiers]
    assert len(selected) == len(identifiers)
    with tempfile.TemporaryDirectory(prefix='brix_crl_selection.', dir='/tmp') as directory:
        fixtures = x509forge.build_all(Path(directory), selected)
        assert not (fixtures / 'build_errors.tsv').exists()
        result = subprocess.run(
            [str(crl_oracle_binary)], capture_output=True, text=True, timeout=30,
            env={**os.environ, 'BRIX_X509_FIXTURES': str(fixtures)})
    assert result.returncode == 0, result.stdout + result.stderr
    assert f'{len(identifiers)} oracle checks, 0 failures' in result.stdout
