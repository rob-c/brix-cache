"""Exercise optional pblock slots against real SQLite catalogs and block files."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def pblock_contract(server_native_compile):
    return server_native_compile('pblock-contract',
                                'tests/c/pblock_contract_native_test.c')


def run_contract(binary, root, options, *arguments):
    (root / 'pblock.opts').write_text(options + '\n')
    result = subprocess.run([str(binary), str(root), *map(str, arguments)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('options', ['', 'lab=1&nearline=1&locks=1&audit=1',
                                     'refs=1&dedup=1&pack=1'])
def test_exchange_moves_subtrees_and_xattrs(pblock_contract, tmp_path, options):
    run_contract(pblock_contract, tmp_path, options, 'exchange', '-')


@pytest.mark.parametrize('case', ['same', 'child', 'parent', 'missing', 'first-missing'])
def test_invalid_exchange_rolls_back_every_name(pblock_contract, tmp_path, case):
    run_contract(pblock_contract, tmp_path, '', 'bad-exchange', case)


@pytest.mark.parametrize('size', [0, 1, 4095, 4096, 4097, 65536, 70001])
@pytest.mark.parametrize('options', ['', 'refs=1&dedup=1', 'xform=zstd'])
def test_bounded_range_copy_and_vectored_read(pblock_contract, tmp_path, size, options):
    run_contract(pblock_contract, tmp_path, options, 'copy', size)


@pytest.mark.parametrize('case,options', [('quota', 'quota=12'), ('lock', 'locks=1')])
def test_refused_copy_preserves_destination(pblock_contract, tmp_path, case, options):
    run_contract(pblock_contract, tmp_path, options, 'copy-refusal', case)


@pytest.mark.parametrize('size', [0, 1, 4096, 4097])
@pytest.mark.parametrize('encoded', [False, True])
def test_verifiable_staged_path_requires_complete_plaintext(pblock_contract,
                                                           tmp_path, size, encoded):
    run_contract(pblock_contract, tmp_path, 'xform=zstd' if encoded else '',
                 'staged', size, int(encoded))


@pytest.mark.parametrize('case,options', [('disabled', ''),
    ('success', 'lab=1&nearline=1'), ('failure', 'lab=1&nearline=1')])
def test_nearline_evict_recall_and_loss(pblock_contract, tmp_path, case, options):
    run_contract(pblock_contract, tmp_path, options, 'nearline', case)


def test_foreign_identity_cannot_exchange_owned_names(pblock_contract, tmp_path):
    run_contract(pblock_contract, tmp_path, '', 'identity', '-')


def test_empty_block_failure_cannot_replace_existing_object(pblock_contract, tmp_path):
    run_contract(pblock_contract, tmp_path, '', 'empty-failure', '-')


@pytest.mark.parametrize('case', ['mixed', 'empty', 'oversized'])
@pytest.mark.parametrize('options', ['', 'refs=1&dedup=1&trash=1&audit=1'])
def test_batch_delete_reports_each_key_without_hiding_errors(pblock_contract, tmp_path,
                                                            case, options):
    run_contract(pblock_contract, tmp_path, options, 'batch', case)


def test_batch_delete_checks_authority_for_every_key(pblock_contract, tmp_path):
    run_contract(pblock_contract, tmp_path, '', 'batch-identity', '-')
