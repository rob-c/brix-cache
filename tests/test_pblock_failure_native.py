"""Real packed-block catalogs recover after failed publication and storage providers."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def failure_binary(server_native_compile):
    names = ('calloc', 'cat_exec', 'pblock_catalog_lookup', 'pblock_catalog_put',
        'pblock_gen_blob_id', 'pblock_ensure_obj_dir', 'pblock_block_path',
        'pblock_copy_one_block', 'pblock_refs_bump', 'pblock_catalog_child_count',
        'pblock_catalog_remove', 'pblock_catalog_rename')
    return server_native_compile('pblock-failure', 'tests/c/pblock_failure_native_test.c',
                                ['-Wl,--wrap=' + name for name in names])


def run_failure(binary, root, operation, fault, options=''):
    (root / 'pblock.opts').write_text(options + '\n')
    result = subprocess.run([str(binary), str(root), operation, fault],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == 'failure remained contained'


@pytest.mark.parametrize('fault', ['alloc-first', 'alloc-second', 'blob-id', 'object-dir'])
def test_partial_staged_open_never_publishes(failure_binary, tmp_path, fault):
    run_failure(failure_binary, tmp_path, 'open', fault)


@pytest.mark.parametrize('operation,fault', [('commit', 'begin'), ('commit', 'lookup-target'),
    ('commit', 'put'), ('commit', 'commit'), ('empty', 'block-path'), ('path', 'block-path')])
@pytest.mark.parametrize('options', ['', 'dedup=1&snap=1&audit=1'])
def test_failed_new_publish_rolls_back_and_releases_staged_owner(failure_binary, tmp_path, operation, fault, options):
    run_failure(failure_binary, tmp_path, operation, fault, options)


@pytest.mark.parametrize('fault', ['begin', 'lookup-target', 'put', 'commit'])
@pytest.mark.parametrize('options', ['', 'dedup=1&snap=1&audit=1'])
def test_failed_overwrite_retains_original_bytes(failure_binary, tmp_path, fault, options):
    run_failure(failure_binary, tmp_path, 'overwrite', fault, options)


@pytest.mark.parametrize('fault,options', [('lookup-source', ''), ('blob-id', ''),
    ('object-dir', ''), ('block-path', ''), ('copy-block', ''), ('put', ''),
    ('put', 'dedup=1'), ('refs-bump', 'dedup=1')])
def test_failed_copy_preserves_source_and_never_exposes_partial_target(failure_binary, tmp_path, fault, options):
    run_failure(failure_binary, tmp_path, 'copy', fault, options)


@pytest.mark.parametrize('operation,fault', [('stat', 'lookup-source'), ('unlink', 'lookup-source'),
    ('unlink', 'child-count'), ('unlink', 'remove'), ('rename', 'lookup-source'),
    ('rename', 'lookup-target'), ('rename', 'child-count'), ('rename', 'remove'),
    ('rename', 'rename'), ('opendir', 'lookup-source'), ('opendir', 'alloc-first'), ('opendir', 'alloc-second')])
def test_catalog_refusal_cannot_report_namespace_success(failure_binary, tmp_path, operation, fault):
    run_failure(failure_binary, tmp_path, operation, fault)


@pytest.mark.parametrize('options', ['nsidx=0', 'nsidx=1'])
@pytest.mark.parametrize('scenario', ['commit-create', 'commit-update', 'commit-remove',
                                     'rollback-create', 'rollback-update', 'rollback-remove'])
def test_namespace_cache_exposes_only_committed_transaction_results(failure_binary, tmp_path, options, scenario):
    run_failure(failure_binary, tmp_path, 'transaction', scenario, options)
