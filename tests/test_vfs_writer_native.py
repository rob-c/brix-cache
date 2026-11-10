"""Real write sessions preserve bytes, publication, policy and scratch ownership."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def writer_binary(server_native_compile):
    return server_native_compile('vfs-writer', 'tests/c/vfs_writer_native_test.c',
                                 ['-Wl,--wrap=' + name for name in (
                                     'brix_vfs_backend_spill', 'ngx_pcalloc', 'ngx_palloc',
                                     'brix_wverify_begin', 'pread64')])


def run_writer(binary, tmp_path, case, atomic, verify):
    export, scratch = tmp_path / 'export', tmp_path / 'scratch'
    export.mkdir()
    scratch.mkdir()
    result = subprocess.run([str(binary), str(export), str(scratch), case,
                             str(int(atomic)), str(int(verify))],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == 'writer contract preserved\n'
    assert list(scratch.iterdir()) == []
    assert {path.name for path in export.iterdir()} <= {'input', 'output'}
    return export


@pytest.mark.parametrize('atomic', [False, True])
@pytest.mark.parametrize('verify', [False, True])
@pytest.mark.parametrize('case,expected', [('normal', b'0123456789'),
                                         ('fd-copy', b'234567')])
def test_complete_writer_publishes_exact_bytes(writer_binary, tmp_path,
                                              atomic, verify, case, expected):
    export = run_writer(writer_binary, tmp_path, case, atomic, verify)
    assert (export / 'output').read_bytes() == expected


@pytest.mark.parametrize('atomic', [False, True])
def test_corruption_during_write_never_survives_commit(writer_binary, tmp_path, atomic):
    export = run_writer(writer_binary, tmp_path, 'corrupt', atomic, True)
    assert not (export / 'output').exists()


@pytest.mark.parametrize('atomic', [False, True])
@pytest.mark.parametrize('case', ['readonly', 'abort', 'invalid', 'fd-short', 'fd-error'])
def test_refused_or_aborted_write_does_not_publish_staged_data(writer_binary,
                                                             tmp_path, atomic, case):
    export = run_writer(writer_binary, tmp_path, case, atomic, True)
    if atomic or case == 'readonly':
        assert not (export / 'output').exists()
    else:
        assert (export / 'output').read_bytes() in (b'', b'0123456789')


def test_in_place_writer_rejects_unenforceable_precondition(writer_binary, tmp_path):
    export = run_writer(writer_binary, tmp_path, 'precondition', False, True)
    assert (export / 'output').read_bytes() == b'0123456789'


@pytest.mark.parametrize('case', ['spill', 'spill-hole', 'spill-limit'])
@pytest.mark.parametrize('verify', [False, True])
def test_reordered_extents_require_complete_nonoverlapping_coverage(writer_binary,
                                                                  tmp_path, case, verify):
    export = run_writer(writer_binary, tmp_path, case, True, verify)
    if case == 'spill':
        assert (export / 'output').read_bytes() == b'0123456789'
    else:
        assert not (export / 'output').exists()


@pytest.mark.parametrize('atomic', [False, True])
@pytest.mark.parametrize('case', ['allocation', 'clone-allocation', 'verify-allocation'])
def test_allocation_failure_cleans_up_partial_writer(writer_binary, tmp_path, atomic, case):
    export = run_writer(writer_binary, tmp_path, case, atomic, True)
    if not atomic and case == 'verify-allocation':
        assert (export / 'output').read_bytes() == b''
    else:
        assert not (export / 'output').exists()


@pytest.mark.parametrize('atomic', [False, True])
def test_interrupted_source_read_keeps_exact_offset(writer_binary, tmp_path, atomic):
    export = run_writer(writer_binary, tmp_path, 'fd-eintr', atomic, True)
    assert (export / 'output').read_bytes() == b'234567'


@pytest.mark.parametrize('case', ['spill-grow', 'spill-cap'])
def test_fragmented_spill_grows_then_refuses_excess_extents(writer_binary, tmp_path, case):
    # The verifier has its own smaller extent cap; isolate the spill store's cap.
    export = run_writer(writer_binary, tmp_path, case, True, case != 'spill-cap')
    if case == 'spill-grow':
        assert (export / 'output').read_bytes() == b'BA' * 130
    else:
        assert not (export / 'output').exists()
