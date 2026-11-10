"""FRM staged publication retains ownership and reports tape consistency failures."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def staged_binary(server_native_compile):
    names = ('calloc', 'sd_posix_reserve', 'brix_stage_engine_journal_dir',
             'brix_stage_on_loop', 'brix_stage_submit')
    return server_native_compile('frm-staged', 'tests/c/frm_staged_native_test.c',
                                ['-Wl,--wrap=' + name for name in names])


def invoke(binary, root, operation, mode):
    online = root / '.online'; online.mkdir(exist_ok=True)
    (online / 'a').write_bytes(b'alpha'); (online / 'b').write_bytes(b'beta')
    result = subprocess.run([str(binary), operation, mode, str(root)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return tuple(map(int, result.stdout.split()))


@pytest.mark.parametrize('mode,error,exchanges,migrates,swapped', [
    ('normal', 0, 1, 2, True), ('unsupported', errno.ENOTSUP, 0, 0, False),
    ('exchange-error', errno.EACCES, 1, 0, False),
    ('migrate-first', errno.ENOSPC, 2, 1, False),
    ('first-no-errno', errno.EIO, 2, 1, False),
    ('migrate-second', errno.ENOSPC, 1, 2, True)])
def test_exchange_rolls_back_only_before_any_tape_publication(staged_binary, tmp_path, mode, error, exchanges, migrates, swapped):
    counts = invoke(staged_binary, tmp_path, 'exchange', mode)
    assert counts[:2] == (-int(bool(error)), error) and counts[3:5] == (migrates, exchanges)
    actual = ((tmp_path / '.online/a').read_bytes(), (tmp_path / '.online/b').read_bytes())
    assert actual == ((b'beta', b'alpha') if swapped else (b'alpha', b'beta'))


@pytest.mark.parametrize('mode,error,purges,migrates', [
    ('normal', 0, 0, 1), ('advisory', 0, 0, 1), ('absent', 0, 0, 1),
    ('create-error', errno.EACCES, 0, 0), ('no-space', errno.ENOSPC, 1, 0),
    ('quota', errno.EDQUOT, 1, 0), ('alloc-state', errno.ENOMEM, 0, 0),
    ('alloc-handle', errno.ENOMEM, 0, 0), ('mismatch', errno.ECANCELED, 1, 0),
    ('missing', errno.ECANCELED, 1, 0), ('existing', errno.EEXIST, 1, 0),
    ('migrate-first', errno.ENOSPC, 1, 1)])
def test_staged_failures_close_descriptors_and_never_migrate_refused_data(staged_binary, tmp_path, mode, error, purges, migrates):
    counts = invoke(staged_binary, tmp_path, 'staged', mode)
    assert counts[:4] == (-int(bool(error)), error, purges, migrates)
    if purges:
        assert not (tmp_path / '.online/a').exists()


@pytest.mark.parametrize('mode,error,seals,submitted', [('inline-seal', 0, 1, 0),
    ('deferred', 0, 0, 1), ('deferred-refused', 0, 1, 1), ('seal-error', errno.EIO, 1, 0)])
def test_deferred_seal_rejection_falls_back_without_losing_publication(staged_binary, tmp_path, mode, error, seals, submitted):
    counts = invoke(staged_binary, tmp_path, 'staged', mode)
    assert counts[:2] == (-int(bool(error)), error)
    assert counts[3] == 1 and counts[5:] == (seals, submitted)


@pytest.mark.parametrize('mode,error,seals', [('normal', 0, 1), ('invalid', errno.EINVAL, 0),
    ('null-key', errno.EINVAL, 0), ('unsupported', errno.ENOTSUP, 0), ('seal-error', errno.EIO, 1)])
def test_seal_requires_a_supported_instance_and_valid_key(staged_binary, tmp_path, mode, error, seals):
    counts = invoke(staged_binary, tmp_path, 'seal', mode)
    assert counts[:2] == (-int(bool(error)), error) and counts[5] == seals
