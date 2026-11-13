"""Real archive sidecars, listings and recall transitions preserve data availability."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def archive_adapter(server_native_compile):
    return server_native_compile('archive-adapter', 'tests/c/archive_adapter_native_test.c')


def sidecar(tmp_path, rows):
    directory = tmp_path / '.arcidx'
    directory.mkdir()
    (directory / 'dataset.idx').write_text(rows)


def invoke(binary, tmp_path, operation, key='/dataset/member', *, member=-1, archive=-1,
           poll=0, begin_error=0, list_error=0, durable=0, stop=0, expected=0):
    result = subprocess.run([str(binary), str(tmp_path), operation, key, str(member),
        str(archive), str(poll), str(begin_error), str(list_error), str(durable), str(stop),
        str(expected)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.splitlines()


def test_sidecar_roundtrip_sorts_without_losing_metadata(archive_adapter, tmp_path):
    invoke(archive_adapter, tmp_path, 'roundtrip')
    assert (tmp_path / '.arcidx/dataset.idx').read_text() == 'alpha\t7\t11\t00001234\nzeta\t7\t11\t00001234\n'


@pytest.mark.parametrize('row', ['no-tab', '\t7\t11\t1234', 'member\tbad',
    '../member\t7\t11\t1234', '/member\t7\t11\t1234', 'dir//member\t7\t11\t1234'])
def test_invalid_sidecar_records_cannot_invent_members(archive_adapter, tmp_path, row):
    sidecar(tmp_path, row + '\nmember\t7\t11\t1234\n')
    invoke(archive_adapter, tmp_path, 'metadata', 'member', expected=1)
    invoke(archive_adapter, tmp_path, 'metadata', '../member', expected=0)


@pytest.mark.parametrize('list_error', [0, errno.ENOENT])
@pytest.mark.parametrize('stop', [0, 1])
def test_listing_merges_and_deduplicates_disk_and_tape_names(archive_adapter, tmp_path, list_error, stop):
    sidecar(tmp_path, 'alpha\t7\t11\t1234\ndir/a\t7\t11\t1234\ndir/b\t7\t11\t1234\nzeta\t7\t11\t1234\n')
    lines = invoke(archive_adapter, tmp_path, 'list', '/dataset', list_error=list_error, stop=stop)
    assert lines[:-1] == (['entry:alpha:0'] if stop else ['entry:alpha:0', 'entry:dir:1', 'entry:zeta:0'])


@pytest.mark.parametrize('key,error', [('/', errno.EIO), ('/dataset', errno.EIO),
                                     ('/dataset', errno.ENOENT), ('no-list', 0)])
def test_unavailable_listing_remains_an_error(archive_adapter, tmp_path, key, error):
    invoke(archive_adapter, tmp_path, 'list', key, list_error=error, expected=-1)


@pytest.mark.parametrize('operation,key,expected', [('exchange', '/one', 0),
    ('exchange', '/dataset/member', -1), ('exchange', '/dataset.brixarc.zip', -1),
    ('exchange', 'no-exchange', -1), ('mkdir', '/one', 0), ('mkdir', 'no-mkdir', -1)])
def test_namespace_operations_respect_archive_immutability(archive_adapter, tmp_path, operation, key, expected):
    invoke(archive_adapter, tmp_path, operation, key, expected=expected)


@pytest.mark.parametrize('operation,member,archive,poll,expected', [
    ('residency', -1, -1, 0, -1), ('residency', -1, 2, 0, 2),
    ('residency', 0, -1, 0, 0), ('residency', 2, -1, 0, 2),
    ('begin', -1, -1, 0, -1), ('begin', -1, 2, 0, 0),
    ('poll', -1, -1, 0, -1), ('poll', -1, 2, 0, 0),
    ('poll', 0, -1, 0, 1), ('poll', 2, -1, -1, -1),
])
def test_missing_index_does_not_fabricate_online_bytes(archive_adapter, tmp_path,
                                                     operation, member, archive, poll, expected):
    invoke(archive_adapter, tmp_path, operation, member=member, archive=archive,
           poll=poll, expected=expected)


@pytest.mark.parametrize('operation', ['begin', 'poll'])
@pytest.mark.parametrize('poll', [-1, 0])
def test_indexed_member_retains_archive_recall_result(archive_adapter, tmp_path, operation, poll):
    sidecar(tmp_path, 'member\t7\t11\t1234\n')
    output = invoke(archive_adapter, tmp_path, operation, archive=2, poll=poll, expected=poll)
    assert output == [f'begins:{int(operation == "begin")} polls:1']


def test_failed_archive_recall_does_not_poll_or_extract(archive_adapter, tmp_path):
    sidecar(tmp_path, 'member\t7\t11\t1234\n')
    assert invoke(archive_adapter, tmp_path, 'begin', archive=2,
                  begin_error=errno.EBUSY, expected=-1) == ['begins:1 polls:0']


@pytest.mark.parametrize('durable', [0, 1])
@pytest.mark.parametrize('indexed', [False, True])
def test_purge_requires_indexed_member_and_durable_archive(archive_adapter, tmp_path, durable, indexed):
    if indexed:
        sidecar(tmp_path, 'member\t7\t11\t1234\n')
    invoke(archive_adapter, tmp_path, 'durable', durable=durable, expected=int(indexed and durable))
