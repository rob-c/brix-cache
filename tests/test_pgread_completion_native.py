"""AIO page-read completion preserves response channel and buffer ownership."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def pgread_done(server_native_compile, tmp_path_factory):
    names = ('brix_queue_response_chain', 'brix_queue_response_base', 'brix_send_empty_pgread',
        'brix_aio_resume', 'brix_read_io_error', 'brix_send_error', 'brix_send_error_sid',
        'brix_park_front_buf', 'brix_ensure_write_event', 'brix_run_deferred_teardown',
        'brix_release_read_buffer', 'brix_build_pgread_chain')
    binary = server_native_compile('pgread-done', 'tests/c/pgread_completion_native_test.c',
                                  ['-Wl,--wrap=' + name for name in names])
    source = tmp_path_factory.mktemp('pgread-done') / 'source'
    source.write_bytes(b'abcdefghijklmnop')
    def run(mode, secondary):
        result = subprocess.run([str(binary), mode, str(secondary), str(source)],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        return dict(item.split('=', 1) for item in result.stdout.split())
    return run


@pytest.mark.parametrize('secondary', [0, 1])
@pytest.mark.parametrize('mode,held,byte_count', [('normal', 0, 8), ('queued', 1, 8),
    ('eof', 0, 0), ('receiving', 0, 8), ('uncounted', 0, 8)])
def test_success_accounts_bytes_and_only_queue_retains_slot(pgread_done, secondary, mode, held, byte_count):
    result = pgread_done(mode, secondary)
    assert result['queues'] == result['resume'] == '1'
    assert result['error'] == result['wait'] == result['chunks'] == '0'
    assert result['held'] == str(held)
    assert result['bytes'] == str(byte_count)
    assert result['pending'] == ('1,1' if mode == 'uncounted' else f'0,{1 - secondary}')
    assert result['hdr'] == ('17' if mode == 'receiving' else '0')


@pytest.mark.parametrize('secondary', [0, 1])
@pytest.mark.parametrize('mode,error,wait', [('error', 1, 0), ('wait', 0, 1)])
def test_failed_read_returns_slot_without_publishing_data(pgread_done, secondary, mode, error, wait):
    result = pgread_done(mode, secondary)
    assert result['queues'] == result['held'] == result['bytes'] == '0'
    assert result['error'] == str(error) and result['wait'] == str(wait)
    assert result['resume'] == result['release'] == '1'


def test_primary_chain_allocation_failure_releases_slot(pgread_done):
    result = pgread_done('chain-failure', 0)
    assert result['queues'] == result['held'] == result['bytes'] == '0'
    assert result['resume'] == result['release'] == '1'


@pytest.mark.parametrize('secondary', [0, 1])
@pytest.mark.parametrize('mode,teardown', [('primary-dead', '1,0'), ('primary-busy', '0,0')])
def test_dead_primary_never_resumes_or_accounts_and_only_last_task_reaps(pgread_done, secondary, mode, teardown):
    result = pgread_done(mode, secondary)
    assert result['queues'] == result['resume'] == result['bytes'] == '0'
    assert result['teardown'] == teardown
    assert result['release'] == str(secondary)
    assert result['held'] == str(1 - secondary)


@pytest.mark.parametrize('mode,error,resume,teardown', [('secondary-dead', 1, 1, '0,1'),
                                                     ('both-dead', 0, 0, '1,1')])
def test_secondary_loss_releases_its_slot_and_reaps_each_owner(pgread_done, mode, error, resume, teardown):
    result = pgread_done(mode, 1)
    assert result['queues'] == result['held'] == result['bytes'] == '0'
    assert result['error'] == str(error) and result['resume'] == str(resume)
    assert result['teardown'] == teardown and result['release'] == '1'


@pytest.mark.parametrize('mode,held,parks,arms,byte_count,resume,teardown,sent', [
    ('sent', 0, 0, 0, 8, 1, '0,0', 44),
    ('sent-queued', 0, 0, 1, 8, 1, '0,0', 44),
    ('sent-secondary-dead', 0, 0, 0, 8, 1, '0,1', 44),
    ('sent-primary-dead', 0, 0, 0, 0, 0, '1,0', 44),
    ('token', 1, 1, 0, 8, 1, '0,0', 7),
    ('token-primary-dead', 1, 1, 0, 0, 0, '1,0', 7),
    ('token-secondary-dead', 0, 0, 0, 0, 1, '0,1', 7)])
def test_pool_send_ownership_survives_connection_lifetime(pgread_done, mode, held, parks, arms,
                                                        byte_count, resume, teardown, sent):
    result = pgread_done(mode, 1)
    assert result['queues'] == result['token'] == '0'
    expected = dict(held=held, parks=parks, arms=arms, bytes=byte_count, resume=resume,
                    teardown=teardown, sent=sent, error=int(mode == 'token-secondary-dead'))
    assert {key: result[key] for key in expected} == {key: str(value) for key, value in expected.items()}


@pytest.mark.parametrize('mode,error,chunks', [('send-error', 1, 0),
                                            ('chunk-error', 0, 1), ('chunk-errno', 0, 1)])
def test_wire_failure_reports_on_correct_channel_without_requeue(pgread_done, mode, error, chunks):
    result = pgread_done(mode, 1)
    assert result['queues'] == result['held'] == result['bytes'] == '0'
    assert result['error'] == str(error) and result['chunks'] == str(chunks)
    assert result['resume'] == result['release'] == '1'
