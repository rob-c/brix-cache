"""Multipart completion publishes actual part bytes or preserves the prior object on failure."""

import subprocess

import pytest

from test_nginx_native_contract import server_native_compile


@pytest.fixture(scope='module')
def completion_binary(server_native_compile):
    names = ['s3_build_vfs_ctx', 'brix_vfs_require_unlocked', 's3_metrics_finalize_request_method',
        's3_send_xml_error', 'brix_http_send_xml_buffer', 's3_thread_pool', 'ngx_thread_task_alloc',
        'ngx_thread_task_post', 'brix_vfs_export_open_fd', 'brix_vfs_open_fd', 'fstat64',
        'brix_copy_range', 'brix_rename_confined_canon', 'mpu_rmdir_recursive',
        's3_object_crc64nvme_b64', 'ngx_create_temp_buf', 'brix_cns_emit_at']
    return server_native_compile('mpu-complete', 'tests/c/mpu_complete_native_test.c',
                                ['-Wl,--wrap=' + name for name in names])


def invoke(binary, tmp_path, mode, query='uploadId=abcdef0123456789abcdef01'):
    destination = tmp_path / 'object'; destination.write_bytes(b'old object')
    staging = tmp_path / '.object.mpu-abcdef0123456789abcdef01'; staging.mkdir()
    (staging / 'part.1').write_bytes(b'first'); (staging / 'part.3').write_bytes(b'last')
    result = subprocess.run([str(binary), mode, str(tmp_path), query], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    header, _, xml = result.stdout.partition('\n')
    assert not (tmp_path / 'object.mputmp').exists()
    return tuple(map(int, header.split())), xml, destination, staging


@pytest.mark.parametrize('mode,posts', [('normal', 0), ('async', 1), ('cleanup', 0)])
def test_ordered_completion_publishes_exact_bytes_and_balances_async_reference(completion_binary, tmp_path, mode, posts):
    counts, xml, destination, staging = invoke(completion_binary, tmp_path, mode)
    assert counts == (200, 1, posts) and '<Key>object</Key>' in xml
    assert destination.read_bytes() == b'firstlast'
    assert destination.stat().st_mode & 0o777 == 0o600
    assert staging.exists() == (mode == 'cleanup')


@pytest.mark.parametrize('mode,status', [('create', 507), ('async-create', 507), ('part-open', 500),
    ('part-stat', 500), ('final-stat', 500), ('copy', 500), ('rename', 500),
    ('async-allocate', 500), ('async-post', 500), ('readonly', 403), ('locked', 409),
    ('empty-path', 500), ('no-context', 500)])
def test_failed_completion_keeps_the_existing_object_and_all_parts(completion_binary, tmp_path, mode, status):
    counts, xml, destination, staging = invoke(completion_binary, tmp_path, mode)
    assert counts[0:2] == (status, 0) and not xml
    assert destination.read_bytes() == b'old object'
    assert (staging / 'part.1').read_bytes() == b'first'
    assert (staging / 'part.3').read_bytes() == b'last'


@pytest.mark.parametrize('query', ['', 'uploadId=../../escape', 'uploadId=not-hex'])
def test_missing_or_unsafe_upload_identifier_cannot_open_a_staging_namespace(completion_binary, tmp_path, query):
    counts, xml, destination, staging = invoke(completion_binary, tmp_path, 'normal', query)
    assert counts == (400, 0, 0) and not xml
    assert destination.read_bytes() == b'old object' and staging.exists()


@pytest.mark.parametrize('mode', ['response-allocate', 'response-overflow'])
def test_response_failure_does_not_undo_an_already_atomic_publication(completion_binary, tmp_path, mode):
    counts, xml, destination, staging = invoke(completion_binary, tmp_path, mode)
    assert counts == (500, 0, 0) and not xml
    assert destination.read_bytes() == b'firstlast' and not staging.exists()
