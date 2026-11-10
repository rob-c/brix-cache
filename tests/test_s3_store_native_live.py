"""Real SigV4 storage operations checked against MinIO through independent boto3 reads."""

import os
from pathlib import Path
import subprocess
import uuid

import pytest

from brix_suite.client_build import client_make
from settings import HOST
from test_sts_minio_live import ROOT_USER, ROOT_PW, _minio_service, _wait_minio

pytestmark = [pytest.mark.serial, pytest.mark.timeout(180)]


@pytest.fixture(scope='module')
def s3_store(tmp_path_factory):
    boto3 = pytest.importorskip('boto3')
    port = 19926
    endpoint = f'http://{HOST}:{port}'
    root = tmp_path_factory.mktemp('s3-native-minio')
    with _minio_service(root, port) as process:
        _wait_minio(process, endpoint)
        client = boto3.client('s3', endpoint_url=endpoint, region_name='us-east-1',
                              aws_access_key_id=ROOT_USER, aws_secret_access_key=ROOT_PW)
        yield client, port
        client.close()


@pytest.fixture(scope='module')
def s3_binary(tmp_path_factory):
    output = tmp_path_factory.mktemp('s3-native-driver')
    client = Path(__file__).resolve().parents[1] / 'client'
    result = client_make(client, 's3-store-live-unit', f'BINDIR={output}',
                         capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, result.stdout + result.stderr
    return output / 's3_store_live_unit'


def cleanup_bucket(client, bucket):
    for upload in client.list_multipart_uploads(Bucket=bucket).get('Uploads', []):
        client.abort_multipart_upload(Bucket=bucket, Key=upload['Key'], UploadId=upload['UploadId'])
    keys = client.list_objects_v2(Bucket=bucket).get('Contents', [])
    if keys:
        client.delete_objects(Bucket=bucket, Delete={'Objects': [{'Key': item['Key']} for item in keys]})
    client.delete_bucket(Bucket=bucket)


@pytest.fixture
def s3_bucket(s3_store):
    client, port = s3_store
    bucket = 'brix-native-' + uuid.uuid4().hex
    client.create_bucket(Bucket=bucket)
    try:
        yield client, port, bucket
    finally:
        cleanup_bucket(client, bucket)


def run_driver(binary, lab, case, size=0, known=-1, checksum=1, key='object'):
    _client, port, bucket = lab
    path = f'/{bucket}/{key}' if key else f'/{bucket}'
    environment = {**os.environ, 'BRIX_TEST_S3_AK': ROOT_USER, 'BRIX_TEST_S3_SK': ROOT_PW}
    result = subprocess.run([str(binary), HOST, str(port), path, case,
                             str(size), str(known), str(checksum)], env=environment,
                            capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.endswith('S3 native contract: PASS\n')


def pattern(size):
    return (bytes(range(251)) * (size // 251 + 1))[:size]


def object_bytes(lab, key='object'):
    client, _port, bucket = lab
    response = client.get_object(Bucket=bucket, Key=key)
    with response['Body'] as body:
        return body.read()


@pytest.mark.parametrize('size,known', [(0, 0), (19, 19), (70001, -1),
    (6 * 1024 * 1024 + 17, -1), (6 * 1024 * 1024 + 17, 6 * 1024 * 1024 + 17),
    (6 * 1024 * 1024 + 17, 19)])
@pytest.mark.parametrize('checksum', [0, 1])
def test_single_put_and_lazy_or_explicit_multipart_are_byte_exact(s3_binary, s3_bucket,
                                                                size, known, checksum):
    run_driver(s3_binary, s3_bucket, 'write', size, known, checksum)
    assert object_bytes(s3_bucket) == pattern(size)


@pytest.mark.parametrize('case,size', [('abort', 19), ('abort', 6 * 1024 * 1024 + 17),
    ('conditional', 19), ('conditional', 6 * 1024 * 1024 + 17)])
def test_aborted_or_refused_publish_preserves_original(s3_binary, s3_bucket, case, size):
    client, _port, bucket = s3_bucket
    client.put_object(Bucket=bucket, Key='object', Body=b'protected')
    run_driver(s3_binary, s3_bucket, case, size)
    assert object_bytes(s3_bucket) == b'protected'
    assert client.list_multipart_uploads(Bucket=bucket).get('Uploads', []) == []


@pytest.mark.parametrize('case', ['metadata', 'archive', 'denied'])
def test_metadata_and_restore_errors_preserve_object_bytes(s3_binary, s3_bucket, case):
    client, _port, bucket = s3_bucket
    client.put_object(Bucket=bucket, Key='object', Body=b'original')
    run_driver(s3_binary, s3_bucket, case)
    assert object_bytes(s3_bucket) == b'original'


@pytest.mark.parametrize('case', ['batch', 'batch-denied'])
def test_batch_delete_escapes_keys_and_preserves_failed_results(s3_binary, s3_bucket, case):
    client, _port, bucket = s3_bucket
    for key in ['plain', 'escaped&<>\'"']:
        client.put_object(Bucket=bucket, Key=key, Body=key.encode())
    run_driver(s3_binary, s3_bucket, case, key='')
    if case == 'batch':
        assert client.list_objects_v2(Bucket=bucket).get('Contents', []) == []
    else:
        for key in ['plain', 'escaped&<>\'"']:
            assert object_bytes(s3_bucket, key) == key.encode()
