"""POST parent preparation must preserve the same lock scope as PUT."""
import uuid

import pytest
import requests

from test_cross_protocol_locks import lock_srv, pytestmark, _lock, _s3, _unlock


def _post(srv, key):
    return requests.post(_s3(srv, ''),
        data={'key': key, 'success_action_status': '201'},
        files={'file': ('payload.bin', b'post payload', 'application/octet-stream')},
        timeout=10)


@pytest.mark.parametrize('nested', [False, True])
def test_post_existing_parent_honors_depth_zero_lock_scope(lock_srv, nested):
    prefix = f'post-parent-{uuid.uuid4().hex}/' if nested else ''
    root = lock_srv['dirs']['shared']
    (root / prefix).mkdir(exist_ok=True)
    target = prefix + f'new-{uuid.uuid4().hex}'
    response = _lock(lock_srv, '/' + prefix, headers={'Depth': '0'})
    assert response.status_code in (200, 201), response.text
    try:
        uploaded = _post(lock_srv, target)
        assert uploaded.status_code == 201, uploaded.text
        assert (root / target).read_bytes() == b'post payload'
    finally:
        _unlock(lock_srv, '/' + prefix, response.headers['Lock-Token'])


def test_post_still_refuses_the_locked_target(lock_srv):
    key = f'post-locked-{uuid.uuid4().hex}'
    path = lock_srv['dirs']['shared'] / key
    path.write_bytes(b'protected')
    response = _lock(lock_srv, '/' + key)
    assert response.status_code in (200, 201), response.text
    try:
        assert _post(lock_srv, key).status_code == 423
        assert path.read_bytes() == b'protected'
    finally:
        _unlock(lock_srv, '/' + key, response.headers['Lock-Token'])


def test_post_still_creates_a_missing_parent(lock_srv):
    key = f'post-missing-{uuid.uuid4().hex}/nested/payload.bin'
    assert _post(lock_srv, key).status_code == 201
    assert (lock_srv['dirs']['shared'] / key).read_bytes() == b'post payload'


def test_post_parent_file_is_not_replaced_by_a_directory(lock_srv):
    name = f'post-parent-file-{uuid.uuid4().hex}'
    parent = lock_srv['dirs']['shared'] / name
    parent.write_bytes(b'keep parent')
    assert _post(lock_srv, name + '/payload.bin').status_code == 404
    assert parent.read_bytes() == b'keep parent'
