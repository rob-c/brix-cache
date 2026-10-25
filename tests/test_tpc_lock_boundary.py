"""Native TPC uses the confined VFS path and preserves export-root locks."""
import os
import time

import pytest

from _test_audit16v_tpc_off_arms_helpers import (
    PAYLOAD, clean_proxy, kXR_OK, kXR_error, planes, pytestmark,
)


@pytest.mark.parametrize('expires_delta,accepted', [(-60, True), (300, False)])
def test_native_pull_honours_export_root_lock(planes, clean_proxy, expires_delta, accepted):
    """Expired locks allow exact bytes; live ancestor locks prevent creation."""
    name = planes.seed()
    key = 'user.nginx_xrootd.lock'
    record = (f'v=2|token=opaquelocktoken:tpc-parent|owner=fixture|'
              f'expires={int(time.time()) + expires_delta}|scope=exclusive|depth=infinity|null=0').encode()
    os.setxattr(planes.data_root, key, record)
    try:
        status, error, destination = planes.pull(
            'pulling', planes.source_url(name), source_name=name)
        if accepted:
            assert status == kXR_OK, (status, error)
            assert planes.disk(destination).read_bytes() == PAYLOAD
        else:
            assert status == kXR_error, (status, error)
            assert 'busy' in error.lower() or 'lock' in error.lower(), error
            assert not planes.disk(destination).exists()
        assert os.getxattr(planes.data_root, key) == record
        assert (planes.data_root / name).read_bytes() == PAYLOAD
    finally:
        os.removexattr(planes.data_root, key)


def test_native_pull_without_lock_has_exact_bytes(planes, clean_proxy):
    """Success: the VFS translates the confined path once and stores all bytes."""
    name = planes.seed()
    status, error, destination = planes.pull(
        'pulling', planes.source_url(name), source_name=name)
    assert status == kXR_OK, (status, error)
    assert planes.disk(destination).read_bytes() == PAYLOAD
