"""Ceph adapter ABI, layout selection, binary attributes and iterator ownership."""

import errno
import subprocess

import pytest

from test_nginx_native_contract import server_native_compile  # noqa: F401


@pytest.fixture(scope='module')
def striper(server_native_compile):
    names = ('create', 'destroy', 'set_object_layout_stripe_unit',
        'set_object_layout_stripe_count', 'set_object_layout_object_size', 'read',
        'write', 'trunc', 'remove', 'stat', 'getxattr', 'setxattr', 'rmxattr',
        'getxattrs', 'getxattrs_next', 'getxattrs_end')
    binary = server_native_compile('ceph-striper', 'tests/c/ceph_striper_native_test.c',
        ['-Wl,--wrap=rados_striper_' + name for name in names])
    def run(mode, error=0, argument=0, empty=0):
        result = subprocess.run([str(binary), mode, str(error), str(argument), str(empty)],
                                capture_output=True, text=True, timeout=10)
        if result.returncode == 77:
            pytest.skip('configured server has no Ceph striper adapter')
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout
    return run


@pytest.mark.parametrize('mask', range(-1, 8))
def test_default_and_individual_layout_fields(striper, mask):
    assert striper('create', argument=mask) == 'calls=1 ended=1\n'


@pytest.mark.parametrize('error', [errno.ENOMEM, errno.EACCES, errno.EIO])
def test_failed_create_does_not_publish_or_destroy_handle(striper, error):
    assert striper('create', error=error, argument=7) == 'calls=1 ended=0\n'


def test_missing_output_is_rejected_before_sdk_call(striper):
    assert striper('create', argument=8) == 'calls=0 ended=0\n'


@pytest.mark.parametrize('optional', range(4))
@pytest.mark.parametrize('error', [0, errno.EIO, errno.EACCES, errno.ENOENT, errno.ENOSPC])
def test_io_preserves_bytes_errors_and_optional_metadata(striper, optional, error):
    assert striper('io', error=error, argument=optional) == 'calls=8 ended=0\n'


@pytest.mark.parametrize('capacity', [0, 8, 9, 17, 18, 24])
def test_attribute_names_are_bounded_and_iterator_always_closes(striper, capacity):
    assert striper('attrs', argument=capacity) == 'calls=1 ended=1\n'


@pytest.mark.parametrize('empty', [1, 2, 3])
@pytest.mark.parametrize('capacity', [0, 24])
def test_empty_or_failed_iteration_releases_handle(striper, empty, capacity):
    assert striper('attrs', argument=capacity, empty=empty) == 'calls=1 ended=1\n'


@pytest.mark.parametrize('error', [errno.EACCES, errno.EIO, errno.ENOENT])
def test_attribute_open_failure_has_no_iterator_to_release(striper, error):
    assert striper('attrs', argument=24, error=error) == 'calls=1 ended=0\n'
