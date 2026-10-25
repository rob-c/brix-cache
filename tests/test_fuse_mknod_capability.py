"""Independent native capability probes must not hide real mknod failures."""
import errno
import os
import stat

import pytest

from lib_py import fuse_host


def test_regular_mknod_probe_success(tmp_path, monkeypatch):
    def create_regular(path, mode):
        assert stat.S_ISREG(mode)
        with open(path, "xb"):
            pass

    monkeypatch.setattr(os, "mknod", create_regular)
    probe = tmp_path / "probe"
    assert fuse_host.regular_mknod_error(probe) == 0
    assert not probe.exists()


@pytest.mark.parametrize("number", [errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP])
def test_regular_mknod_probe_refusal(tmp_path, monkeypatch, number):
    def refuse(path, mode):
        raise OSError(number, "native refusal")

    monkeypatch.setattr(os, "mknod", refuse)
    assert fuse_host.regular_mknod_error(tmp_path / "probe") == number


@pytest.mark.parametrize("number", [errno.EPERM, errno.EACCES, errno.EIO])
def test_regular_mknod_probe_does_not_hide_failures(tmp_path, monkeypatch, number):
    def refuse(path, mode):
        raise OSError(number, "real failure")

    monkeypatch.setattr(os, "mknod", refuse)
    with pytest.raises(OSError) as caught:
        fuse_host.regular_mknod_error(tmp_path / "probe")
    assert caught.value.errno == number


def test_regular_mknod_probe_rejects_mutating_refusal(tmp_path, monkeypatch):
    def create_then_refuse(path, mode):
        with open(path, "xb"):
            pass
        raise OSError(errno.EINVAL, "mutated before refusing")

    monkeypatch.setattr(os, "mknod", create_then_refuse)
    with pytest.raises(AssertionError, match="created a node"):
        fuse_host.regular_mknod_error(tmp_path / "probe")
