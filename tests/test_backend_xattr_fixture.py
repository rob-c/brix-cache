"""OS labels must not hide wrong-domain or unexpected application metadata."""

import os
from types import SimpleNamespace

import pytest

import test_backend_caps_negative as subject


class _Properties:
    def __init__(self, origin, local, write_local):
        self.origin = origin
        self.local = local
        self.write_local = write_local

    def set_xattr(self, path, values):
        os.setxattr(self.origin, "user.nginx_xrootd.webdav.fixture", b"v")
        if self.write_local:
            os.setxattr(self.local, "user.caps", b"v")
        return SimpleNamespace(ok=True), [("user.caps", "v", {"ok": True})]

    def get_xattr(self, path, names):
        value = os.getxattr(self.origin, "user.nginx_xrootd.webdav.fixture").decode()
        return SimpleNamespace(ok=True), [("user.caps", value, {"ok": True})]

    def del_xattr(self, path, names):
        os.removexattr(self.origin, "user.nginx_xrootd.webdav.fixture")
        return SimpleNamespace(ok=True), [("user.caps", "v", {"ok": True})]


@pytest.fixture
def caps(tmp_path, monkeypatch):
    origin, local = tmp_path / "origin", tmp_path / "local"
    origin.mkdir()
    local.mkdir()
    origin_file = origin / subject.PROBE
    origin_file.write_bytes(subject.PROBE_BYTES)
    properties = _Properties(origin_file, local / subject.PROBE, False)
    original_list = os.listxattr
    monkeypatch.setattr(subject.os, "listxattr", lambda path:
                        [*original_list(path), "security.selinux"])
    return SimpleNamespace(origin=origin, export=lambda arm: local,
                           fs=lambda arm: properties), properties


def test_origin_roundtrip_retains_independent_os_label(caps):
    fixture, _ = caps
    subject.test_xattr_round_trips_to_the_origin(fixture, subject.STAGED)
    assert subject._local_xattrs(fixture.origin / subject.PROBE) == []


def test_unexpected_user_metadata_still_fails(caps):
    fixture, _ = caps
    os.setxattr(fixture.origin / subject.PROBE, "user.unexpected", b"wrong")
    with pytest.raises(AssertionError, match="dead-property xattr"):
        subject.test_xattr_round_trips_to_the_origin(fixture, subject.DIRECT)


def test_local_storage_mutation_still_fails(caps):
    fixture, properties = caps
    properties.write_local = True
    with pytest.raises(AssertionError, match="local file"):
        subject.test_xattr_does_not_touch_local_storage(fixture, subject.STAGED)
