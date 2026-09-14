"""Keep gateway property assertions strict while allowing independent OS labels."""

import os
from types import SimpleNamespace

import pytest

import test_ns_mutation_gateways as subject


def _mesh(origin, mode):
    """Provide only the owned origin and the ordinary property-set boundary."""
    def seed_file(plane, name):
        assert plane == subject.GW_HTTP
        (origin / name).write_bytes(b"owned origin data")

    def set_xattr(path, values):
        assert path == "/attr.bin" and values == [("user.ns", "v")]
        if mode != "missing":
            os.setxattr(origin / "attr.bin", "user.nginx_xrootd.webdav.fixture", b"v")
        if mode == "unexpected":
            os.setxattr(origin / "attr.bin", "user.unexpected", b"wrong")
        return None, [("user.ns", "v", {"ok": True})]

    return SimpleNamespace(seed_file=seed_file, store=lambda plane: origin,
                           fs=lambda plane: SimpleNamespace(set_xattr=set_xattr))


@pytest.mark.parametrize("mode", ["expected", "missing", "unexpected"])
def test_gateway_checks_user_properties_independently_of_os_labels(tmp_path, monkeypatch, mode):
    original_list = os.listxattr
    monkeypatch.setattr(subject.os, "listxattr", lambda path:
                        [*original_list(path), "security.selinux"])
    mesh = _mesh(tmp_path, mode)
    if mode == "expected":
        subject.test_xattr_through_the_http_gateway_lands_at_the_origin(mesh)
    else:
        with pytest.raises(AssertionError, match="dead-property xattr"):
            subject.test_xattr_through_the_http_gateway_lands_at_the_origin(mesh)
