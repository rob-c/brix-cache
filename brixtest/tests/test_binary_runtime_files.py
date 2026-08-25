"""Immutable runtime-data contracts for locally captured binaries."""

import hashlib
import stat
from pathlib import Path

import pytest

from brixtest import CapturedBinary, SpecError, binary
from brixtest.runtime.binaries import BinaryStore
from brixtest.runtime.images import OCIImageStore


def _executable(path: Path) -> Path:
    path.write_bytes(b"#!/bin/sh\nexit 0\n")
    path.chmod(0o755)
    return path


@pytest.mark.parametrize("destination", ["relative/plugin.so", "/", "/a/../plugin.so", "/a//plugin.so"])
def test_runtime_file_destinations_are_normalized_absolute_files(destination):
    with pytest.raises(SpecError, match="normalized absolute file path"):
        binary("tool", "/bin/true", runtime_files={destination: "/tmp/plugin.so"})


def test_image_only_binary_rejects_unusable_runtime_files():
    with pytest.raises(SpecError, match="require a local binary path"):
        binary(
            "tool", image="registry/tool@sha256:" + "a" * 64,
            image_path="/tool", runtime_files={"/etc/tool.conf": "/tmp/tool.conf"},
        )


def test_binary_store_captures_and_verifies_runtime_data(tmp_path):
    executable = _executable(tmp_path / "tool")
    plugin = tmp_path / "db2.so"
    plugin.write_bytes(b"stable-plugin")
    declaration = binary(
        "tool", executable, discover_libraries=False,
        runtime_files={"/usr/lib/krb5/plugins/db2.so": plugin},
    )

    captured = BinaryStore(tmp_path / "run", tmp_path).capture(declaration)
    held = captured.runtime_files["/usr/lib/krb5/plugins/db2.so"]
    plugin.write_bytes(b"later-build")

    assert held.read_bytes() == b"stable-plugin"
    assert captured.verify()
    held.write_bytes(b"corrupt")
    assert not captured.verify()


def test_binary_store_rejects_missing_runtime_source(tmp_path):
    executable = _executable(tmp_path / "tool")
    declaration = binary(
        "tool", executable, discover_libraries=False,
        runtime_files={"/etc/tool.conf": "missing.conf"},
    )
    with pytest.raises(SpecError, match="regular file"):
        BinaryStore(tmp_path / "run", tmp_path).capture(declaration)


def test_discovered_library_preserves_loader_soname(tmp_path, monkeypatch):
    executable = _executable(tmp_path / "tool")
    versioned = tmp_path / "libplugin.so.1.2"
    versioned.write_bytes(b"shared-library")
    soname = tmp_path / "libplugin.so.1"
    soname.symlink_to(versioned.name)

    def discovered(path):
        return (soname,) if path == executable.resolve() else ()

    monkeypatch.setattr("brixtest.runtime.binaries._ldd_libraries", discovered)
    captured = BinaryStore(tmp_path / "run", tmp_path).capture(
        binary("tool", executable),
    )

    assert [path.name for path in captured.libraries] == ["libplugin.so.1"]
    assert captured.libraries[0].read_bytes() == b"shared-library"


def test_declared_library_preserves_loader_soname(tmp_path):
    executable = _executable(tmp_path / "tool")
    versioned = tmp_path / "libplugin.so.1.2"
    versioned.write_bytes(b"shared-library")
    soname = tmp_path / "libplugin.so.1"
    soname.symlink_to(versioned.name)

    captured = BinaryStore(tmp_path / "run", tmp_path).capture(
        binary("tool", executable, libraries=(soname,), discover_libraries=False),
    )

    assert [path.name for path in captured.libraries] == ["libplugin.so.1"]


def test_generated_image_stages_runtime_data_at_exact_path_and_mode(tmp_path):
    executable = _executable(tmp_path / "tool")
    plugin = tmp_path / "db2.so"
    plugin.write_bytes(b"plugin")
    plugin.chmod(0o640)
    captured = CapturedBinary(
        "tool", executable, tmp_path / "lib",
        hashlib.sha256(executable.read_bytes()).hexdigest(), (),
        runtime_files={"/usr/lib/krb5/plugins/db2.so": plugin},
    )

    files, paths = OCIImageStore._stage(tmp_path / "rootfs", (captured,))
    staged = tmp_path / "rootfs/usr/lib/krb5/plugins/db2.so"

    assert paths == {"tool": "/opt/brixtest/bin/tool"}
    assert staged.read_bytes() == b"plugin"
    assert stat.S_IMODE(staged.stat().st_mode) == 0o640
    assert any(row["path"] == "/usr/lib/krb5/plugins/db2.so" for row in files)


def test_generated_image_rejects_conflicting_runtime_destination(tmp_path):
    executable = _executable(tmp_path / "tool")
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"not-the-executable")
    replacement.chmod(0o755)
    captured = CapturedBinary(
        "tool", executable, tmp_path / "lib",
        hashlib.sha256(executable.read_bytes()).hexdigest(), (),
        runtime_files={"/opt/brixtest/bin/tool": replacement},
    )
    with pytest.raises(SpecError, match="conflicting captured inputs"):
        OCIImageStore._stage(tmp_path / "rootfs", (captured,))
