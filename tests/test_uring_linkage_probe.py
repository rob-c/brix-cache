"""Ring capability classification uses real resolved linkage on every host."""

import subprocess

import pytest

import test_audit15i_plane_pins as pins


@pytest.mark.parametrize("evidence", [
    "liburing.so.2 => /usr/lib64/liburing.so.2 (0x1234)\n",
    "binary:\n\t/opt/sdk/lib/liburing.2.dylib (compatibility version 2.0.0)\n",
])
def test_resolved_ring_library_is_detected(monkeypatch, evidence):
    """Success: selected ELF and Mach-O dependency evidence is recognized."""
    monkeypatch.setattr(pins, "linked_libraries", lambda path, **kwargs: evidence)
    assert pins._object_links_liburing("binary")


def test_inspector_failure_is_not_a_capability_skip(monkeypatch):
    """Error: an uninspectable binary cannot silently downgrade coverage."""
    def fail(path, **kwargs):
        raise subprocess.CalledProcessError(1, ["inspector", path])

    monkeypatch.setattr(pins, "linked_libraries", fail)
    with pytest.raises(subprocess.CalledProcessError):
        pins._object_links_liburing("broken")


def test_unresolved_ring_library_is_not_support(monkeypatch):
    """Negative: a missing dependency is not a compiled usable capability."""
    monkeypatch.setattr(pins, "linked_libraries",
                        lambda path, **kwargs: "liburing.so.2 => not found\n")
    assert not pins._object_links_liburing("binary")
