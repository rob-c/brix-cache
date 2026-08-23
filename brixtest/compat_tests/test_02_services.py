"""Compatibility examples for uniform test services.

Nothing here touches a static server, so the file carries no
declaration marker and the gate reads it as clean — services are
reachable without owning any part of the fleet.
"""

from __future__ import annotations

import pytest

from brixtest.errors import ArtifactNotFound, SpecError, WaitTimeout
from brixtest.services import make_payload, verify_payload, wait_until

MOTD_TEXT = "welcome to the BriXTest project\n"


def test_03_artifacts_resolve_by_name(brix):
    """The catalog answers by name, and a miss names what does exist."""
    motd = brix.fleet.artifacts.root / "motd.txt"
    motd.parent.mkdir(parents=True, exist_ok=True)
    motd.write_text(MOTD_TEXT)
    brix.fleet.artifacts.publish("motd", motd, note="test message")
    motd = brix.artifact("motd")
    assert motd.read_text() == MOTD_TEXT
    with pytest.raises(ArtifactNotFound) as err:
        brix.artifact("no-such-artifact")
    assert "motd" in str(err.value)


def test_04_workspaces_are_unique_and_lane_scoped(brix, request):
    """Every invocation gets a fresh directory inside the lane; asking
    again for the same test id never hands back an old workspace."""
    assert brix.workspace.is_dir()
    assert brix.fleet.lane.contains_path(brix.workspace)
    again = brix.fleet.workspaces.for_test(request.node.nodeid)
    assert again != brix.workspace
    assert again.parent == brix.workspace.parent
    assert again.is_dir()


def test_05_payloads_are_deterministic_and_verifiable(brix):
    """Same (seed, size) -> same bytes; a corrupted copy is refused
    with the offset of the first differing byte."""
    original = make_payload(brix.workspace, size=1 << 16, seed=7)
    copy = make_payload(brix.workspace, size=1 << 16, seed=7, name="copy.bin")
    assert copy.sha256 == original.sha256
    verify_payload(copy.path, original)
    damaged = bytearray(copy.path.read_bytes())
    damaged[12345] ^= 0xFF
    copy.path.write_bytes(bytes(damaged))
    with pytest.raises(SpecError) as err:
        verify_payload(copy.path, original)
    assert "offset 12345" in str(err.value)


def test_06_wait_until_returns_the_value_and_names_the_wait():
    """``wait_until`` hands back the truthy observation, and a timeout
    error says *what* was being waited for — never a bare sleep loop."""
    counter = {"n": 0}

    def probe():
        counter["n"] += 1
        return "done" if counter["n"] >= 3 else ""

    assert wait_until(probe, timeout=5.0, poll=0.01, what="the counter to fill") == "done"
    with pytest.raises(WaitTimeout) as err:
        wait_until(lambda: 0, timeout=0.2, poll=0.05, what="a nonzero answer")
    assert "a nonzero answer" in str(err.value)
