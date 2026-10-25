"""Main-only proof lanes reserve their actual scope and cannot allocate mocks."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

import port_ladder
from test_ci_ts3_settings_live_lane import proof_lane_base, proof_mock_width
from test_ci_ts3_settings_live_lane import _lane_env


@pytest.mark.parametrize("parent,floor", [(10000, 32768), (30000, 49152)])
def test_proof_reservation_clears_the_full_parent_and_the_kernel(parent, floor):
    """A Linux proof fits above the parent; a high macOS lane leaves room below."""
    named = port_ladder.PORT_COUNT + proof_mock_width()
    whole = port_ladder.TOTAL_PORT_COUNT
    base = proof_lane_base(parent, whole, named, floor)
    assert base is not None and base >= 1024
    assert base + named < floor
    assert base + named < parent + 1 or parent + whole < base + 1


def test_no_geometry_is_reported_when_no_safe_reservation_fits():
    """An impossible narrow kernel window cannot yield an overlapping lane."""
    assert proof_lane_base(2048, 4000, 3000, 5000) is None


@pytest.mark.parametrize("value", ["-1", "16385", "not-an-integer"])
def test_invalid_mock_reservations_are_rejected(value):
    """Negative, excessive or malformed widths never alter allocation bounds."""
    with pytest.raises(RuntimeError, match="TEST_MOCK_PORT_WIDTH"):
        port_ladder.configured_mock_width(value)


def test_main_only_child_refuses_every_mock_draw(tmp_path):
    """Disabling unused mock capacity cannot become an unreserved allocation."""
    tests = Path(__file__).resolve().parent
    floor = 32768
    base = floor - port_ladder.PORT_COUNT - 1
    env = dict(os.environ, PYTHONPATH=str(tests), TEST_ROOT=str(tmp_path),
               TEST_PORT_START=str(base), TEST_MOCK_PORT_WIDTH="0")
    code = (
        "import json, port_ladder as p, ephemeral_port as e\n"
        "try:\n e.free_port()\nexcept RuntimeError:\n disabled = True\n"
        "else:\n disabled = False\n"
        "print(json.dumps([p.TOTAL_PORT_COUNT, p.PORT_COUNT, disabled]))\n"
    )
    result = subprocess.run([sys.executable, "-c", code], env=env,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [port_ladder.PORT_COUNT, port_ladder.PORT_COUNT, True]
    assert not (tmp_path / "mock-port-leases.json").exists()


@pytest.mark.parametrize('root_name', ['proof', 'sibling', 'deep/isolated'])
def test_proof_lane_never_inherits_parent_registry_authority(monkeypatch, tmp_path, root_name):
    """Success/error/hostile parent paths cannot move a child into another fleet."""
    monkeypatch.setenv('TEST_REGISTRY_ROOT', '/foreign/registry')
    monkeypatch.setenv('TEST_REGISTRY_MANIFEST', '/foreign/registry/manifest.json')
    root = str(tmp_path / root_name)
    child = _lane_env(root)
    assert child['TEST_ROOT'] == root
    assert child['TEST_REGISTRY_ROOT'] == str(Path(root, 'registry'))
    assert child['TEST_REGISTRY_MANIFEST'] == str(Path(root, 'registry', 'manifest.json'))
    assert os.environ['TEST_REGISTRY_ROOT'] == '/foreign/registry'
