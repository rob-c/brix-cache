"""Reference CMS daemons must use the family selected by the owned mesh."""

from pathlib import Path

import pytest

from brix_suite.mesh import cms_mesh_lib as mesh
from settings import HOST, HOST6


def _daemon_calls(calls):
    return [call for call in calls
            if call[0][0] in (mesh.CMSD_BIN, mesh.BRIX_BIN)]


def _assert_daemon_call(call, expected, root):
    argv, kwargs = call
    assert argv[1:1 + len(expected)] == expected
    option_index = 1 + len(expected)
    if argv[option_index] == "-R":
        option_index += 2
    assert argv[option_index] == "-c"
    assert Path(argv[argv.index("-c") + 1]).is_file()
    assert kwargs["cwd"] == root
    assert kwargs["start_new_session"] is True


@pytest.mark.parametrize("host, expected", [
    (HOST, ["-I", "v4"]),
    (HOST6, ["-I", "v6"]),
    ("mesh.fixture.invalid", []),
])
def test_reference_launch_selects_family_without_resolving(
    tmp_path, monkeypatch, host, expected,
):
    """Drive real config/argv construction with daemon execution intercepted."""
    monkeypatch.setattr(mesh, "MESH_DIR", str(tmp_path))
    monkeypatch.setattr(mesh, "HOST", host)
    calls = []
    monkeypatch.setattr(mesh.subprocess, "run", lambda argv, **kwargs:
                        calls.append((argv, kwargs)))
    topology = mesh.Mesh("family-fixture")
    topology.brix_node("node", "server", mesh.PORTS["b_rds"],
                      mesh.PORTS["b_rds_cms"], topology.datadir("node"),
                      "/", f"{host}:{mesh.PORTS['b_mgr_cms']}")
    daemon_calls = _daemon_calls(calls)
    assert len(daemon_calls) == 2
    assert [call[0][0] for call in daemon_calls] == [mesh.CMSD_BIN,
                                                     mesh.BRIX_BIN]
    for call in daemon_calls:
        _assert_daemon_call(call, expected, topology.root)
