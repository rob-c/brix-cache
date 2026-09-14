"""Reference CMS daemons must use the family selected by the owned mesh."""

from pathlib import Path

import pytest

from brix_suite.mesh import cms_mesh_lib as mesh
from settings import HOST, HOST6


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
    assert len(calls) == 2
    assert [call[0][0] for call in calls] == [mesh.CMSD_BIN, mesh.BRIX_BIN]
    for argv, kwargs in calls:
        assert argv[1:1 + len(expected)] == expected
        assert argv[1 + len(expected)] == "-c"
        assert Path(argv[argv.index("-c") + 1]).is_file()
        assert kwargs["cwd"] == topology.root
        assert kwargs["start_new_session"] is True
