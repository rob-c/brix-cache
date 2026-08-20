"""Project-config contract: success, input error, and path confinement."""

from __future__ import annotations

import json

import pytest

from brixtest.errors import SpecError
from brixtest.project import Project


def _write_servers(root, payload):
    configs = root / "configs"
    configs.mkdir()
    (configs / "servers.json").write_text(json.dumps(payload))


def test_project_loads_lane_relative_server_and_named_client(tmp_path):
    _write_servers(tmp_path, {
        "lane": {"port_base": 40100, "port_span": 20, "dynamic_port_offset": 15},
        "servers": {
            "echo": {
                "port_offsets": {"primary": 2},
                "command": ["{python}", "-c", "print('ready')"],
                "readiness": "none"
            }
        }
    })
    (tmp_path / "configs" / "clients.json").write_text(json.dumps({
        "clients": {"python": {"command": ["{python}"], "timeout": 2.0}}
    }))

    project = Project.load(tmp_path, env={})

    assert project.servers[0].primary_port == 40102
    assert project.clients.names() == ("python",)
    assert project.clients.get("python").command


def test_project_rejects_unknown_server_field(tmp_path):
    _write_servers(tmp_path, {
        "servers": {
            "echo": {
                "command": ["/bin/true"],
                "readyness": "tcp"
            }
        }
    })

    with pytest.raises(SpecError) as error:
        Project.load(tmp_path, env={})

    assert "readyness" in str(error.value)
    assert "unknown field" in str(error.value)


def test_project_rejects_client_shell_string(tmp_path):
    _write_servers(tmp_path, {"servers": {}})
    (tmp_path / "configs" / "clients.json").write_text(json.dumps({
        "clients": {"unsafe": {"command": "echo this is not an argv"}}
    }))

    with pytest.raises(SpecError) as error:
        Project.load(tmp_path, env={})

    assert "non-empty array" in str(error.value)


def test_project_rejects_template_path_escape(tmp_path):
    _write_servers(tmp_path, {
        "servers": {
            "echo": {
                "command": ["/bin/true"],
                "config_template": "../outside.conf"
            }
        }
    })

    with pytest.raises(SpecError) as error:
        Project.load(tmp_path, env={})

    assert "must stay inside" in str(error.value)
