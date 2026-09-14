"""Check the actual gateway render callers without starting their servers."""

from pathlib import Path
from types import SimpleNamespace

import pytest

import config_templates
import test_data_substreams_gateway as gateway


@pytest.fixture(params=["origin", "gateway"])
def rendered(request, monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(config_templates, "CONFIG_DIR", Path(__file__).parent / "configs")

    def render(name, destination, **values):
        calls.append((name, values))
        return config_templates.render_config_to_path(name, destination, strict=True, **values)

    monkeypatch.setattr(gateway, "render_config_to_path", render)
    destination = tmp_path / "rendered.conf"
    getattr(gateway, "_" + request.param + "_conf")(tmp_path, destination)
    name, values = calls[0]
    return SimpleNamespace(kind=request.param, name=name, values=values,
                           text=destination.read_text())


def test_actual_callers_render_single_structural_braces(rendered):
    tokens = [line.split() for line in rendered.text.splitlines()]
    assert ["events", "{", "worker_connections", "64;", "}"] in tokens
    assert ["stream", "{"] in tokens
    assert ["server", "{"] in tokens
    assert rendered.text.count("{") == rendered.text.count("}") == 3
    assert config_templates.unresolved_placeholders(rendered.text) == []


def test_incomplete_module_selection_is_rejected_by_strict_render(rendered):
    values = dict(rendered.values)
    del values["BRIX_MODULE"]
    with pytest.raises(ValueError, match="BRIX_MODULE"):
        config_templates.render_config(rendered.name, strict=True, **values)


def test_render_preserves_explicit_export_and_write_policy(rendered):
    lines = {line.strip() for line in rendered.text.splitlines()}
    assert "brix_root on;" in lines
    assert "brix_auth none;" in lines
    assert "brix_allow_write on;" in lines
    assert "brix_export " + rendered.values["DATA_DIR"] + ";" in lines
    assert "load_module " + rendered.values["BRIX_MODULE"] + ";" in lines
    if rendered.kind == "gateway":
        _check_gateway_backend(rendered.values, lines)


def _check_gateway_backend(values, lines):
    assert "brix_stage_flush sync;" in lines
    backend = "root://" + values["HOST"] + ":" + str(values["ORIGIN_PORT"])
    assert "brix_storage_backend " + backend + ";" in lines
