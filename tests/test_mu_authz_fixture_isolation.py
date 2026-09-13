"""MU lifecycle fixtures must not consume another worker's authorization policy."""

import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from mu_authz_lib import ports, principals
from settings import HOST


def _capture_start(specs, shared_authdb, spec):
    # Reproduce the policy-renderer's write between fixture setup and nginx -t.
    shared_authdb.write_text("# concurrent XrdAcc policy\nid somebody / rl\n")
    specs.append(spec)
    return SimpleNamespace(url=f"root://{HOST}:12345", port=12345)


@pytest.mark.parametrize("module,fixture,extra,expected", [
    ("test_root_open_existence_oracle", "direct_authz_env", {}, "g cms / rl\n"),
    ("test_mu_webdav_authz", "webdav_authz_env", {"cast": {}},
     "u * /cms rl\nu * /restricted rl\n"),
    ("test_mu_cache_serve_authz", "noimp_env", {"cast": {}},
     "# MU no-imp cache verification authdb\ng cms / rl\n"),
])
def test_policy_stays_private_during_concurrent_render(
        tmp_path, monkeypatch, module, fixture, extra, expected):
    shared = tmp_path / "shared"
    shared.mkdir()
    for name, suffix in (("MU_ROOT", ""), ("DATA_ROOT", "data"),
                         ("CACHE_ROOT", "cache"), ("AUTHDB", "authdb")):
        monkeypatch.setattr(ports.MU, name, str(shared / suffix))
    monkeypatch.setattr(principals, "build_cast", lambda: {})
    shared_authdb = Path(ports.MU.AUTHDB)
    specs = []
    lifecycle = SimpleNamespace(
        start=lambda spec: _capture_start(specs, shared_authdb, spec))
    setup = getattr(importlib.import_module(module), fixture).__wrapped__
    setup(lifecycle=lifecycle, tmp_path=tmp_path, **extra)

    authdb = Path(specs[-1].template_values["AUTHDB"])
    assert authdb != shared_authdb
    assert authdb.read_text() == expected
    assert "id somebody" in shared_authdb.read_text()
