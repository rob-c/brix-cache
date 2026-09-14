"""Explicit upstream feature requirements never conceal configuration errors."""

from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools/ci"))
import check_example_configs as guard
import example_config_lib as lib


@pytest.fixture
def version_output(monkeypatch):
    def select(version):
        result = subprocess.CompletedProcess(["nginx", "-v"], 0, "", version)
        monkeypatch.setattr(lib.subprocess, "run", lambda *args, **kwargs: result)
    return select


def _example(body="http { server { } }"):
    text = "# check_example_configs: min-nginx=1.21.0\n" + body
    return lib.Example("variable-client-cert.conf", text, "full")


@pytest.mark.parametrize("version", ["1.21.0", "1.28.3", "1.31.5"])
def test_supported_version_preserves_config_validation(version_output, version):
    version_output("nginx version: nginx/" + version)
    assert lib.unsupported_reason(_example(), "nginx") == ""


def test_stock_version_reports_the_unavailable_feature(version_output):
    version_output("nginx version: nginx/1.20.1")
    assert lib.unsupported_reason(_example(), "nginx") == (
        "variable-client-cert.conf requires nginx >= 1.21.0; selected 1.20.1")


def test_unrecognized_version_cannot_be_counted_as_unsupported(version_output):
    version_output("not a version")
    with pytest.raises(ValueError, match="cannot determine nginx version"):
        lib.unsupported_reason(_example(), "nginx")


def test_requirement_does_not_exempt_unknown_directives(version_output, capsys):
    version_output("nginx version: nginx/1.20.1")
    example = _example("http {\n brix_does_not_exist on;\n}")
    failures, parsed = guard._check_all([example], set(), "nginx", True, False)
    assert parsed == 0
    assert failures == [
        "variable-client-cert.conf: unknown directive(s) brix_does_not_exist"]
    assert "UNSUPPORTED" in capsys.readouterr().out
