"""Real nginx -t checks keep bootstrap diagnostics in their owned prefix."""

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from brix_suite.launcher import internal_operations
from cmdscripts.live_common import (
    inject_nginx_load_modules,
    inject_nginx_runtime_paths,
)
from fleet_lifecycle_ports import PARSE_PLACEHOLDER_PORT
from config_templates import render_config
from server_launcher_errors import RegistryCommandFailure
from settings import BIND_HOST, NGINX_BIN


@pytest.fixture
def config_check(tmp_path):
    """Use the real launcher invocation seam and nginx, without any listener."""
    binary = os.environ.get("TEST_NGINX_BIN", NGINX_BIN)
    if not os.access(binary, os.X_OK):
        pytest.skip(f"nginx not executable: {binary}")

    def run(name, extra=(), invalid=False):
        prefix = tmp_path / name
        data = prefix / "data"
        data.mkdir(parents=True)
        config = prefix / "nginx.conf"
        config.write_text(_config_body(data, invalid), encoding="utf-8")
        inject_nginx_load_modules(config, nginx_bin=binary)
        inject_nginx_runtime_paths(config, prefix)
        endpoint = SimpleNamespace(prefix=str(prefix), config=str(config))
        namespace = {
            "_nginx_bin": lambda: binary,
            "endpoint_for": lambda _spec: endpoint,
            "RegistryCommandFailure": RegistryCommandFailure,
        }
        result = internal_operations.nginx(
            ["-t", "-p", str(prefix), "-c", str(config), *extra],
            endpoint, None, True, namespace,
        )
        return result, prefix / "logs/error.log"

    return run


def _config_body(data, invalid):
    refusal = "brix_bootstrap_invalid_directive on;" if invalid else ""
    return render_config("nginx_bootstrap_logging.conf", strict=True,
                         BIND_HOST=BIND_HOST, PARSE_PORT=PARSE_PLACEHOLDER_PORT,
                         DATA=data, REFUSAL=refusal)



def test_merge_notices_reach_the_owned_error_log(config_check):
    result, log = config_check("accepted")
    body = log.read_text(encoding="utf-8")
    assert result.returncode == 0
    assert "brix: read_only on - the export is read-only" in body
    assert "endpoint ready" in body and "(read-only)" in body
    assert "endpoint ready" not in result.stderr


def test_rejected_config_keeps_fatal_diagnostics(config_check):
    with pytest.raises(RegistryCommandFailure) as failure:
        config_check("rejected", invalid=True)
    error = failure.value
    body = (Path(error.logs_dir) / "error.log").read_text(encoding="utf-8")
    assert error.returncode != 0
    assert 'unknown directive "brix_bootstrap_invalid_directive"' in error.stderr_tail
    assert "[emerg]" in body and "brix_bootstrap_invalid_directive" in body


def test_explicit_bootstrap_log_does_not_contaminate_another_prefix(
        config_check, tmp_path):
    _result, first_log = config_check("first")
    original = first_log.read_bytes()
    selected = tmp_path / "explicit-bootstrap.log"
    _result, second_log = config_check("second", extra=("-e", str(selected)))
    body = selected.read_text(encoding="utf-8")
    assert "endpoint ready" in body and "(read-only)" in body
    assert "endpoint ready" not in second_log.read_text(encoding="utf-8")
    assert first_log.read_bytes() == original
