"""Phase-108 C12: the VFS authorization backstop is a tested pytest surface."""

import os

import pytest

from _test_phase25_ratelimit_helpers import _http_values, _parse_fail
from cmdscripts.c_object_units import run_one
from settings import NGINX_BIN


_CASES = (
    "test_backstop_agrees_with_edge",
    "test_backstop_reads_are_gated_too",
    "test_backstop_unbound_refuses",
    "test_backstop_unmapped_op_refuses",
    "test_backstop_no_rules_is_distinguishable",
    "test_edge_gate_removed_still_refused",
    "test_backstop_never_more_permissive",
    "test_backstop_after_erofs",
    "test_backstop_observe_never_refuses",
    "test_backstop_handle_snapshot",
)


@pytest.fixture(scope="module")
def backstop_unit(tmp_path_factory):
    work = tmp_path_factory.mktemp("vfs-authz-backstop")
    results = run_one("vfs_authz_backstop", work)
    assert results and all(ok for ok, _ in results), "\n".join(
        message for _, message in results)
    output = "\n".join(message for _, message in results)
    if "SKIP " in output:
        pytest.skip(output)
    return output


@pytest.mark.parametrize("case", _CASES)
def test_backstop_contract(case, backstop_unit):
    """Expose each design obligation as an individually selectable pytest case."""
    assert f"ok {case}" in backstop_unit


def _location(mode):
    return "\n".join((
        "        location /authz-backstop {",
        "            brix_webdav on;",
        "            brix_storage_backend ceph:xrdtest;",
        f"            brix_authz_backstop {mode};",
        "            brix_webdav_auth none;",
        "        }",
        "",
    ))


@pytest.mark.parametrize("mode", ("off", "observe", "enforce"))
def test_authz_backstop_directive_accepts_all_modes(tmp_path, mode):
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    rc, output = _parse_fail(
        tmp_path, "nginx_rl_http.conf", _http_values("", "", _location(mode)))
    assert rc == 0, output


def test_authz_backstop_directive_rejects_unknown_mode(tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    rc, output = _parse_fail(
        tmp_path, "nginx_rl_http.conf", _http_values("", "", _location("audit")))
    assert rc != 0, output
    assert 'invalid value "audit"' in output
