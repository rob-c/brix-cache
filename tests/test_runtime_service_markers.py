"""Service prerequisites are judged after fleet startup, not during imports."""

import ast
import os
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture(scope="module")
def service_conditions():
    """Read the actual security-suite marks without importing their subjects."""
    root = Path(__file__).parent
    files = ("test_malicious_credentials.py", "test_attack_vectors.py",
             "test_evil_paths.py", "_test_evil_paths_helpers.py")
    conditions = [condition for filename in files
                  for condition in _file_conditions(root / filename)]
    assert len(conditions) == 8, "service prerequisite census changed"
    return conditions


def _service_mark(node):
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "skipif" and bool(node.args))


def _file_conditions(path, probe="_port_up"):
    for node in ast.walk(ast.parse(path.read_text())):
        if _service_mark(node) and probe in ast.unparse(node.args[0]):
            condition = ast.literal_eval(node.args[0])
            assert isinstance(condition, str), "service probe ran during import"
            yield condition


def _namespace(probe):
    return {"_port_up": probe, "_HAVE_REQUESTS": True,
            "NGINX_HTTP_WEBDAV_PORT": 1, "NGINX_WEBDAV_PORT": 2,
            "NGINX_WEBDAV_GSI_TLS_PORT": 3, "NGINX_S3_PORT": 4}


def test_healthy_services_are_checked_only_at_execution(service_conditions):
    calls = []
    for condition in service_conditions:
        before = len(calls)
        marker = pytest.mark.skipif(condition, reason="service readiness")
        namespace = _namespace(lambda port: calls.append(port) or True)
        assert len(calls) == before
        assert eval(marker.args[0], namespace) is False
        assert len(calls) == before + 1


def test_unreachable_service_still_skips(service_conditions):
    for condition in service_conditions:
        assert eval(condition, _namespace(lambda _port: False)) is True


def test_previous_health_cannot_authorize_a_now_missing_service(service_conditions):
    state = {"healthy": True}
    namespace = _namespace(lambda _port: state["healthy"])
    for condition in service_conditions:
        state["healthy"] = True
        marker = pytest.mark.skipif(condition, reason="service readiness")
        state["healthy"] = False
        assert eval(marker.args[0], namespace) is True


@pytest.fixture(params=["test_client_autorefresh.py", "test_client_robustness.py"])
def client_condition(request):
    """Read each native-client live prerequisite without importing the test."""
    conditions = list(_file_conditions(Path(__file__).with_name(request.param), "_server_up"))
    assert len(conditions) == 1
    return conditions[0]


def _client_namespace(binary, fixture, probe):
    """Supply only the declared inputs to a client's readiness expression."""
    paths = SimpleNamespace(join=os.path.join,
                            exists=lambda path: binary if path == "/bin/xrdcp" else fixture)
    return {"os": SimpleNamespace(path=paths), "XRDCP": "/bin/xrdcp",
            "DATA_DIR": "/fixtures", "_server_up": probe}


def test_client_readiness_is_not_cached_during_collection(client_condition):
    """A server coming up after import runs; later loss cannot inherit health."""
    calls = []
    state = {"online": True}
    marker = pytest.mark.skipif(client_condition, reason="client readiness")
    namespace = _client_namespace(True, True, lambda: calls.append(1) or state["online"])
    assert not calls
    assert eval(marker.args[0], namespace) is False
    assert calls == [1]
    state["online"] = False
    assert eval(marker.args[0], namespace) is True


@pytest.mark.parametrize("binary,fixture,online", [(False, True, True),
                                                  (True, False, True),
                                                  (True, True, False)])
def test_client_missing_prerequisite_still_skips(client_condition, binary, fixture, online):
    """A missing executable, fixture or live endpoint cannot run a false proof."""
    assert eval(client_condition, _client_namespace(binary, fixture, lambda: online)) is True


@pytest.mark.parametrize('name', ['test_ci_lane_ownership_gate', 'test_fleet_teardown_orphans'])
def test_host_inventory_uses_serial_scheduling_not_skips(name):
    """Host-wide native snapshots still run, without unrelated xdist exec races."""
    import importlib

    module = importlib.import_module(name)
    marks = module.pytestmark if isinstance(module.pytestmark, list) else [module.pytestmark]
    names = {mark.name for mark in marks}
    assert 'serial' in names
    assert names.isdisjoint({'skip', 'skipif'})


def test_serial_inventory_retains_deliberately_competing_harness_proofs():
    """Isolation does not remove the actual foreign-owner or prefix-sibling cases."""
    import test_ci_lane_ownership_gate as suite

    assert callable(suite.test_reaping_a_lane_someone_else_claims_is_refused)
    assert callable(suite.test_a_prefix_sibling_lane_is_not_claimed)
