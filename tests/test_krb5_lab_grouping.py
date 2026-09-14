"""Keep fixed lab owners together using pure scheduling and inert callbacks."""

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest
from xdist.scheduler.loadgroup import LoadGroupScheduling

from brix_suite.harness.xdist_groups import materialize_xdist_group


def _source_tree(filename="test_krb5_forward_live.py"):
    return ast.parse(Path(__file__).with_name(filename).read_text())


def _module_markers(tree):
    assignment = next(node for node in tree.body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == "pytestmark"
                              for target in node.targets))
    namespace = {"pytest": pytest}
    exec(compile(ast.Module(body=[assignment], type_ignores=[]), "lab-markers", "exec"), namespace)
    return namespace["pytestmark"]


class _Item:
    def __init__(self, name, markers, module="test_krb5_forward_live"):
        self._nodeid = f"tests/{module}.py::{name}"
        self.markers = markers

    @property
    def nodeid(self):
        return self._nodeid

    def iter_markers(self, name):
        return [marker.mark for marker in self.markers if marker.name == name]


class _Worker:
    def __init__(self, name):
        self.gateway = SimpleNamespace(id=name)
        self.sent = []
        self.shutting_down = False

    def send_runtest_some(self, indices):
        self.sent.append(indices)

    def shutdown(self):
        self.shutting_down = True


def _test_names(tree):
    return [node.name for node in tree.body if isinstance(node, ast.FunctionDef)
            and node.name.startswith("test_")]


def _lab_collection():
    tree = _source_tree()
    markers = _module_markers(tree)
    names = _test_names(tree)
    assert len(names) == 16
    assert [marker.args for marker in markers if marker.name == "timeout"] == [(300,)]
    items = [_Item(name, markers) for name in names]
    for item in items:
        materialize_xdist_group(item)
    return [item.nodeid for item in items]


def _schedule(collection):
    config = SimpleNamespace(getvalue=lambda name: ["popen", "popen"],
                             option=SimpleNamespace(loadscopereorder=True))
    scheduler = LoadGroupScheduling(config)
    workers = [_Worker("first"), _Worker("second")]
    for worker in workers:
        scheduler.add_node(worker)
        scheduler.add_node_collection(worker, collection)
    scheduler.schedule()
    return scheduler, workers


def test_fixed_kdc_lab_reaches_one_scheduler_worker():
    collection = _lab_collection()
    scheduler, workers = _schedule(collection)
    assert [batch for worker in workers for batch in worker.sent] == [list(range(16))]
    assert {scheduler._split_scope(node) for node in collection} == {"krb5-forward-live"}


def _guard(name, filename="test_krb5_forward_live.py", **values):
    node = next(node for node in _source_tree(filename).body if isinstance(node, ast.FunctionDef)
                and node.name == name)
    namespace = {"pytest": pytest, **values}
    exec(compile(ast.Module(body=[node], type_ignores=[]), "lab-guard", "exec"), namespace)
    return namespace[name]


def test_existing_occupied_port_guard_still_refuses_a_foreign_listener():
    checked = []

    def occupied(port):
        checked.append(port)
        return True

    guard = _guard("_guard_krb5_lab_4", _port_open=occupied, KDC_PORT="owned-port")
    with pytest.raises(pytest.skip.Exception, match="already in use"):
        guard()
    assert checked == ["owned-port"]


def test_existing_user_namespace_guard_still_refuses_unavailable_isolation():
    guard = _guard("_guard_krb5_lab_3", _userns_works=lambda: False)
    with pytest.raises(pytest.skip.Exception, match="user namespaces"):
        guard()


def _checksum_collection():
    tree = _source_tree("test_release20_checksum_plugin.py")
    markers = _module_markers(tree)
    assert [marker.name for marker in markers] == ["uses_lifecycle_harness", "xdist_group"]
    items = [_Item(name, markers, "test_release20_checksum_plugin") for name in _test_names(tree)]
    assert len(items) == 22
    for item in items:
        materialize_xdist_group(item)
    return [item.nodeid for item in items]


def test_checksum_configurations_reach_one_scheduler_worker():
    collection = _checksum_collection()
    scheduler, workers = _schedule(collection)
    assert [batch for worker in workers for batch in worker.sent] == [list(range(22))]
    assert {scheduler._split_scope(node) for node in collection} == {"lc-r20-cks-plugin"}


@pytest.mark.parametrize("returncode,stdout,stderr,expected", [
    (0, "valid registration", "", ""),
    (1, "registration error: ", "missing object", "registration error: missing object"),
    (1, "", "group- or world-writable", "group- or world-writable"),
])
def test_checksum_config_verdicts_are_preserved(returncode, stdout, stderr, expected):
    calls = []
    spec = object()

    def configure(name, check):
        calls.append(("test", name, check))
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    lifecycle = SimpleNamespace(register=lambda value: calls.append(("register", value)),
                                reconfigure=lambda name: calls.append(("reconfigure", name)),
                                nginx_test=configure)
    function = _guard("_config_test", "test_release20_checksum_plugin.py",
                      _spec=lambda **kwargs: spec, _SERVER="fixture-checksum-lab")
    assert function(lifecycle) == expected
    assert calls == [("register", spec), ("reconfigure", "fixture-checksum-lab"),
                     ("test", "fixture-checksum-lab", False)]
