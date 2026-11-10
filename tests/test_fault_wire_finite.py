"""Replay established wire contracts through real relays with normal teardown.

Only the test process/control transport changes: the existing tests retain their
independent upstreams and byte, counter, error and non-execution assertions.
Production relay, mutation, route, oracle and command implementations stay real.
"""

from contextlib import ExitStack
import importlib
import inspect

import pytest

from settings import HOST

from _test_brix_fault_proxy_helpers import _free_port
from test_fault_privileged_finite import command
from test_fault_proxy_control_unit import control_unit  # noqa: F401
from test_fault_route_finite import network_driver

pytestmark = pytest.mark.timeout(120)


class FiniteProxy:
    """Translate the existing test teardown request into owned EOF cleanup."""

    def __init__(self, process, lifetime):
        self.process = process
        self.lifetime = lifetime

    def terminate(self):
        self.lifetime.close()

    def wait(self, timeout=None):
        return self.process.wait(timeout=timeout)


def finite_spawn(lifetime, binary, target_port, extra=None, enable_exec=False):
    """Start a real dynamic route using the already tested finite consumer."""
    assert not extra, 'A daemon CLI option needs an explicit finite equivalent'
    owned = lifetime.enter_context(ExitStack())
    process = owned.enter_context(network_driver(binary, enable_exec=enable_exec))
    listen = _free_port()
    response = command(process, f'route add wire {listen} {HOST}:{target_port}')
    assert response.startswith('ok:'), response
    return FiniteProxy(process, owned), listen, process


def wire_cases():
    """Use each family's public test functions, preserving their assertions."""
    for family in ['mitm', 'attack', 'protocol', 'dpi', 'header_hold']:
        module = importlib.import_module('test_fault_proxy_' + family)
        for name, function in inspect.getmembers(module, inspect.isfunction):
            if name.startswith('test_'):
                yield pytest.param(module, function, id=family + ':' + name)
    yield from class_cases('fidelity', ['TestToxicity', 'TestSlowClose',
        'TestConnectDelay', 'TestRefuse', 'TestLatencyDist', 'TestRate'])
    yield from class_cases('fidelity_b', ['TestJsonControl', 'TestMetrics'])
    yield from class_cases('toxics', ['TestNamedToxics'])


def class_cases(family, classes):
    """Select relay/dispatcher classes; daemon CLI and socket-control stay separate."""
    module = importlib.import_module('test_fault_proxy_' + family)
    for name in classes:
        instance = getattr(module, name)()
        for method, contract in inspect.getmembers(instance, inspect.ismethod):
            if method.startswith('test_'):
                yield pytest.param(module, contract, id=family + ':' + name + ':' + method)


@pytest.mark.parametrize('module,contract', list(wire_cases()))
def test_wire_contract_with_normal_exit(control_unit, tmp_path, monkeypatch,
                                       module, contract):
    """Check the same live wire behavior and then require successful cleanup."""
    with ExitStack() as lifetime:
        def spawn(binary, target_port, extra=None, enable_exec=False):
            return finite_spawn(lifetime, binary, target_port, extra, enable_exec)

        monkeypatch.setattr(module, '_spawn', spawn)
        monkeypatch.setattr(module, '_ctl', command)
        arguments = {'bfp': control_unit, 'tmp_path': tmp_path}
        contract(**{name: arguments[name] for name in inspect.signature(contract).parameters})
