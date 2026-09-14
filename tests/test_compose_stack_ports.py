"""Compose fixtures may only use an available port from the shared lease range."""

from contextlib import nullcontext
from types import SimpleNamespace

import pytest

import compose_stack_ports as subject
from port_ladder import MOCK_PORT_FIRST


@pytest.mark.parametrize("busy, succeeds", [
    ([False], True),
    ([True, False], True),
    ([True, True], False),
])
def test_leased_ports_must_be_bindable(monkeypatch, busy, succeeds):
    leases = iter(range(MOCK_PORT_FIRST, MOCK_PORT_FIRST + len(busy)))
    outcomes = iter(busy)
    bound = []

    def bind(address):
        bound.append(address[1])
        if next(outcomes):
            raise OSError("fixture port already in use")

    probe = SimpleNamespace(bind=bind, setsockopt=lambda *args: None)
    monkeypatch.setattr(subject, "free_port", lambda: next(leases))
    monkeypatch.setattr(subject.socket, "socket", lambda: nullcontext(probe))
    if succeeds:
        port = subject._lease_bindable(attempts=len(busy))
        assert port == MOCK_PORT_FIRST + len(busy) - 1
    else:
        with pytest.raises(RuntimeError, match="no bindable mock port"):
            subject._lease_bindable(attempts=len(busy))
    assert bound == list(range(MOCK_PORT_FIRST, MOCK_PORT_FIRST + len(busy)))
