"""Test TLS fixture address ownership without DNS lookups or live listeners."""

import errno
import socket
from types import SimpleNamespace

import pytest

import _test_audit16y_helpers as tls_fixture
from settings import HOST, HOST6, SERVER_HOST


class Listener:
    def __init__(self, family, failure=None):
        self.family = family
        self.failure = failure
        self.operations = []
        self.close_count = 0

    def setsockopt(self, *arguments):
        self.operations.append(("option", arguments))

    def bind(self, address):
        self.operations.append(("bind", address))
        if self.failure:
            raise self.failure

    def listen(self, backlog):
        self.operations.append(("listen", backlog))

    def settimeout(self, timeout):
        self.operations.append(("timeout", timeout))

    def close(self):
        self.close_count += 1


@pytest.fixture
def factory(monkeypatch):
    state = SimpleNamespace(answers=[], listeners=[], threads=[], certificates=[],
                            failure=None, lookups=[])

    def resolve(host, port, **options):
        state.lookups.append((host, port, options))
        return state.answers

    def allocate(family, kind, protocol):
        assert kind == socket.SOCK_STREAM and protocol == socket.IPPROTO_TCP
        failure = state.failure if state.listeners else None
        listener = Listener(family, failure)
        state.listeners.append(listener)
        return listener

    def thread(**options):
        item = SimpleNamespace(options=options, started=False, joined=False)
        item.start = lambda: setattr(item, "started", True)
        item.join = lambda timeout: setattr(item, "joined", True)
        state.threads.append(item)
        return item

    context = SimpleNamespace(load_cert_chain=lambda *args: state.certificates.append(args))
    monkeypatch.setattr(tls_fixture.socket, "getaddrinfo", resolve)
    monkeypatch.setattr(tls_fixture.socket, "socket", allocate)
    monkeypatch.setattr(tls_fixture.ssl, "SSLContext", lambda protocol: context)
    monkeypatch.setattr(tls_fixture.threading, "Thread", thread)
    return state


def _answer(family, address):
    return family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", address


def _assert_listener_threads(peer, factory):
    assert len(factory.listeners) == len(factory.threads) == 2
    for thread, listener in zip(factory.threads, factory.listeners):
        assert thread.started
        assert thread.options["target"].__self__ is peer
        assert thread.options["args"] == (listener,)


def test_both_families_share_the_certificate_and_transcript(factory):
    ipv4 = _answer(socket.AF_INET, (HOST, 11941))
    ipv6 = _answer(socket.AF_INET6, (HOST6, 11941, 0, 0))
    factory.answers = [ipv6, ipv4, ipv4]

    peer = tls_fixture.GotoTlsUpstream(SERVER_HOST, 11941, "peer.pem", "peer.key")
    try:
        assert factory.lookups == [(SERVER_HOST, 11941,
                                   {"type": socket.SOCK_STREAM,
                                    "proto": socket.IPPROTO_TCP})]
        assert factory.certificates == [("peer.pem", "peer.key")]
        _assert_listener_threads(peer, factory)
        assert ("bind", ipv6[-1]) in factory.listeners[0].operations
        assert ("bind", ipv4[-1]) in factory.listeners[1].operations
        peer._record("tls-established", "IPv6")
        peer._record("tls-established", "IPv4")
        assert peer.details("tls-established") == ["IPv6", "IPv4"]
    finally:
        peer.close()
    assert all(listener.close_count == 1 for listener in factory.listeners)
    assert all(thread.joined for thread in factory.threads)


def test_partial_bind_failure_closes_owned_sockets_and_stays_an_error(factory):
    factory.answers = [_answer(socket.AF_INET6, (HOST6, 11942, 0, 0)),
                       _answer(socket.AF_INET, (HOST, 11942))]
    failure = OSError(errno.EADDRINUSE, "fixture port already occupied")
    factory.failure = failure

    with pytest.raises(OSError) as caught:
        tls_fixture.GotoTlsUpstream(SERVER_HOST, 11942, "peer.pem", "peer.key")

    assert caught.value is failure
    assert len(factory.listeners) == 2
    assert all(listener.close_count == 1 for listener in factory.listeners)
    assert factory.threads == []


def test_ipv6_bind_stays_within_its_family_and_teardown_ownership(factory):
    address = (HOST6, 11943, 0, 0)
    factory.answers = [_answer(socket.AF_INET6, address)]
    unrelated = Listener(socket.AF_INET)
    peer = tls_fixture.GotoTlsUpstream(SERVER_HOST, 11943, "peer.pem", "peer.key")
    listener = factory.listeners[0]
    expected = ("option", (socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1))
    assert expected in listener.operations
    assert listener.operations.index(expected) < listener.operations.index(("bind", address))
    assert ("timeout", 0.2) in listener.operations

    peer.close()

    assert listener.close_count == 1
    assert unrelated.close_count == 0
    assert factory.threads[0].joined
