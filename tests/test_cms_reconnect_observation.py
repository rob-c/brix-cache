"""Reconnect proof waits for parsed LOGIN, not an accept-thread scheduling race."""
from types import SimpleNamespace
import threading

import pytest

import test_cms_resilience as resilience


def _peer(parsed, complete):
    """Model accepted sockets independently from completed protocol frames."""
    observations = []

    def wait_frames(code, count, timeout):
        observations.append((code, count, timeout))
        if complete:
            peer.logins = parsed
        return complete

    peer = SimpleNamespace(connections=2, logins=1, _lock=threading.Lock(),
                           wait_connections=lambda *args, **kwargs: True,
                           wait_frames=wait_frames)
    return peer, observations


def test_reconnect_waits_for_the_reader_to_parse_the_second_login():
    """Success: a reader scheduled after accept still supplies the proof."""
    peer, observations = _peer(2, True)
    resilience.test_client_reconnects_when_manager_silent(peer)
    assert observations == [(resilience.CMS_RR_LOGIN, 2, 20.0)]


def test_a_connection_without_a_second_login_cannot_pass():
    """Error: accepted sockets alone never establish a protocol reconnect."""
    peer, observations = _peer(1, False)
    with pytest.raises(AssertionError, match='did not re-issue LOGIN'):
        resilience.test_client_reconnects_when_manager_silent(peer)
    assert observations == [(resilience.CMS_RR_LOGIN, 2, 20.0)]


def test_duplicate_logins_on_one_connection_cannot_fake_a_reconnect():
    """Security-negative: both parsed LOGIN and a fresh connection are required."""
    peer, _ = _peer(2, True)
    peer.connections = 1
    with pytest.raises(AssertionError, match='fresh connection'):
        resilience.test_client_reconnects_when_manager_silent(peer)
