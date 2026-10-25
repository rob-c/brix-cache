"""TCP probe observations must synchronize with the listener's accept thread."""

import socket

from _test_cvmfs_conformance_srv_geo_helpers import ConnCounter
from settings import HOST


def test_completed_connect_is_eventually_counted():
    listener = ConnCounter(HOST, 0)
    try:
        with socket.create_connection((HOST, listener.port), timeout=2):
            assert listener.wait_count(1) == 1
    finally:
        listener.close()


def test_missing_probe_cannot_be_reported_as_observed():
    listener = ConnCounter(HOST, 0)
    try:
        assert listener.wait_count(1, timeout=0.02) == 0
    finally:
        listener.close()


def test_closing_an_idle_listener_reaps_its_accept_thread():
    listener = ConnCounter(HOST, 0)
    listener.close()
    assert not listener._thread.is_alive()
    assert listener.wait_count(1, timeout=0) == 0
