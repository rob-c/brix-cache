"""Storm clients share one join deadline, including deliberately hung clients."""

from types import SimpleNamespace

import _test_ultra_parallel_helpers as storm


def test_completed_clients_all_join_with_the_remaining_budget(monkeypatch):
    clock = [0.0]
    waits = []
    monkeypatch.setattr(storm.time, "perf_counter", lambda: clock[0])

    def join(timeout):
        waits.append(timeout)
        clock[0] += 1.0

    storm._join_until_deadline([SimpleNamespace(join=join) for _ in range(3)], 5.0)
    assert waits == [5.0, 4.0, 3.0]


def test_an_expired_deadline_does_not_wait_again(monkeypatch):
    monkeypatch.setattr(storm.time, "perf_counter", lambda: 10.0)

    def forbidden(**kwargs):
        raise AssertionError("an exhausted budget must not gain a fresh wait")

    storm._join_until_deadline([SimpleNamespace(join=forbidden)], 10.0)


def test_16k_hung_clients_cannot_multiply_the_teardown_budget(monkeypatch):
    clock = [0.0]
    waits = []
    monkeypatch.setattr(storm.time, "perf_counter", lambda: clock[0])

    def hung(timeout):
        waits.append(timeout)
        clock[0] += timeout

    storm._join_until_deadline([SimpleNamespace(join=hung)] * 16384, 2.0)
    assert waits == [2.0]
    assert clock[0] == 2.0
