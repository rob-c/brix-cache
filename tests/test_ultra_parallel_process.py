"""Wide storm actors retain complete accounting and bounded owned cleanup."""

import multiprocessing
from multiprocessing.util import Finalize
import os
import time

import pytest

import _test_ultra_parallel_helpers as U
from _test_ultra_parallel_process import spawn_grouped
from test_ultra_parallel_mixed_storm import _collect_mix, _assert_rung_clean


def _success(index):
    result = U._empty_rung(0)
    result.update(served=1, lat=[0.001], served_xfer=int(index % 4 == 0),
                  served_meta=int(index % 4 != 0), index=index, pid=os.getpid())
    return result


def _crashed(index):
    if index == 0:
        os._exit(7)
    return _success(index)


def _blocked(index):
    time.sleep(60)
    return _success(index)


def _exit_after_results(index):
    if index == 0:
        Finalize(None, os._exit, args=(7,), exitpriority=0)
    return _success(index)


def test_grouped_actors_preserve_global_indices_and_both_client_classes():
    output = [None] * 37
    spawn_grouped(_success, (), output, batch=8, startup_budget=30, operation_budget=10)
    assert [result['index'] for result in output] == list(range(37))
    assert len({result['pid'] for result in output}) == 5
    row = _collect_mix(37, output, 1, 1)
    assert row['served'] == 37 and row['served_xfer'] == 10 and row['served_meta'] == 27
    _assert_rung_clean(row)


def test_crashed_group_is_dirty_and_never_reclassified_as_unspawned():
    output = [None] * 16
    spawn_grouped(_crashed, (), output, batch=8, startup_budget=30, operation_budget=10)
    assert output[:8] == [None] * 8
    assert all(isinstance(result, dict) for result in output[8:])
    row = _collect_mix(16, output, 1, 1)
    assert row['errored'] == 8 and row['unspawned'] == 0
    with pytest.raises(AssertionError, match='dirty failures'):
        _assert_rung_clean(row)


def test_hung_actors_fail_and_all_owned_processes_are_reaped():
    before = {child.pid for child in multiprocessing.active_children()}
    output = [None] * 8
    started = time.monotonic()
    spawn_grouped(_blocked, (), output, batch=4, startup_budget=30, operation_budget=0.2)
    assert time.monotonic() - started < 15
    assert output == [None] * 8
    row = _collect_mix(8, output, 1, 1)
    assert row['errored'] == 8 and row['unspawned'] == 0
    assert {child.pid for child in multiprocessing.active_children()} <= before


def test_abnormal_exit_after_a_result_cannot_pass_the_rung():
    output = [None] * 16
    spawn_grouped(_exit_after_results, (), output, batch=8,
                  startup_budget=30, operation_budget=10)
    assert output[:8] == [None] * 8
    assert all(isinstance(result, dict) for result in output[8:])
    assert _collect_mix(16, output, 1, 1)['errored'] == 8
