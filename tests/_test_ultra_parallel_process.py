"""Keep very wide client storms from sharing a single interpreter's GIL.

Every requested actor still owns one thread and one independent session. Only
the Python scheduling domain changes; missing results remain dirty failures.
"""

import multiprocessing
from multiprocessing.connection import wait
import threading
import time

from _test_ultra_parallel_helpers import _join_until_deadline


def _actor(worker, arguments, gate, output, index, offset, startup_budget):
    """Publish only completed work; an expired gate leaves a failed output slot."""
    if gate.wait(timeout=startup_budget):
        output[index] = worker(offset + index, *arguments)


def _threads(worker, arguments, count, offset, gate, stack, startup_budget):
    """Retain the existing thread-capacity accounting within one client group."""
    output = [None] * count
    threads = []
    previous = threading.stack_size(stack)
    try:
        for index in range(count):
            thread = threading.Thread(target=_actor, daemon=True,
                args=(worker, arguments, gate, output, index, offset, startup_budget))
            try:
                thread.start()
            except RuntimeError:
                output[index:] = ['unspawned'] * (count - index)
                break
            threads.append(thread)
    finally:
        threading.stack_size(previous)
    return threads, output


def _group(worker, arguments, count, offset, release, sender, stack,
           startup_budget, operation_budget):
    """Start every local actor before joining the one global release gate."""
    local_gate = threading.Event()
    try:
        threads, output = _threads(worker, arguments, count, offset, local_gate,
                                    stack, startup_budget)
        sender.send(('ready', None))
        if release.wait(timeout=startup_budget):
            local_gate.set()
        _join_until_deadline(threads, time.perf_counter() + operation_budget)
        sender.send(('result', output))
    finally:
        sender.close()


def _start_group(context, worker, arguments, count, offset, release, stack,
                 startup_budget, operation_budget):
    """Own a separate result pipe so a crashed child cannot corrupt its peers."""
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_group,
        args=(worker, arguments, count, offset, release, sender, stack,
              startup_budget, operation_budget))
    try:
        process.start()
    except BaseException:
        receiver.close()
        sender.close()
        process.close()
        raise
    sender.close()
    return {'process': process, 'pipe': receiver, 'offset': offset, 'count': count,
            'ready': False, 'result': False, 'closed': False}


def _receive(group, output):
    """Require a complete, correctly sized result before replacing any slot."""
    try:
        kind, values = group['pipe'].recv()
    except (EOFError, OSError):
        group['closed'] = True
        return
    if kind == 'ready' and values is None:
        group['ready'] = True
        return
    if kind != 'result' or not isinstance(values, list) or len(values) != group['count']:
        raise RuntimeError('invalid client-group result')
    start = group['offset']
    output[start:start + group['count']] = values
    group['result'] = True


def _pending(groups, field):
    """Keep an absent report distinct from a child whose pipe has closed."""
    return [group for group in groups if not group[field] and not group['closed']]


def _read_ready(pending, output, remaining):
    """Drain only readable private pipes; one dead child cannot block its peers."""
    ready = wait([group['pipe'] for group in pending], timeout=min(0.1, remaining))
    for group in pending:
        if group['pipe'] in ready:
            _receive(group, output)


def _reports(groups, field, output, deadline):
    """Use one wall-clock budget for all client groups, including crashed ones."""
    pending = _pending(groups, field)
    while pending:
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            return
        _read_ready(pending, output, remaining)
        pending = _pending(groups, field)


def _signal_owned(processes, operation):
    """Signal only this rung's still-running children."""
    for process in processes:
        if process.is_alive():
            getattr(process, operation)()


def _discard_failed(groups, output):
    """A result packet cannot turn an abnormal child exit into a passing rung."""
    for group in groups:
        if group['result'] and group['process'].exitcode != 0:
            start = group['offset']
            output[start:start + group['count']] = [None] * group['count']


def _close_group(group):
    """Require reaping before releasing an owned process handle."""
    group['pipe'].close()
    if group['process'].exitcode is None:
        raise RuntimeError('owned storm client process did not stop')
    group['process'].close()


def _stop_groups(groups, output):
    """Reap only owned actors and keep shutdown bounded after a failed rung."""
    processes = [group['process'] for group in groups]
    _join_until_deadline(processes, time.perf_counter() + 2)
    _discard_failed(groups, output)
    _signal_owned(processes, 'terminate')
    _join_until_deadline(processes, time.perf_counter() + 5)
    _signal_owned(processes, 'kill')
    _join_until_deadline(processes, time.perf_counter() + 5)
    for group in groups:
        _close_group(group)


def spawn_grouped(worker, arguments, output, *, batch=512, stack=512 * 1024,
                  startup_budget=300, operation_budget=360):
    """Release all requested actors together across independent Python GILs."""
    context = multiprocessing.get_context('spawn')
    release = context.Event()
    groups = []
    try:
        for offset in range(0, len(output), batch):
            count = min(batch, len(output) - offset)
            groups.append(_start_group(context, worker, arguments, count, offset,
                release, stack, startup_budget, operation_budget))
        _reports(groups, 'ready', output, time.perf_counter() + startup_budget)
        release.set()
        _reports(groups, 'result', output, time.perf_counter() + operation_budget)
    finally:
        release.set()
        _stop_groups(groups, output)
