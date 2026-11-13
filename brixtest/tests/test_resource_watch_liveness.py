"""Missing host telemetry must not be reported as a server crash."""

import os
import subprocess
import sys
from types import SimpleNamespace

from brixtest.harness.resources import ResourceWatch


def _watch(provider):
    findings = []
    store = SimpleNamespace(add_finding=lambda _run, finding: findings.append(finding))
    return ResourceWatch(provider, store, 'fixture'), findings


def test_live_process_without_proc_telemetry_is_not_a_crash():
    pid = os.getpid()
    watch, findings = _watch(lambda: {'server': pid})
    watch._crash('server', pid, 'test_live')
    assert findings == []


def test_exited_registered_process_is_still_a_crash():
    process = subprocess.Popen([sys.executable, '-c', 'pass'])
    process.wait(timeout=5)
    watch, findings = _watch(lambda: {'server': process.pid})
    watch._crash('server', process.pid, 'test_dead')
    assert len(findings) == 1
    assert findings[0].kind == 'crash'


def test_released_process_cannot_be_reported_as_a_crash():
    watch, findings = _watch(lambda: {})
    watch._crash('server', 2147483647, 'test_released')
    assert findings == []
