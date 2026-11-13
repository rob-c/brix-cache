"""A released mount must finish normally; stubborn owned children are reaped."""

import importlib
import subprocess
import sys
import time

import pytest

from cvmfs import conformance_common as common
from cmdscripts import brixcvmfs_live as live


def selected_teardown(harness, monkeypatch, unmount):
    if harness in ('conformance', 'live'):
        owner, teardown = {'conformance': (common, common._terminate_mount),
                           'live': (live, live._unmount_owned)}[harness]
        monkeypatch.setattr(owner, '_unmount', unmount)
        return teardown
    module, function = harness.split(':')
    teardown = getattr(importlib.import_module(module), function)

    def after_unmount(child, mountpoint):
        unmount(mountpoint)
        teardown(child)
    return after_unmount


def start_child(tmp_path, mode):
    ready, release, finished = [tmp_path / name for name in ('ready', 'release', 'finished')]
    script = '''
from pathlib import Path
import signal, sys, time
ready, release, finished = map(Path, sys.argv[1:4])
mode = sys.argv[4]
if mode == 'stubborn':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
ready.touch()
while not release.exists():
    time.sleep(0.01)
time.sleep(0.1)
finished.write_text('normal exit')
'''
    child = subprocess.Popen([sys.executable, '-c', script, str(ready),
                              str(release), str(finished), mode])
    deadline = time.monotonic() + 5
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert ready.exists()
    return child, release, finished


@pytest.mark.parametrize('mode,returncode', [('normal', 0), ('stalled', -15), ('stubborn', -9)])
@pytest.mark.parametrize('harness', ['conformance', 'live',
    'test_cvmfs_dict_client:_terminate_mount_process',
    'test_cvmfs_bundle_client:_guard_bd_mount_3',
    'test_cvmfs_packed_client:_guard_pk_mount_2',
    'test_cvmfs_mount_opts:_guard_opt_mount_2',
    'test_cvmfs_pin_root:_guard_pin_mount_1',
    'test_cvmfs_prefetch:_guard_pf_mount_1'])
def test_mount_teardown_waits_then_reaps_only_its_owner(tmp_path, monkeypatch,
                                                      mode, returncode, harness):
    child, release, finished = start_child(tmp_path, mode)

    def unmount(_path):
        if mode == 'normal':
            release.touch()

    teardown = selected_teardown(harness, monkeypatch, unmount)
    try:
        teardown(child, tmp_path / 'mount')
        assert child.returncode == returncode
        assert finished.exists() == (mode == 'normal')
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(5)
