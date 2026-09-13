"""Pins for ``brix_suite.client_build.client_make`` — the one lock-serialized
door onto ``make`` in the client tree (history-testing-and-incidents §24.16).

  success   — two callers of one tree never run make at the same time (the
              recipe's trace reads start,end,start,end), and two spellings of
              the same directory share one lock file that lives outside it.
  error     — a failing recipe's exit code and stderr reach the caller, and a
              ``timeout=`` still raises ``TimeoutExpired`` with the lock
              released: the next caller of the same tree proceeds at once.
  security  — no module in the suite runs a bare ``subprocess.run(["make"…``
              any more (the race is closed only while every site goes through
              the door), and the detector is proven non-vacuous on a synthetic
              offender.
"""

import errno
import os
import pathlib
import re
import subprocess
import threading
import time

import pytest

from brix_suite.client_build import client_make, make_lock_path
from brix_suite import client_build

TESTS = pathlib.Path(__file__).resolve().parent
BARE_MAKE = re.compile(r'subprocess\.run\(\s*\[\s*"make"')
# Never judged: the door itself, archived shards, this file, and the operator
# CLI that builds the nginx tree — a different tree with a different lock.
EXEMPT = ("brix_suite/client_build.py", "/_legacy/", "cmdscripts/operator_build.py",
          pathlib.Path(__file__).name)

SERIAL_MAKEFILE = "slow:\n\t@echo start >> trace\n\t@sleep 0.3\n\t@echo end >> trace\n"
ERROR_MAKEFILE = "fail:\n\t@echo boom >&2; exit 3\nhang:\n\t@sleep 1\nquick:\n\t@echo ok\n"


def _tree(tmp_path, makefile):
    (tmp_path / "Makefile").write_text(makefile)
    return tmp_path


def _bare_make_sites(root):
    return sorted(str(p.relative_to(root)) for p in root.rglob("*.py")
                  if not any(e in str(p) for e in EXEMPT)
                  and BARE_MAKE.search(p.read_text(errors="replace")))


def _concurrently(fn, n):
    """Run ``fn`` on ``n`` threads at once; results in completion order."""
    results = []
    threads = [threading.Thread(target=lambda: results.append(fn())) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    return results


def test_two_callers_of_one_tree_serialize(tmp_path):
    tree = _tree(tmp_path, SERIAL_MAKEFILE)
    rcs = _concurrently(
        lambda: client_make(tree, "slow", capture_output=True, text=True, timeout=30).returncode, 2)
    assert rcs == [0, 0]
    assert (tree / "trace").read_text().split() == ["start", "end", "start", "end"]


def test_two_spellings_of_one_tree_share_one_lock_outside_it(tmp_path):
    real = tmp_path / "client"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real)
    assert make_lock_path(alias) == make_lock_path(real)
    assert make_lock_path(tmp_path) != make_lock_path(real)
    assert not make_lock_path(real).startswith(str(tmp_path))


def test_existing_lock_is_reopened_without_create_or_write(tmp_path, monkeypatch):
    lock = tmp_path / "make.lock"
    lock.write_bytes(b"unchanged")
    before = lock.stat()
    opened = []
    real_open = os.open

    def record_open(path, flags, *args):
        opened.append(flags)
        return real_open(path, flags, *args)

    monkeypatch.setattr(client_build.os, "open", record_open)
    fd = client_build._open_tree_lock(lock)
    os.close(fd)
    assert not opened[-1] & (os.O_CREAT | os.O_WRONLY | os.O_RDWR)
    assert lock.stat().st_ino == before.st_ino
    assert lock.stat().st_uid == before.st_uid
    assert lock.read_bytes() == b"unchanged"


def test_lock_open_error_is_propagated(tmp_path):
    with pytest.raises(FileNotFoundError):
        client_build._open_tree_lock(tmp_path / "absent" / "make.lock")


def test_lock_symlink_is_refused_without_touching_target(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"unchanged")
    lock = tmp_path / "make.lock"
    lock.symlink_to(target)
    with pytest.raises(OSError) as caught:
        client_build._open_tree_lock(lock)
    assert caught.value.errno == errno.ELOOP
    assert target.read_bytes() == b"unchanged"


def test_nonregular_lock_is_refused_without_blocking(tmp_path):
    lock = tmp_path / "make.lock"
    os.mkfifo(lock)
    with pytest.raises(ValueError, match="regular file"):
        client_build._open_tree_lock(lock)


def test_failure_and_stderr_reach_the_caller(tmp_path):
    tree = _tree(tmp_path, ERROR_MAKEFILE)
    proc = client_make(tree, "fail", capture_output=True, text=True, timeout=30)
    assert proc.returncode != 0
    assert "boom" in proc.stderr


def test_timeout_raises_and_releases_the_lock(tmp_path):
    tree = _tree(tmp_path, ERROR_MAKEFILE)
    with pytest.raises(subprocess.TimeoutExpired):
        client_make(tree, "hang", capture_output=True, text=True, timeout=0.3)
    t0 = time.monotonic()
    proc = client_make(tree, "quick", capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0 and "ok" in proc.stdout
    assert time.monotonic() - t0 < 3  # the hung caller's lock did not outlive it


def test_no_bare_make_outside_the_door():
    assert _bare_make_sites(TESTS) == []


def test_bare_make_detector_fires_on_the_shape(tmp_path):
    (tmp_path / "test_offender.py").write_text(
        'import subprocess\nsubprocess.run(["make", "-C", "client", "xrd"])\n')
    (tmp_path / "test_clean.py").write_text(
        'from brix_suite.client_build import client_make\nclient_make("client", "xrd")\n')
    assert _bare_make_sites(tmp_path) == ["test_offender.py"]
