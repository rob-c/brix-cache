"""The single door onto ``make`` in the client tree.

Seventy-seven suite modules (eighty-five sites) ran ``subprocess.run(["make", "-C", CLIENT_DIR, …])``
themselves, none behind a lock (history-testing-and-incidents §24.16).  GNU
make has no cross-process lock: two xdist workers reaching two of those sites
on a tree with one stale object both compile it and both re-archive
``libbrix.a``, and the second archive or link reads a half-written input.  It
never redded in 41 fail-fast lanes only because each lane refused to launch
until ``make -C client -q`` was clean; the 16:04:38 artifact of 09-07 (three
fresh ``.o``, a fresh ``.a``, twelve untouched bins) is what a killed in-lane
default-target make leaves behind for the next session.

``client_make`` runs the same argv under a blocking flock keyed by the client
tree's realpath, so every caller — any worker, any lane, the pre-flight —
serializes on the tree it is about to mutate.  The keyword arguments are the
caller's and reach ``subprocess.run`` unchanged: a non-zero exit and a
``TimeoutExpired`` arrive exactly as they did, and the lock is released on
every path.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import subprocess

__all__ = ["client_make", "make_lock_path"]

# Not ``tempfile.gettempdir()``: the suite pins TMPDIR per lane at settings
# import, and this lock has to span lanes — two lanes on one tree is the case.
_LOCK_DIR = "/tmp"


def make_lock_path(client_dir):
    """The lock file for one client tree: outside the tree (a ``make clean``
    must not unlink the inode everyone else is blocked on) and keyed by the
    realpath, so two spellings of the same directory share one lock."""
    key = hashlib.sha1(os.path.realpath(client_dir).encode()).hexdigest()[:12]
    return os.path.join(_LOCK_DIR, f"brix-client-make-{key}.lock")


@contextlib.contextmanager
def _tree_lock(client_dir):
    import fcntl  # noqa: PLC0415 — Linux-only, imported lazily (kdc.py idiom)
    fd = os.open(make_lock_path(client_dir), os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)  # blocking: the other caller's make finishes first
        yield
    finally:
        os.close(fd)  # closing drops the flock on every path, TimeoutExpired included


def client_make(client_dir, *targets, **run_kwargs):
    """``subprocess.run(["make", "-C", client_dir, *targets], **run_kwargs)``
    under the tree lock.  ``run_kwargs`` are the caller's (``capture_output``,
    ``text``, ``timeout``, ``env``, ``stdout``, ``stderr``); ``check`` keeps
    subprocess's default, so callers inspect ``returncode`` as before."""
    with _tree_lock(client_dir):
        return subprocess.run(["make", "-C", str(client_dir), *targets], **run_kwargs)
