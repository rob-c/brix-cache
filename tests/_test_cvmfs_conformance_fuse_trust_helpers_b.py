"""Phase-84 CVMFS conformance corpus — row ``fuse_trust``.

Theme
-----
The end-to-end **trust matrix**: forge a signed repo, tamper exactly one artifact
region, and assert the client's SAFETY property — a broken repo is either
*refused* (no mount / nonzero ``--check``) or *read-errors*, but the client NEVER
serves wrong bytes. Every refusal must be a clean, stable diagnostic, and a
refused mount must leave NO orphan behind (empty mountpoint, absent from
``/proc/mounts``); a subsequent valid mount of the same fqrn with a clean cache
must then succeed (no poisoned state).

Driver
------
Two probes, matching how a real operator would triage a repo:
  * ``brixcvmfs --check <fqrn>`` — verifies the whole trust chain + root catalog
    WITHOUT mounting (fast, no /dev/fuse). Exit 0 = healthy, nonzero + a
    ``trust/catalog error -N`` diagnostic on tamper. The full tamper matrix is
    driven here, concurrently (each ``--check`` on a persistent tamper pays the
    client's ~10 s trust-chain retry-with-backoff, so the matrix runs in a thread
    pool — otherwise ~40 serial cases would blow the wall-time budget).
  * a real FUSE mount (standalone ``brixcvmfs <fqrn> <mnt>``) — confirms the
    serve path: clean bytes read back, a content tamper read-errors (EIO) rather
    than serving corruption, and every refused mount leaves no orphan.

Trust-model facts pinned from the sources (``shared/cvmfs/signature/*``,
``shared/cvmfs/client/client.c``, ``shared/cvmfs/fetch/fetch.c``):
  * The manifest / whitelist signature covers ONLY the printed hash-line text
    (raw RSA-PKCS#1 over the literal line after ``\n--\n``); the KV/fingerprint
    *body* is not bound to the signature. So a body tamper that leaves the signed
    hash-line intact and does not break a downstream hash/fetch is ACCEPTED — a
    divergence from official CVMFS (which binds the body via the signed digest).
    Those rows are pinned ``xfail(strict)`` + ``# DIVERGENCE:``.
  * CAS object identity == SHA1 of the STORED bytes; a flipped catalog/cert/chunk
    object fails the fetch-layer hash-verify and is refused (metadata) or
    read-errors (content) — never served.
  * Cert trust = fingerprint(cert DER) ∈ whitelist fingerprint list AND manifest
    signature verifies under that cert.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import (BRIXMOUNT, MOCK, _unmount, _wait_mounted,  # noqa: E402
                                check_repo)
from cmdscripts.cvmfs_driver_units import (  # noqa: E402
    BRIXCVMFS_CORE_DEPS,
    BRIXCVMFS_DRIVER_SRCS,
)
from repo_forge import Dir, File, RepoForge  # noqa: E402
from ephemeral_port import free_port  # noqa: E402
from settings import HOST

REPO = "trust.cern.ch"
pytestmark = pytest.mark.timeout(180)

# The 20-port block 13420-13439 is reserved for this file (conformance_common
# PORT_BLOCKS['fuse_trust']); the concurrent tamper matrix needs ~40 mock origins
# at once, so it draws ephemeral ports via free_port() — the same pattern the
# Wave-1 smoke suite uses for its webroot mocks.

# ---------------------------------------------------------------------------
# process bookkeeping: every mock/mount is torn down at module exit, always.
# ---------------------------------------------------------------------------
_PROCS: list[subprocess.Popen] = []
_WORKDIRS: list[str] = []
_LOCK = threading.Lock()


@pytest.fixture(scope="module")
def matrix() -> dict[str, tuple[int, str, str]]:
    """Run every registered --check tamper case concurrently; yield {cid: result}."""
    binary = _build_brixcvmfs()
    if binary is None:
        pytest.skip(f"cannot build brixcvmfs --check binary: {_BUILD_ERR}")
    os.environ["BRIXCVMFS_BIN"] = binary

    results: dict[str, tuple[int, str, str]] = {}
    try:
        with ThreadPoolExecutor(max_workers=12) as ex:
            futs = {ex.submit(fn): cid for cid, _kind, fn in _CASES}
            for fut, cid in [(f, futs[f]) for f in futs]:
                results[cid] = fut.result()
        yield results
    finally:
        with _LOCK:
            for p in _PROCS:
                if p.poll() is None:
                    p.terminate()
            for p in _PROCS:
                try:
                    p.wait(3)
                except subprocess.TimeoutExpired:
                    p.kill()
            for d in _WORKDIRS:
                shutil.rmtree(d, ignore_errors=True)
            _PROCS.clear()
            _WORKDIRS.clear()


# ---------------------------------------------------------------------------
# matrix assertions — one collected test per registered case.
# ---------------------------------------------------------------------------

def _ids(kind):
    return [c[0] for c in _CASES if c[1] == kind]

class _Mount:
    """Mount a forged repo via the standalone ``brixcvmfs <fqrn> <mnt>`` and
    ALWAYS unmount on exit — an orphaned FUSE mount wedges the whole fleet."""

    def __init__(self, binary: str, web: str, pub: str, cache: str | None = None):
        self.binary, self.url, self.pub = binary, _serve(web), pub
        self.cache = cache
        self.wd = _workdir("ft_mnt.")
        self.mnt = os.path.join(self.wd, "mnt")
        os.mkdir(self.mnt)
        self.proc: subprocess.Popen | None = None

    def __enter__(self):
        cache = self.cache or os.path.join(self.wd, "cache")
        os.makedirs(cache, exist_ok=True)
        env = {**os.environ, "BRIXCVMFS_SERVER": self.url, "BRIXCVMFS_PUBKEY": self.pub,
               "BRIXCVMFS_CACHE": cache, "BRIXCVMFS_TMP": os.path.join(self.wd, "tmp")}
        os.makedirs(env["BRIXCVMFS_TMP"], exist_ok=True)
        self.proc = _track(subprocess.Popen(
            [self.binary, REPO, self.mnt, "-o", "auto_unmount", "-f"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        _wait_mounted(self.mnt, 20)
        return self

    @property
    def mounted(self) -> bool:
        return os.path.ismount(self.mnt)

    def __exit__(self, *_):
        from pathlib import Path
        _unmount(Path(self.mnt))
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        _unmount(Path(self.mnt))


@pytest.fixture(scope="module")
def bin_mount(matrix) -> str:
    """The built binary (matrix fixture guarantees it and BRIXCVMFS_BIN)."""
    return os.environ["BRIXCVMFS_BIN"]


@requires_fuse

def _broken_wrong_pubkey():
    forge, web, pub = _forge()
    k = RepoForge.gen_key(_workdir("ft_bp.") + "/k.key")
    open(pub, "wb").write(subprocess.run(["openssl", "pkey", "-in", str(k), "-pubout"],
                                         check=True, stdout=subprocess.PIPE).stdout)
    return web, pub


def _broken_manifest_sig():
    forge, web, pub = _forge()
    forge.flip_byte("manifest", -5)
    return web, pub


def _broken_whitelist_sig():
    forge, web, pub = _forge()
    forge.flip_byte("whitelist", -5)
    return web, pub


def _broken_catalog_obj():
    forge, web, pub = _forge()
    forge.flip_byte(next(k for k in forge.cas if k.endswith("C")), 8)
    return web, pub
