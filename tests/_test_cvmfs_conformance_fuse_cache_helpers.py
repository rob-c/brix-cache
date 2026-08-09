# tests/test_cvmfs_conformance_fuse_cache.py — Phase-84 fuse corpus: local cache.
#
# Theme (design doc row: fuse_cache, ports 13300-13319)
# -----------------------------------------------------
# The brixcvmfs local CAS cache (shared/cache/cas_store.c) driven end-to-end
# through a real FUSE mount over a forged signed repo (repo_forge) served by
# mock_stratum1 --webroot.  The mock's /ctl/log is the origin-traffic oracle:
# every non-ctl GET is logged, so "warm serve" == zero new /data/ fetches.
#
# Pinned implementation facts (sources):
#  * fetch.c cvmfs_fetch_object: cache-first (brix_cas_has -> serve_from_cache);
#    fills store VERIFIED PLAINTEXT keyed "<hex><suffix>" at <2>/<38+suffix>.
#  * cas_store.c brix_cas_put: quota enforced synchronously at put time
#    (brix_cas_enforce_quota -> reap to 75% of quota, atime-LRU); the 30s
#    reap_tick is only the safety net for adopted-over-quota caches.
#  * client.c: whitelist/manifest are raw (never cached); cert 'X' and catalogs
#    'C' go through the caching fetch path; catalogs spill to
#    $BRIXCVMFS_TMP/brixcvmfs.cat.<pid>.XXXXXX and are unlinked on umount.
#  * brixcvmfs.c: cache dir precedence -o cache= > $BRIXCVMFS_CACHE > default
#    /var/lib/brixcvmfs/<repo>; clever overlay = pre-mount dirfd on
#    <mnt>/.brixcache (default ON, disabled by -o noclever / any explicit cache).
#
# RETIRED DIVERGENCE (cache-trust): serve_from_cache (shared/cvmfs/fetch/fetch.c)
# now re-verifies every hit against a per-entry integrity sidecar ("<key>.chk":
# plaintext hash + length, written at store time).  Damaged/truncated/
# unverifiable entries — including pre-sidecar-era caches — are purged and
# transparently refetched, matching official CVMFS's miss-on-damage behavior.
import errno
import hashlib
import itertools
import json
import os
import random
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
import zlib
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

# Defined here (not only in the base test module) so the split-continuation
# sibling (test_cvmfs_conformance_fuse_cache_c) that reexports this helper
# resolves it: trim the transport retry budget for dead-origin paths.
_FAST = ("-o", "retries=1")

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import BRIXMOUNT, PortBlock, _unmount, _wait_mounted
from conformance_common import fuse_mount as _fuse_mount_shared
from settings import ARTIFACTS_DIR


def _wait_mounted_or_dead(mnt, proc, timeout):
    """Like _wait_mounted but proc-aware: return as soon as the mount appears OR
    brixMount exits. A crashed process is then detected in ~0.1s (not after the
    full ceiling), so a bring-up retry respawns immediately instead of burning the
    whole `timeout` polling a mountpoint that will never appear."""
    import time as _t
    deadline = _t.monotonic() + timeout
    while _t.monotonic() < deadline:
        if os.path.ismount(str(mnt)) or proc.poll() is not None:
            break
        _t.sleep(0.1)
    return os.path.ismount(str(mnt))


@contextmanager
def fuse_mount(fqrn, server_url, pubkey, *, cache=None, tmp=None, mount_type="cvmfs",
               opts="auto_unmount", brixmount=None, extra_env=None, extra_args=(),
               timeout=90, bringup_retries=4):
    """Local twin of the shared fuse_mount with two conformance-corpus tweaks:
    a wider default mount-wait (under concurrent fleet/FUSE load a healthy
    brixMount can take >15s to come up) and brixMount stderr CAPTURED to a file
    (proc.stderr_path) so a mount failure carries its own diagnosis instead of
    a bare 'failed to mount' — e.g. 'trust/catalog error -5' fingerprints a
    stale mock squatting the port. Teardown mirrors the shared helper exactly:
    ALWAYS unmount, an orphaned FUSE mount wedges the whole test fleet.

    The generous `timeout` is a CEILING, not a cost: `_wait_mounted` returns the
    instant the mount appears, so a healthy mount still costs ~1s — the headroom
    only matters when a saturated box slows the fetch. `bringup_retries` re-launches
    brixMount ONLY if it EXITED before mounting (a transient crash — cheap to redo);
    a process still ALIVE at the ceiling is making progress, so relaunching would
    just discard it, and we yield instead. NEGATIVE/xfail cases that expect a mount
    to fail (dead origin, corrupt cached catalog) pass `bringup_retries=1`."""
    workdir = Path(tempfile.mkdtemp(prefix="cvmfs_mount."))
    mnt = workdir / "mnt"
    mnt.mkdir()
    env = {
        **os.environ,
        "BRIXCVMFS_SERVER": server_url,
        "BRIXCVMFS_PUBKEY": str(pubkey),
        "BRIXCVMFS_TMP": str(tmp if tmp is not None else (workdir / "tmp")),
    }
    (workdir / "tmp").mkdir(exist_ok=True)
    if cache is not None:
        env["BRIXCVMFS_CACHE"] = str(cache)
    else:
        (workdir / "cache").mkdir(exist_ok=True)
        env["BRIXCVMFS_CACHE"] = str(workdir / "cache")
    if extra_env:
        env.update(extra_env)

    argv = [brixmount or BRIXMOUNT, mount_type, fqrn, str(mnt), *extra_args, "-o", opts, "-f"]
    stderr_path = workdir / "brixmount.stderr"

    def _spawn():
        ef = open(stderr_path, "wb")
        p = subprocess.Popen(argv, env=env, stdout=subprocess.DEVNULL, stderr=ef)
        p.stderr_path = stderr_path
        return p

    def _reap(p):
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(3)
            except subprocess.TimeoutExpired:
                p.kill()

    proc = _spawn()
    for attempt in range(bringup_retries):
        _wait_mounted_or_dead(mnt, proc, timeout)
        if os.path.ismount(str(mnt)) or proc.poll() is None:
            break                        # mounted, or alive+progressing (don't thrash)
        if attempt + 1 < bringup_retries:  # exited before mounting — transient crash, respawn
            _unmount(mnt)
            time.sleep(min(2 ** attempt, 8))  # backoff so respawns span a load spike, not one instant
            proc = _spawn()
    try:
        yield mnt, proc
    finally:
        _unmount(mnt)
        _reap(proc)
        _unmount(mnt)          # belt-and-braces after the process is gone
        shutil.rmtree(workdir, ignore_errors=True)
from lib_py.util import wait_tcp
from repo_forge import Dir, File, RepoForge, Symlink
from settings import BIND_HOST, HOST

REPO = "test.cern.ch"
MOCK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs", "mock_stratum1.py")

_FUSE_READY = (os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None
               and os.path.exists(BRIXMOUNT))
# Every test here does 1-3 real FUSE mounts; under concurrent fleet/FUSE load the
# global 30s budget can lapse mid-mount, and the thread-method timeout then aborts
# the SESSION mid-test, orphaning the test's mock origin — which squats its port
# and poisons later runs with wrong-key trust failures (see MockOrigin.start).
pytestmark = [
    pytest.mark.skipif(not _FUSE_READY, reason="fuse mount prerequisites missing"),
    # This whole module asserts the FLAT cache's on-disk contract (two-hex
    # fan-out, plaintext entries + .chk sidecars, file-level corruption
    # surgery, atime-LRU reaper, clever overlay).  A packed-store parity run
    # (BRIXCVMFS_CACHE_FORMAT=packed) makes every premise false by design;
    # the packed equivalents live in test_cvmfs_packed_client.py.
    pytest.mark.skipif(os.environ.get("BRIXCVMFS_CACHE_FORMAT") == "packed",
                       reason="flat-cache layout contract — packed equivalents "
                              "live in test_cvmfs_packed_client.py"),
    pytest.mark.timeout(300),          # ceiling: a saturated box slows every mount;
]                                      # healthy runs finish each test in seconds

# This file owns the fuse_cache block (PORT_BLOCKS["fuse_cache"], shifted into
# this session's tile by PortBlock); tests run sequentially within the module,
# so cycling the block is collision-free. Nothing here may name an absolute
# port — a literal would land in ANOTHER session's tile (or the fleet's).
_BLOCK = PortBlock("fuse_cache")
_PORTS = itertools.cycle(range(_BLOCK.base, _BLOCK.base + 20))


# ---- local helpers ---------------------------------------------------------

class MockOrigin:
    """One mock Stratum-1 in --webroot mode with kill/restart for offline tests."""

    def __init__(self, web: Path, repo: str = REPO):
        self.web, self.repo = web, repo
        self.port = next(_PORTS)
        self.proc = None

    @property
    def url(self) -> str:
        return f"http://{HOST}:{self.port}/cvmfs/{self.repo}"

    def start(self) -> "MockOrigin":
        # A stale listener on a cycled port (leaked mock from a crashed run) makes
        # our fresh mock die on EADDRINUSE while wait_tcp still sees the squatter —
        # brixMount then fetches a repo signed with the WRONG keys and the mount
        # fails with trust error -5/-9.  Guard: the port is ours only if OUR mock
        # process is still alive once the port is listening; otherwise cycle on.
        for _ in range(20):
            self.proc = subprocess.Popen(
                [sys.executable, MOCK, "--port", str(self.port), "--repo", self.repo,
                 "--webroot", str(self.web)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if wait_tcp(BIND_HOST, self.port, 10) and self.proc.poll() is None:
                return self
            self.kill()                      # reap the bind-loser (or non-starter)
            self.port = next(_PORTS)         # and try the next port in the block
        raise RuntimeError("no free port in the session's fuse_cache block")

    def kill(self) -> None:
        if self.proc is None or self.proc.poll() is not None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(3)

    def restart(self) -> None:
        self.kill()
        self.start()

    def log(self) -> list:
        with urllib.request.urlopen(f"http://{HOST}:{self.port}/ctl/log", timeout=10) as r:
            return json.load(r)

    def reset_log(self) -> None:
        urllib.request.urlopen(urllib.request.Request(
            f"http://{HOST}:{self.port}/ctl/reset-log", method="POST"), timeout=10).read()

    def data_fetches(self, key: str = "", suffix: str = "") -> int:
        """GET count for one CAS object, or all /data/ traffic with no key."""
        needle = f"/data/{key[:2]}/{key[2:]}{suffix}" if key else "/data/"
        return sum(1 for e in self.log() if needle in e["path"])


@pytest.fixture
def make_origin():
    origins = []

    def _make(web: Path) -> MockOrigin:
        o = MockOrigin(web).start()
        origins.append(o)
        return o

    yield _make
    for o in origins:
        o.kill()


def _std_tree() -> dict:
    return {
        "hello": File(b"Hello fuse-cache corpus!\n"),
        "secret": File(b"trust me exactly, byte for byte\n"),
        "sub": Dir({"leaf": File(b"leaf bytes\n"),
                    "deep": Dir({"x": File(b"deep x\n")})}),
        "link": Symlink("hello"),
    }


def _quota_tree(n: int = 8, size: int = 300_000, seed: int = 7) -> dict:
    rng = random.Random(seed)
    return {f"f{i}": File(rng.randbytes(size)) for i in range(n)}


def _forge(tmp_path: Path, tree: dict, **kw):
    web = tmp_path / "web"
    pub = tmp_path / "repo.pub"
    forge = RepoForge(REPO, web, **kw).build(tree, pub)
    return forge, web, pub


def content_key(data: bytes) -> str:
    """CAS key of a compressed File node: SHA1 of the stored (zlib) bytes."""
    return hashlib.sha1(zlib.compress(data)).hexdigest()


def cache_entry(cache_dir, key: str, suffix: str = "") -> Path:
    return Path(cache_dir) / key[:2] / (key[2:] + suffix)


def cas_entries(cache_dir) -> list:
    """All '<hex><suffix>' keys present in a CAS cache dir (ignores .tmp.*)."""
    root = Path(cache_dir)
    if not root.is_dir():
        return []
    return [d.name + f.name for d in root.iterdir() if d.is_dir() and len(d.name) == 2
            for f in d.iterdir() if not f.name.startswith(".")]


def cache_du(cache_dir) -> int:
    return sum(cache_entry(cache_dir, k).stat().st_size for k in cas_entries(cache_dir))


def read_tree(mnt) -> dict:
    """Walk + read every regular file under the mount; {relpath: bytes}."""
    out = {}
    for base, dirs, files in os.walk(mnt):
        dirs[:] = [d for d in dirs if d != ".brixcache"]
        for f in files:
            p = os.path.join(base, f)
            if not os.path.islink(p):
                out[os.path.relpath(p, mnt)] = Path(p).read_bytes()
    return out


@contextmanager
def mounted(tmp_path, make_origin, tree=None, *, cache=None, forge_kw=None,
            bringup_retries=4, **mount_kw):
    """forge -> mock --webroot -> fuse_mount with an explicit cache dir. Every caller
    asserts the mount comes up, so the bring-up retry defaults ON (a starved brixMount
    on a saturated box is re-launched, never a genuinely-refused one — see fuse_mount)."""
    forge, web, pub = _forge(tmp_path, tree if tree is not None else _std_tree(),
                             **(forge_kw or {}))
    origin = make_origin(web)
    cache = Path(cache) if cache else tmp_path / "cache"
    try:
        with fuse_mount(REPO, origin.url, pub, cache=str(cache),
                        bringup_retries=bringup_retries, **mount_kw) as (mnt, proc):
            assert os.path.ismount(str(mnt)), "brixMount failed to mount the forged repo"
            yield SimpleNamespace(forge=forge, origin=origin, mnt=mnt, proc=proc,
                                  cache=cache, pub=pub, web=web)
    finally:
        forge.close()


_TMP_DEFAULT = object()


@contextmanager
def own_mount(fqrn, url, pubkey, *, mnt=None, cache_env=None, tmp_env=_TMP_DEFAULT,
              opts="auto_unmount", extra_args=(), timeout=90, bringup_retries=4):
    """brixMount with FULL env control: unlike the shared fuse_mount helper this
    can leave BRIXCVMFS_CACHE/BRIXCVMFS_TMP UNSET (clever-overlay and cache-dir
    precedence need exactly that).  Same always-unmount teardown discipline.
    `bringup_retries` behaves exactly as in `fuse_mount` (defaults ON; negative
    cases pass 1)."""
    workdir = Path(tempfile.mkdtemp(prefix="p84cache."))
    mnt = Path(mnt) if mnt is not None else workdir / "mnt"
    mnt.mkdir(exist_ok=True)
    env = {k: v for k, v in os.environ.items()
           if k not in ("BRIXCVMFS_CACHE", "BRIXCVMFS_TMP")}
    env.update({"BRIXCVMFS_SERVER": url, "BRIXCVMFS_PUBKEY": str(pubkey)})
    if cache_env is not None:
        env["BRIXCVMFS_CACHE"] = str(cache_env)
    if tmp_env is _TMP_DEFAULT:
        (workdir / "tmp").mkdir(exist_ok=True)
        env["BRIXCVMFS_TMP"] = str(workdir / "tmp")
    elif tmp_env is not None:
        env["BRIXCVMFS_TMP"] = str(tmp_env)
    # tmp_env=None: leave unset -> binary default /tmp/brixcvmfs-<repo>

    argv = [BRIXMOUNT, "cvmfs", fqrn, str(mnt), *extra_args, "-o", opts, "-f"]

    def _spawn():
        return subprocess.Popen(argv, env=env, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)

    def _reap(p):
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(3)
            except subprocess.TimeoutExpired:
                p.kill()

    proc = _spawn()
    for attempt in range(bringup_retries):
        _wait_mounted_or_dead(mnt, proc, timeout)
        if os.path.ismount(str(mnt)) or proc.poll() is None:
            break                        # mounted, or alive+progressing (don't thrash)
        if attempt + 1 < bringup_retries:  # exited before mounting — transient crash, respawn
            _unmount(mnt)
            time.sleep(min(2 ** attempt, 8))  # backoff so respawns span a load spike, not one instant
            proc = _spawn()
    try:
        yield mnt, proc
    finally:
        _unmount(mnt)
        _reap(proc)
        _unmount(mnt)
        shutil.rmtree(workdir, ignore_errors=True)


def wait_read(path, deadline_s: float):
    """Retry a read until it succeeds (blacklist snap-back) or deadline."""
    end = time.monotonic() + deadline_s
    last = None
    while time.monotonic() < end:
        try:
            return Path(path).read_bytes()
        except OSError as e:
            last = e
            time.sleep(1)
    raise AssertionError(f"read of {path} did not recover before deadline: {last}")


# ===========================================================================
# A. cache-first: cold fetches once, warm serves with zero origin traffic
# ===========================================================================

def _expect_mount_failure(fqrn, url, pub, mnt, cache_opt):
    env = {k: v for k, v in os.environ.items() if k != "BRIXCVMFS_CACHE"}
    env.update({"BRIXCVMFS_SERVER": url, "BRIXCVMFS_PUBKEY": str(pub),
                "BRIXCVMFS_TMP": str(Path(mnt).parent / "tmp")})
    Path(env["BRIXCVMFS_TMP"]).mkdir(exist_ok=True)
    proc = subprocess.Popen(
        [BRIXMOUNT, "cvmfs", fqrn, str(mnt), "-o", f"cache={cache_opt}",
         "-o", "auto_unmount", "-f"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        rc = proc.wait(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
        _unmount(Path(mnt))
    return rc
