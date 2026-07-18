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

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import BRIXMOUNT, _unmount, _wait_mounted
from conformance_common import fuse_mount as _fuse_mount_shared


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
    pytest.mark.timeout(300),          # ceiling: a saturated box slows every mount;
]                                      # healthy runs finish each test in seconds

# This file owns the 13300-13319 block (PORT_BLOCKS["fuse_cache"]); tests run
# sequentially within the module, so cycling the block is collision-free.
_PORTS = itertools.cycle(range(13300, 13320))


# ---- local helpers ---------------------------------------------------------

class MockOrigin:
    """One mock Stratum-1 in --webroot mode with kill/restart for offline tests."""

    def __init__(self, web: Path, repo: str = REPO):
        self.web, self.repo = web, repo
        self.port = next(_PORTS)
        self.proc = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/cvmfs/{self.repo}"

    def start(self) -> "MockOrigin":
        # A stale listener on a cycled port (leaked mock from a crashed run) makes
        # our fresh mock die on EADDRINUSE while wait_tcp still sees the squatter —
        # brixMount then fetches a repo signed with the WRONG keys and the mount
        # fails with trust error -5/-9.  Guard: the port is ours only if OUR mock
        # process is still alive once the port is listening; otherwise cycle on.
        for _ in range(len(range(13300, 13320))):
            self.proc = subprocess.Popen(
                [sys.executable, MOCK, "--port", str(self.port), "--repo", self.repo,
                 "--webroot", str(self.web)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if wait_tcp("127.0.0.1", self.port, 10) and self.proc.poll() is None:
                return self
            self.kill()                      # reap the bind-loser (or non-starter)
            self.port = next(_PORTS)         # and try the next port in the block
        raise RuntimeError("no free port in the fuse_cache block 13300-13319")

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
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/ctl/log", timeout=10) as r:
            return json.load(r)

    def reset_log(self) -> None:
        urllib.request.urlopen(urllib.request.Request(
            f"http://127.0.0.1:{self.port}/ctl/reset-log", method="POST"), timeout=10).read()

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

def test_cold_read_fetches_object_exactly_once(tmp_path, make_origin):
    with mounted(tmp_path, make_origin) as m:
        key = content_key(b"Hello fuse-cache corpus!\n")
        m.origin.reset_log()
        assert (m.mnt / "hello").read_bytes() == b"Hello fuse-cache corpus!\n"
        assert m.origin.data_fetches(key) == 1


def test_warm_reread_zero_new_origin_fetches(tmp_path, make_origin):
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "hello").read_bytes()
        m.origin.reset_log()
        assert (m.mnt / "hello").read_bytes() == b"Hello fuse-cache corpus!\n"
        assert m.origin.data_fetches() == 0


def test_warm_reread_repeated_stays_zero(tmp_path, make_origin):
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "sub" / "leaf").read_bytes()
        m.origin.reset_log()
        for _ in range(5):
            assert (m.mnt / "sub" / "leaf").read_bytes() == b"leaf bytes\n"
        assert m.origin.data_fetches() == 0


def test_each_object_fetched_once_across_rereads(tmp_path, make_origin):
    contents = {"hello": b"Hello fuse-cache corpus!\n", "secret": b"trust me exactly, byte for byte\n",
                "sub/leaf": b"leaf bytes\n"}
    with mounted(tmp_path, make_origin) as m:
        m.origin.reset_log()
        for _ in range(3):
            for rel, data in contents.items():
                assert (m.mnt / rel).read_bytes() == data
        for data in contents.values():
            assert m.origin.data_fetches(content_key(data)) == 1


def test_tree_walk_twice_second_walk_zero_data_fetches(tmp_path, make_origin):
    with mounted(tmp_path, make_origin) as m:
        first = read_tree(m.mnt)
        assert len(first) == 4
        m.origin.reset_log()
        assert read_tree(m.mnt) == first
        assert m.origin.data_fetches() == 0


def test_cold_read_populates_cache_entry_with_plaintext(tmp_path, make_origin):
    data = b"Hello fuse-cache corpus!\n"
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "hello").read_bytes()
        ent = cache_entry(m.cache, content_key(data))
        assert ent.is_file(), "cold read did not populate the CAS cache"
        assert ent.read_bytes() == data, "cache stores verified plaintext"


def test_metadata_cert_and_catalog_are_cached(tmp_path, make_origin):
    with mounted(tmp_path, make_origin) as m:
        assert cache_entry(m.cache, m.forge.cert_hash, "X").is_file()
        assert cache_entry(m.cache, m.forge.root_catalog_hash, "C").is_file()


def test_warm_stat_and_listing_zero_origin_traffic(tmp_path, make_origin):
    with mounted(tmp_path, make_origin) as m:
        read_tree(m.mnt)
        m.origin.reset_log()
        assert sorted(os.listdir(m.mnt)) == ["hello", "link", "secret", "sub"]
        assert (m.mnt / "hello").stat().st_size == 25
        assert os.readlink(m.mnt / "link") == "hello"
        assert m.origin.data_fetches() == 0


def test_warm_partial_reads_served_from_cache(tmp_path, make_origin):
    data = b"trust me exactly, byte for byte\n"
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "secret").read_bytes()
        m.origin.reset_log()
        fd = os.open(m.mnt / "secret", os.O_RDONLY)
        try:
            assert os.pread(fd, 8, 6) == data[6:14]
            assert os.pread(fd, 100, 24) == data[24:]
        finally:
            os.close(fd)
        assert m.origin.data_fetches() == 0


def test_cache_entries_use_two_hex_fanout_layout(tmp_path, make_origin):
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "hello").read_bytes()
        keys = cas_entries(m.cache)
        assert keys, "no cache entries after a cold read"
        for k in keys:
            hexpart = k[:40]
            assert all(c in "0123456789abcdef" for c in hexpart)
            assert cache_entry(m.cache, hexpart, k[40:]).is_file()


# ===========================================================================
# B. persistence: umount/remount over the same cache dir
# ===========================================================================

def test_cache_persists_across_remount_zero_data_fetches(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    cache = tmp_path / "cache"
    with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, _):
        assert os.path.ismount(str(mnt))
        first = read_tree(mnt)
    origin.reset_log()
    with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, _):
        assert os.path.ismount(str(mnt))
        assert read_tree(mnt) == first
    assert origin.data_fetches() == 0, "warm remount refetched data from the origin"
    forge.close()


def test_remount_refetches_manifest_but_no_data(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    cache = tmp_path / "cache"
    with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, _):
        read_tree(mnt)
    origin.reset_log()
    with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, _):
        assert os.path.ismount(str(mnt))
    log = [e["path"] for e in origin.log()]
    assert any(".cvmfswhitelist" in p for p in log), "trust chain must be re-fetched raw"
    assert any(".cvmfspublished" in p for p in log)
    assert origin.data_fetches() == 0
    forge.close()


def test_sequential_mounts_share_single_fill_per_object(tmp_path, make_origin):
    data = b"Hello fuse-cache corpus!\n"
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    cache = tmp_path / "shared-cache"
    for _ in range(2):
        with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, _):
            assert (mnt / "hello").read_bytes() == data
    assert origin.data_fetches(content_key(data)) == 1, \
        "second mount over the shared cache dir re-filled an existing entry"
    forge.close()


def test_remount_serves_after_origin_data_removed(tmp_path, make_origin):
    # The strongest persistence proof: wipe the origin's entire /data tree; a
    # warm remount (manifest/whitelist still served) must run fully off cache.
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    cache = tmp_path / "cache"
    with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, _):
        first = read_tree(mnt)
    shutil.rmtree(web / "cvmfs" / REPO / "data")
    with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, _):
        assert os.path.ismount(str(mnt)), "remount must not need /data/ when cache is warm"
        assert read_tree(mnt) == first
    forge.close()


def test_remount_with_different_tmp_dir_still_warm(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    cache = tmp_path / "cache"
    with fuse_mount(REPO, origin.url, pub, cache=str(cache), tmp=str(tmp_path / "t1")) as (mnt, _):
        read_tree(mnt)
    origin.reset_log()
    with fuse_mount(REPO, origin.url, pub, cache=str(cache), tmp=str(tmp_path / "t2")) as (mnt, _):
        assert (mnt / "hello").read_bytes() == b"Hello fuse-cache corpus!\n"
    assert origin.data_fetches() == 0
    forge.close()


# ===========================================================================
# C. offline tolerance: warm cache serves with the origin dead
# ===========================================================================

_FAST = ("-o", "retries=1")     # trim the transport retry budget for dead-origin paths


def test_offline_warm_read_ok(tmp_path, make_origin):
    with mounted(tmp_path, make_origin, extra_args=_FAST, bringup_retries=6) as m:
        (m.mnt / "hello").read_bytes()
        m.origin.kill()
        assert (m.mnt / "hello").read_bytes() == b"Hello fuse-cache corpus!\n"


def test_offline_warm_tree_walk_ok(tmp_path, make_origin):
    with mounted(tmp_path, make_origin, extra_args=_FAST, bringup_retries=6) as m:
        first = read_tree(m.mnt)
        m.origin.kill()
        assert read_tree(m.mnt) == first
        assert sorted(os.listdir(m.mnt)) == ["hello", "link", "secret", "sub"]


@pytest.mark.timeout(180)
def test_offline_cold_read_fails_cleanly(tmp_path, make_origin):
    with mounted(tmp_path, make_origin, extra_args=_FAST, bringup_retries=6) as m:
        (m.mnt / "hello").read_bytes()          # warm ONE file only
        m.origin.kill()
        with pytest.raises(OSError) as e:
            (m.mnt / "secret").read_bytes()     # cold: never fetched
        assert e.value.errno == errno.EIO


def test_offline_cold_stat_ok_metadata_from_catalog(tmp_path, make_origin):
    with mounted(tmp_path, make_origin, extra_args=_FAST, bringup_retries=6) as m:
        m.origin.kill()
        st = (m.mnt / "secret").stat()          # never read: pure catalog metadata
        assert st.st_size == len(b"trust me exactly, byte for byte\n")


@pytest.mark.timeout(180)
def test_offline_warm_still_ok_after_cold_failure(tmp_path, make_origin):
    with mounted(tmp_path, make_origin, extra_args=_FAST, bringup_retries=6) as m:
        (m.mnt / "hello").read_bytes()
        m.origin.kill()
        with pytest.raises(OSError):
            (m.mnt / "secret").read_bytes()
        assert (m.mnt / "hello").read_bytes() == b"Hello fuse-cache corpus!\n"


@pytest.mark.timeout(240)
def test_origin_restart_makes_cold_file_readable(tmp_path, make_origin):
    with mounted(tmp_path, make_origin, extra_args=_FAST, bringup_retries=6) as m:
        (m.mnt / "hello").read_bytes()
        m.origin.kill()
        with pytest.raises(OSError):
            (m.mnt / "secret").read_bytes()
        m.origin.restart()
        # host blacklist snap-back is 2s doubling per consecutive failure — a
        # bounded retry loop rides it out.
        assert wait_read(m.mnt / "secret", 30) == b"trust me exactly, byte for byte\n"


def test_offline_getxattr_fqrn_ok(tmp_path, make_origin):
    with mounted(tmp_path, make_origin, extra_args=_FAST, bringup_retries=6) as m:
        m.origin.kill()
        assert os.getxattr(m.mnt / "hello", "user.fqrn") == REPO.encode()


def test_offline_umount_is_clean(tmp_path, make_origin):
    with mounted(tmp_path, make_origin, extra_args=_FAST, bringup_retries=6) as m:
        (m.mnt / "hello").read_bytes()
        m.origin.kill()
        mnt = m.mnt
        _unmount(mnt)
        deadline = time.monotonic() + 10
        while os.path.ismount(str(mnt)) and time.monotonic() < deadline:
            time.sleep(0.2)
        assert not os.path.ismount(str(mnt)), "umount wedged with the origin dead"


# ===========================================================================
# D. on-disk cache corruption: official behavior = detect + refetch
# ===========================================================================

def test_corrupt_cached_entry_is_not_served(tmp_path, make_origin):
    # RETIRED DIVERGENCE: serve_from_cache() re-verifies every hit against the
    # entry's integrity sidecar (fetch.c) — tampered/bit-rotted local bytes are
    # purged and transparently refetched, never served.
    data = b"trust me exactly, byte for byte\n"
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "secret").read_bytes()
        ent = cache_entry(m.cache, content_key(data))
        blob = bytearray(ent.read_bytes())
        blob[6] ^= 0xFF
        ent.write_bytes(bytes(blob))
        assert (m.mnt / "secret").read_bytes() == data, "corrupt cache entry served as-is"


def test_corrupt_cached_entry_triggers_refetch(tmp_path, make_origin):
    # companion oracle to the test above — the damaged object must cost at
    # least one new origin fetch (purge + refetch).
    data = b"trust me exactly, byte for byte\n"
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "secret").read_bytes()
        ent = cache_entry(m.cache, content_key(data))
        blob = bytearray(ent.read_bytes())
        blob[0] ^= 0x01
        ent.write_bytes(bytes(blob))
        m.origin.reset_log()
        (m.mnt / "secret").read_bytes()
        assert m.origin.data_fetches(content_key(data)) >= 1


def test_corrupt_cached_entry_does_not_crash_mount(tmp_path, make_origin):
    # Actual-behavior guard: whatever is served, the mount must stay alive and
    # untouched objects must remain correct.
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "secret").read_bytes()
        (m.mnt / "hello").read_bytes()
        ent = cache_entry(m.cache, content_key(b"trust me exactly, byte for byte\n"))
        blob = bytearray(ent.read_bytes())
        blob[3] ^= 0xFF
        ent.write_bytes(bytes(blob))
        try:
            (m.mnt / "secret").read_bytes()
        except OSError:
            pass                                    # a clean error is acceptable
        assert os.path.ismount(str(m.mnt))
        assert (m.mnt / "hello").read_bytes() == b"Hello fuse-cache corpus!\n"


def test_truncated_cached_entry_refetched_not_served_empty(tmp_path, make_origin):
    # RETIRED DIVERGENCE: the sidecar records the plaintext length, so a
    # truncated entry fails re-verification and is treated as a miss + refetch
    # instead of serving an empty file.
    data = b"trust me exactly, byte for byte\n"
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "secret").read_bytes()
        cache_entry(m.cache, content_key(data)).write_bytes(b"")
        assert (m.mnt / "secret").read_bytes() == data


def test_truncated_cached_entry_does_not_crash_mount(tmp_path, make_origin):
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "secret").read_bytes()
        (m.mnt / "hello").read_bytes()
        cache_entry(m.cache, content_key(b"trust me exactly, byte for byte\n")).write_bytes(b"")
        try:
            (m.mnt / "secret").read_bytes()
        except OSError:
            pass
        assert os.path.ismount(str(m.mnt))
        assert (m.mnt / "hello").read_bytes() == b"Hello fuse-cache corpus!\n"


def test_deleted_cached_entry_transparent_refetch(tmp_path, make_origin):
    data = b"trust me exactly, byte for byte\n"
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "secret").read_bytes()
        cache_entry(m.cache, content_key(data)).unlink()
        m.origin.reset_log()
        assert (m.mnt / "secret").read_bytes() == data
        assert m.origin.data_fetches(content_key(data)) == 1


def test_deleted_entry_refetch_repopulates_cache(tmp_path, make_origin):
    data = b"trust me exactly, byte for byte\n"
    with mounted(tmp_path, make_origin) as m:
        (m.mnt / "secret").read_bytes()
        ent = cache_entry(m.cache, content_key(data))
        ent.unlink()
        (m.mnt / "secret").read_bytes()
        assert ent.is_file() and ent.read_bytes() == data


@pytest.mark.timeout(240)
def test_corrupt_cached_catalog_entry_remount_recovers(tmp_path, make_origin):
    # RETIRED DIVERGENCE: a damaged cached 'C' (catalog) entry now fails the
    # sidecar re-verification, is purged, and the pristine object is refetched
    # from the origin — the remount succeeds.
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    cache = tmp_path / "cache"
    with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, _):
        assert os.path.ismount(str(mnt))
    ent = cache_entry(cache, forge.root_catalog_hash, "C")
    blob = bytearray(ent.read_bytes())
    blob[16] ^= 0xFF                                # inside the sqlite header
    ent.write_bytes(bytes(blob))
    try:
        with fuse_mount(REPO, origin.url, pub, cache=str(cache), timeout=25,
                        bringup_retries=1) as (mnt, _):
            assert os.path.ismount(str(mnt)), "remount must survive a damaged cached catalog"
    finally:
        forge.close()


# ===========================================================================
# E. quota: high-watermark reap to 75%, enforced synchronously at fill time
# ===========================================================================

QUOTA_MB = 1
QUOTA = QUOTA_MB * 1024 * 1024


@pytest.mark.timeout(180)
def test_quota_fill_past_watermark_reaps_to_75pct(tmp_path, make_origin):
    # 8 x 300KB (2.4MB plaintext) through a 1MB quota: brix_cas_put enforces the
    # quota on every fill, reaping atime-LRU down to the 75% target — no need to
    # wait for the 30s reap_tick.
    with mounted(tmp_path, make_origin, tree=_quota_tree(),
                 extra_args=("-o", f"quota={QUOTA_MB}")) as m:
        expect = read_tree(m.mnt)
        assert len(expect) == 8 and all(len(v) == 300_000 for v in expect.values())
        du = cache_du(m.cache)
        # The reap fires when a fill would cross the hard quota, evicting LRU down
        # to the 75% low-watermark. The final resting size therefore depends on
        # whether the LAST fill crossed the quota: if it did not (600K + 300K =
        # 900K < 1M) the cache legitimately rests one object above the low
        # watermark. Both outcomes are correct; the invariant under test is that
        # the cache stays bounded near 75% and never exceeds the hard quota — not
        # that it always lands at-or-below the low watermark on the final fill.
        assert du <= QUOTA, f"cache {du}B exceeded the hard quota"
        assert du <= (QUOTA * 3) // 4 + 300_000, \
            f"cache {du}B more than one object above the 75% reap target"
        assert du < 8 * 300_000, "reap must have evicted something (cache < full 2.4MB)"
        assert du > 0, "reap must not empty the cache entirely"


@pytest.mark.timeout(180)
def test_quota_under_watermark_keeps_all_entries(tmp_path, make_origin):
    tree = _quota_tree(n=3, size=200_000)           # 600KB < 1MB: no reap
    with mounted(tmp_path, make_origin, tree=tree,
                 extra_args=("-o", f"quota={QUOTA_MB}")) as m:
        read_tree(m.mnt)
        for node in tree.values():
            assert cache_entry(m.cache, content_key(node.content)).is_file(), \
                "entry reaped while the cache was under quota"


@pytest.mark.timeout(180)
def test_reaped_entries_are_refetchable(tmp_path, make_origin):
    tree = _quota_tree()
    with mounted(tmp_path, make_origin, tree=tree,
                 extra_args=("-o", f"quota={QUOTA_MB}")) as m:
        expect = read_tree(m.mnt)                   # drives multiple reaps
        reaped = [f"f{i}" for i in range(8)
                  if not cache_entry(m.cache, content_key(tree[f"f{i}"].content)).is_file()]
        assert reaped, "2.4MB through a 1MB quota must have evicted something"
        m.origin.reset_log()
        name = reaped[0]
        assert (m.mnt / name).read_bytes() == expect[name]
        assert m.origin.data_fetches(content_key(tree[name].content)) >= 1


@pytest.mark.timeout(180)
def test_currently_open_file_survives_reap(tmp_path, make_origin):
    tree = _quota_tree()
    with mounted(tmp_path, make_origin, tree=tree,
                 extra_args=("-o", f"quota={QUOTA_MB}")) as m:
        first = (m.mnt / "f0").read_bytes()
        fd = os.open(m.mnt / "f0", os.O_RDONLY)
        try:
            for i in range(1, 8):                   # push f0 out of the cache
                (m.mnt / f"f{i}").read_bytes()
            got = bytearray()
            while chunk := os.read(fd, 65536):
                got += chunk
            assert bytes(got) == first, "open handle broke when its entry was reaped"
        finally:
            os.close(fd)


@pytest.mark.timeout(240)
def test_single_object_larger_than_quota_served_not_wedged(tmp_path, make_origin):
    big = random.Random(11).randbytes(2 * 1024 * 1024)
    with mounted(tmp_path, make_origin, tree={"big": File(big)},
                 extra_args=("-o", f"quota={QUOTA_MB}")) as m:
        assert (m.mnt / "big").read_bytes() == big, "over-quota object must still be served"
        assert os.path.ismount(str(m.mnt))
        assert (m.mnt / "big").read_bytes() == big  # and again, via refetch
        assert cache_du(m.cache) <= QUOTA


@pytest.mark.timeout(180)
def test_no_quota_means_unbounded_cache(tmp_path, make_origin):
    tree = _quota_tree()                            # 2.4MB, no quota option
    with mounted(tmp_path, make_origin, tree=tree) as m:
        read_tree(m.mnt)
        for node in tree.values():
            assert cache_entry(m.cache, content_key(node.content)).is_file()
        assert cache_du(m.cache) >= 8 * 300_000


@pytest.mark.timeout(180)
def test_preexisting_overquota_cache_reaped_on_next_fill(tmp_path, make_origin):
    # Adopt a 2.7MB cache under a 1MB quota: brix_cas_init re-counts the disk, so
    # the FIRST new fill trips the watermark and reaps the adopted entries too.
    tree = _quota_tree(n=9)
    forge, web, pub = _forge(tmp_path, tree)
    origin = make_origin(web)
    cache = tmp_path / "cache"
    with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, _):
        for i in range(8):
            (mnt / f"f{i}").read_bytes()            # no quota: 2.4MB adopted
    assert cache_du(cache) >= 8 * 300_000
    with fuse_mount(REPO, origin.url, pub, cache=str(cache),
                    extra_args=("-o", f"quota={QUOTA_MB}")) as (mnt, _):
        (mnt / "f8").read_bytes()                   # cold fill -> synchronous enforce
        assert cache_du(cache) <= (QUOTA * 3) // 4
    forge.close()


# ===========================================================================
# F. cache dir precedence: -o cache= > $BRIXCVMFS_CACHE > default
# ===========================================================================

def test_opt_cache_beats_env_cache(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    optdir, envdir = tmp_path / "optcache", tmp_path / "envcache"
    with own_mount(REPO, origin.url, pub, cache_env=envdir,
                   extra_args=("-o", f"cache={optdir}")) as (mnt, _):
        assert os.path.ismount(str(mnt))
        (mnt / "hello").read_bytes()
    assert cas_entries(optdir), "-o cache= dir did not receive the entries"
    assert not cas_entries(envdir), "$BRIXCVMFS_CACHE was used despite -o cache="
    forge.close()


def test_env_cache_used_when_no_opt(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    envdir = tmp_path / "envcache"
    with own_mount(REPO, origin.url, pub, cache_env=envdir) as (mnt, _):
        assert os.path.ismount(str(mnt))
        (mnt / "hello").read_bytes()
    assert cas_entries(envdir), "$BRIXCVMFS_CACHE dir did not receive the entries"
    forge.close()


def test_opt_cache_disables_clever_overlay(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    optdir, mnt_dir = tmp_path / "optcache", tmp_path / "m"
    with own_mount(REPO, origin.url, pub, mnt=mnt_dir,
                   extra_args=("-o", f"cache={optdir}")) as (mnt, _):
        assert os.path.ismount(str(mnt))
        (mnt / "hello").read_bytes()
    assert not (mnt_dir / ".brixcache").exists(), "-o cache= must disable the overlay"
    assert cas_entries(optdir)
    forge.close()


@pytest.mark.skipif(not os.access("/var/lib", os.W_OK),
                    reason="default cache dir /var/lib/brixcvmfs needs a writable /var/lib")
def test_default_cache_dir_when_no_opt_no_env(tmp_path, make_origin):
    # -o noclever with neither -o cache= nor $BRIXCVMFS_CACHE: the binary's
    # built-in default /var/lib/brixcvmfs/<repo> is the fallback.
    default_dir = Path("/var/lib/brixcvmfs") / REPO
    shutil.rmtree(default_dir, ignore_errors=True)
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    try:
        with own_mount(REPO, origin.url, pub, extra_args=("-o", "noclever")) as (mnt, _):
            assert os.path.ismount(str(mnt))
            (mnt / "hello").read_bytes()
        assert cas_entries(default_dir), "default /var/lib/brixcvmfs/<repo> not used"
    finally:
        shutil.rmtree(default_dir, ignore_errors=True)
        forge.close()


# ===========================================================================
# G. clever overlay: .brixcache inside the mountpoint
# ===========================================================================

def test_clever_brixcache_hidden_from_readdir(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    with own_mount(REPO, origin.url, pub, mnt=tmp_path / "m") as (mnt, _):
        assert os.path.ismount(str(mnt))
        names = os.listdir(mnt)
        assert ".brixcache" not in names, "overlay dir leaked into the FUSE readdir"
        assert sorted(names) == ["hello", "link", "secret", "sub"]
    forge.close()


def test_clever_entries_land_in_underlying_brixcache(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    mnt_dir = tmp_path / "m"
    with own_mount(REPO, origin.url, pub, mnt=mnt_dir) as (mnt, _):
        assert os.path.ismount(str(mnt))
        (mnt / "hello").read_bytes()
    # the mount is gone: the pre-mount dirfd wrote into the UNDERLYING dir
    keys = cas_entries(mnt_dir / ".brixcache")
    assert content_key(b"Hello fuse-cache corpus!\n") in [k[:40] for k in keys]
    forge.close()


def test_clever_cache_warm_across_remounts(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    mnt_dir = tmp_path / "m"
    with own_mount(REPO, origin.url, pub, mnt=mnt_dir) as (mnt, _):
        first = read_tree(mnt)
    origin.reset_log()
    with own_mount(REPO, origin.url, pub, mnt=mnt_dir) as (mnt, _):
        assert os.path.ismount(str(mnt))
        assert read_tree(mnt) == first
    assert origin.data_fetches() == 0, "second clever mount did not reuse .brixcache"
    forge.close()


def test_noclever_does_not_create_brixcache(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    mnt_dir = tmp_path / "m"
    with own_mount(REPO, origin.url, pub, mnt=mnt_dir, cache_env=tmp_path / "envcache",
                   extra_args=("-o", "noclever")) as (mnt, _):
        assert os.path.ismount(str(mnt))
        (mnt / "hello").read_bytes()
    assert not (mnt_dir / ".brixcache").exists()
    assert cas_entries(tmp_path / "envcache")
    forge.close()


def test_env_cache_disables_clever_overlay(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    mnt_dir = tmp_path / "m"
    with own_mount(REPO, origin.url, pub, mnt=mnt_dir,
                   cache_env=tmp_path / "envcache") as (mnt, _):
        assert os.path.ismount(str(mnt))
        (mnt / "hello").read_bytes()
    assert not (mnt_dir / ".brixcache").exists(), \
        "$BRIXCVMFS_CACHE must opt out of the clever overlay"
    forge.close()


# ===========================================================================
# H. unusable cache dir: clean mount failure, no crash, mountpoint reusable
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


def test_cache_dir_under_regular_file_clean_mount_failure(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    blob = tmp_path / "blob"
    blob.write_bytes(b"not a directory")
    mnt = tmp_path / "m"
    mnt.mkdir()
    rc = _expect_mount_failure(REPO, origin.url, pub, mnt, blob / "sub")
    assert rc is not None and rc > 0, f"expected a clean nonzero exit, got {rc}"
    assert not os.path.ismount(str(mnt))
    forge.close()


def test_cache_dir_under_devnull_clean_mount_failure(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    mnt = tmp_path / "m"
    mnt.mkdir()
    rc = _expect_mount_failure(REPO, origin.url, pub, mnt, "/dev/null/cache")
    assert rc is not None and rc > 0, "crash (signal) or hang instead of a clean error"
    assert not os.path.ismount(str(mnt))
    forge.close()


def test_mountpoint_reusable_after_failed_mount(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    mnt = tmp_path / "m"
    mnt.mkdir()
    rc = _expect_mount_failure(REPO, origin.url, pub, mnt, "/dev/null/cache")
    assert rc > 0
    with own_mount(REPO, origin.url, pub, mnt=mnt,
                   cache_env=tmp_path / "cache") as (mnt2, _):
        assert os.path.ismount(str(mnt2))
        assert (mnt2 / "hello").read_bytes() == b"Hello fuse-cache corpus!\n"
    forge.close()


# ===========================================================================
# I. BRIXCVMFS_TMP: catalog spill location + cleanup
# ===========================================================================

def test_tmp_env_hosts_catalog_spill(tmp_path, make_origin):
    spill = tmp_path / "spill"
    spill.mkdir()
    with mounted(tmp_path, make_origin, tmp=str(spill)) as m:
        cats = list(spill.glob("brixcvmfs.cat.*"))
        assert cats, "root catalog spill file not in $BRIXCVMFS_TMP"
        assert cats[0].read_bytes()[:16] == b"SQLite format 3\x00"


def test_tmp_spill_cleaned_up_on_umount(tmp_path, make_origin):
    spill = tmp_path / "spill"
    spill.mkdir()
    with mounted(tmp_path, make_origin, tmp=str(spill)) as m:
        assert list(spill.glob("brixcvmfs.cat.*"))
        _unmount(m.mnt)
        m.proc.wait(10)                             # umount path unlinks the spill
    assert not list(spill.glob("brixcvmfs.cat.*")), "catalog spill leaked after umount"


def test_tmp_default_dir_when_env_unset(tmp_path, make_origin):
    default_tmp = Path(f"/tmp/brixcvmfs-{REPO}")
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    try:
        with own_mount(REPO, origin.url, pub, cache_env=tmp_path / "cache",
                       tmp_env=None) as (mnt, _):
            assert os.path.ismount(str(mnt))
            assert default_tmp.is_dir(), "default scratch dir not created"
            assert list(default_tmp.glob("brixcvmfs.cat.*"))
    finally:
        shutil.rmtree(default_tmp, ignore_errors=True)
        forge.close()


# ===========================================================================
# J. robustness
# ===========================================================================

@pytest.mark.timeout(240)
def test_kill9_then_remount_warm_over_same_cache(tmp_path, make_origin):
    forge, web, pub = _forge(tmp_path, _std_tree())
    origin = make_origin(web)
    cache = tmp_path / "cache"
    with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, proc):
        first = read_tree(mnt)
        proc.send_signal(signal.SIGKILL)
        proc.wait(10)
        deadline = time.monotonic() + 10            # auto_unmount reaps the mount
        while os.path.ismount(str(mnt)) and time.monotonic() < deadline:
            time.sleep(0.2)
        _unmount(mnt)                               # belt-and-braces
        assert not os.path.ismount(str(mnt))
    origin.reset_log()
    with fuse_mount(REPO, origin.url, pub, cache=str(cache)) as (mnt, _):
        assert os.path.ismount(str(mnt))
        assert read_tree(mnt) == first
    assert origin.data_fetches() == 0, "cache filled before SIGKILL was not reused"
    forge.close()


@pytest.mark.timeout(240)
def test_cold_cache_mount_with_dead_origin_fails_cleanly(tmp_path):
    # Nothing listens on the port: the trust chain cannot be fetched raw and the
    # mount must fail with a clean error after its bounded retry/backoff (~15s).
    forge, web, pub = _forge(tmp_path, _std_tree())
    dead = next(_PORTS)
    url = f"http://127.0.0.1:{dead}/cvmfs/{REPO}"
    mnt = tmp_path / "m"
    mnt.mkdir()
    with own_mount(REPO, url, pub, mnt=mnt, cache_env=tmp_path / "cache",
                   extra_args=_FAST, timeout=1, bringup_retries=1) as (mnt2, proc):
        rc = proc.wait(timeout=60)
        assert rc is not None and rc > 0, "expected a clean nonzero exit"
        assert not os.path.ismount(str(mnt2))
    forge.close()
