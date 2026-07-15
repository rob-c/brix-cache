"""Harness for differential conformance against the STOCK XRootD server/tools.

Launches, on the same data tree:
  * our server  — nginx-xrootd (anon, allow_write)
  * the stock xrootd data server (anon)
and provides runners for the stock client (xrdfs/xrdcp) and our native client.

Quadrants this enables:
  Q2  our client   -> stock server   (finds OUR CLIENT divergences)
  Q3  stock client -> our server     (finds OUR SERVER divergences — the gold one)
  Q4  stock client -> stock server   (reference baseline / oracle)

Everything self-provisions on high ports; skips cleanly if a tool is missing.
"""

import os
import pwd
import shutil
import signal
import socket
import subprocess
import time

from config_templates import render_config
from settings import NGINX_BIN, TEST_ROOT

BIND = "127.0.0.1"

# --------------------------------------------------------------------------- #
# Permission harmonisation for out-of-band, test-CREATED working files.
#
# The fleet runs our nginx workers as root but the stock xrootd as `nobody`
# (-R nobody; xrootd refuses to run as superuser). harmonize_perms() already
# mirrors the owner triad into group+other on the SEEDED tree so both servers
# agree on the stat flags AND `nobody` can serve/mutate it. But conformance
# tests ALSO create working files out-of-band straight onto disk
# (`open(disk_for(...), "wb")`, `open(off_disk(...), "w")`, …) as the root
# pytest process, and then have a server reopen them — often for WRITE. A
# default umask of 022 makes those files 0644 root-owned, so the `nobody` stock
# server matches only the OTHER triad (r--) and a write-open fails with
# "permission denied" (the create-on-one-server / reopen-on-the-other artefact
# called out in root cause #2). Clearing the umask ONCE at import makes every
# subsequent out-of-band file the test process creates 0666 (dirs 0777), so
# `nobody` gains the read+write it needs — identically on both data roots, so
# every differential stays exact. Negative permission tests are unaffected:
# they set restrictive modes EXPLICITLY (via os.chmod or a server-side
# xrdfs chmod), which the umask never overrides.
os.umask(0)

# Wall-clock at import — the boundary between PRIOR-run leftovers and
# THIS-session files. Any non-seeded working file older than this predates the
# current run and is safe to wipe; anything newer belongs to a test running now
# (possibly on another xdist worker) and MUST be preserved. See
# _wipe_stale_working_files().
_IMPORT_TIME = time.time()
# Legacy self-start defaults (kept for the few callers — test_official_interop.py,
# test_deep_tree_special_files.py — that still drive start_our_server/
# start_official_server directly; the differential srv fixtures now ATTACH to the
# fleet, see start_pair / FLEET_* below).
OUR_PORT = 13990
OFF_PORT = 13991

# --------------------------------------------------------------------------- #
# Shared fleet instances for the differential-conformance suite.
#
# The old model started a server PAIR (our nginx + stock xrootd) per test_conf_*
# module, per xdist worker, on worker-shifted ports. With ~35 conf modules that
# is dozens of ephemeral nginx+xrootd daemons churning per run — the port/fd/proc
# pressure is what produced the flaky "stat mismatch" / "server did not start"
# skips the migration removes. Now the FLEET starts exactly ONE pair once
# (start_all_dedicated): our nginx-xrootd "interop-our" on FLEET_OUR_PORT over
# FLEET_OUR_DATA, and a stock xrootd "interop-off" on FLEET_OFF_PORT over
# FLEET_OFF_DATA. start_pair() ATTACHES to these fixed ports and seeds the
# deterministic tree, exactly like tests/test_zip_member.py::zipsrv.
try:                                              # settings owns the canonical port
    from settings import INTEROP_OUR_PORT as _FLEET_OUR_PORT
    from settings import INTEROP_OFF_PORT as _FLEET_OFF_PORT
except Exception:                                 # pragma: no cover - pre-merge fallback
    _FLEET_OUR_PORT = int(os.environ.get("TEST_INTEROP_OUR_PORT", "21200"))
    _FLEET_OFF_PORT = int(os.environ.get("TEST_INTEROP_OFF_PORT", "21201"))

FLEET_OUR_PORT = _FLEET_OUR_PORT
FLEET_OFF_PORT = _FLEET_OFF_PORT
FLEET_OUR_DATA = os.path.join(TEST_ROOT, "data-interop-our")
FLEET_OFF_DATA = os.path.join(TEST_ROOT, "data-interop-off")

# --------------------------------------------------------------------------- #
# Worker-unique ports for the differential conformance suite.
#
# Each test_conf_* module owns a fixed pair of ports and a module-scoped server
# fixture.  Under pytest-xdist `--dist load` the tests of ONE module are scattered
# across several workers, and every worker that receives any of them instantiates
# the module fixture — so without per-worker ports, N workers all try to bind the
# SAME fixed port.  The second binder fails, but `_wait()` still sees a listener
# (the first worker's server) and reports success, so the second worker silently
# talks to the first worker's data tree → cross-talk (writes land in tree A, reads
# look in tree B → FileNotFoundError).  `worker_port()` shifts every conformance
# port into a private per-worker band, lifted clear of the shared fleet
# (max ~18456) so the two never collide.
_WORKER_BAND_LIFT = 16000     # lift conf ports above the shared fleet's range
_WORKER_BAND_STRIDE = 1000    # per-worker band width (> max conf base-port span ~923)
_WORKER_BAND_COUNT = 44       # wrap so a huge -n never overflows 16-bit ports


def _worker_index():
    """0-based pytest-xdist worker index ('gw3' -> 3); 0 when run serially."""
    w = os.environ.get("PYTEST_XDIST_WORKER", "")
    if w.startswith("gw"):
        try:
            return int(w[2:]) % _WORKER_BAND_COUNT
        except ValueError:
            return 0
    return 0


def worker_port(base):
    """Map a module's fixed conformance port into this worker's private band.

    Deterministic and collision-free: distinct base ports stay distinct within a
    worker (same shift applied to all), and per-worker bands never overlap because
    the stride exceeds the span of all conformance base ports."""
    return base + _WORKER_BAND_LIFT + _worker_index() * _WORKER_BAND_STRIDE


def worker_tag():
    """Short token unique to this pytest-xdist worker ('gw3' under xdist, 'main'
    when serial), stable for the life of the process.

    The whole conf suite shares ONE fleet export per server, so under
    `-n8 --dist load` several worker processes create files in the SAME
    data-interop-{our,off} trees at once. Any test that enumerates a shared
    directory and compares our-vs-stock, or reuses a fixed working-file name,
    then sees a CONCURRENT worker's files in its differential. Embedding this tag
    in every such working file / scratch dir name confines each worker to a
    private namespace, so concurrent workers never collide or pollute each
    other's listings. (The cross-run wipe handles staleness of a reused tag.)"""
    return os.environ.get("PYTEST_XDIST_WORKER", "main")


def worker_prefix(base):
    """Make a filename PREFIX unique per xdist worker — the filesystem analogue of
    worker_port().

    Many modules share the fleet's single mutable data root and clean up by
    deleting *every* PREFIX-named artefact before/after each test.  Under
    `--dist load` a module's tests scatter across workers, so a CONSTANT prefix
    lets one worker's teardown delete another worker's in-flight files
    (FileNotFound / wrong-size / cross-talk races).  Tag the prefix with the
    worker id so each worker's create+cleanup is confined to its own namespace.
    Returns ``base`` unchanged in serial / `-n0` runs except for a stable "main"
    tag (PYTEST_XDIST_WORKER is unset), so single-worker semantics are preserved."""
    return "%s%s_" % (base, os.environ.get("PYTEST_XDIST_WORKER", "main"))

OFF_XRDFS = shutil.which("xrdfs")
OFF_XRDCP = shutil.which("xrdcp")
OFF_XROOTD = shutil.which("xrootd")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUR_XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")
OUR_XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")


def have_official():
    return all((OFF_XRDFS, OFF_XRDCP, OFF_XROOTD))


def _wait(port, t=10.0):
    end = time.time() + t
    while time.time() < end:
        try:
            with socket.create_connection((BIND, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def _det(n, seed=0):
    # (i*37 + 11 + seed) mod 256 has period 256 (37 is odd → coprime with 256),
    # so build one 256-byte cycle and tile it. Byte-identical to the old
    # per-byte generator but ~constant-time instead of O(n) Python calls (the old
    # form spent seconds on the 1 MiB tree files, ×2 servers, ×~20 conf modules).
    c = (11 + seed) & 0xff
    cycle = bytes((i * 37 + c) & 0xff for i in range(256))
    full, rem = divmod(n, 256)
    return cycle * full + cycle[:rem]


def _seed_file(path, data):
    """Write `data` (str or bytes) to `path` exactly ONCE.

    Idempotent skip-if-present: the fleet tree is a single shared export, so
    several xdist workers may call make_tree()/make_rich_tree() on it
    concurrently. Rewriting a file another worker is mid-read would race; the
    bytes are deterministic, so the first writer wins and everyone else is a
    no-op."""
    if os.path.exists(path):
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "wb" if isinstance(data, (bytes, bytearray)) else "w"
    tmp = "%s.tmp.%d" % (path, os.getpid())
    with open(tmp, mode) as f:
        f.write(data)
    try:
        os.replace(tmp, path)             # atomic publish; loser's replace is benign
    except OSError:
        pass


def make_tree(root):
    """A small, deterministic data tree shared by both servers (idempotent)."""
    os.makedirs(os.path.join(root, "sub"), exist_ok=True)
    _seed_file(os.path.join(root, "hello.txt"), "hello world\n")
    _seed_file(os.path.join(root, "data.bin"), _det(4096))
    _seed_file(os.path.join(root, "sub", "nested.txt"), "nested\n")


def make_rich_tree(root):
    """A richer deterministic tree for edge-case conformance probing. Identical
    bytes on both servers so differential checks are exact."""
    make_tree(root)
    j = os.path.join
    os.makedirs(j(root, "deep", "a", "b", "c"), exist_ok=True)
    os.makedirs(j(root, "empty_dir"), exist_ok=True)
    os.makedirs(j(root, "many"), exist_ok=True)
    if not os.path.exists(j(root, "empty.txt")):
        open(j(root, "empty.txt"), "w").close()                   # 0 bytes
    _seed_file(j(root, "deep", "a", "b", "c", "leaf.txt"), "leaf\n")
    # exact page-boundary sizes (pgread / read edge cases)
    for n in (1, 255, 4095, 4096, 4097, 8192, 65536):
        _seed_file(j(root, f"sz_{n}.bin"), _det(n, seed=n))
    _seed_file(j(root, "big1m.bin"), _det(1024 * 1024, seed=7))
    _seed_file(j(root, "with space.txt"), "spaced\n")
    for i in range(12):
        _seed_file(j(root, "many", f"f{i:02d}.txt"), f"file {i}\n")
    # data files for checksum cross-checks
    _seed_file(j(root, "cksum.bin"), _det(10000, seed=3))


# --------------------------------------------------------------------------- #
# Per-worker LISTING ROOT for full our-vs-stock directory-listing differentials.
#
# Tests that enumerate a WHOLE directory and assert the our-vs-stock name set is
# EQUAL cannot target the shared export '/': under `-n8 --dist load` a concurrent
# worker's transient working files appear in one server's listing but not the
# other's (timing), spuriously breaking the set equality. Such a test instead
# enumerates this per-worker directory — seeded identically on BOTH data roots
# and touched by no other worker — so the differential stays exact. Its contents
# mirror what '/' exercised (files of varied sizes + a subdir, for plain ls,
# `ls -l` sizes, dir-flag and `ls -R` recursion). Tests that only check a SUBSET
# of '/' (a known name present via `.get`/`<=`) are pollution-immune and keep
# using the real '/'.
LISTING_ROOT_SENTINEL = "@listing_root@"     # stable placeholder for @parametrize
LISTING_ROOT_FILES = {"lr_alpha.txt": b"alpha\n",
                      "lr_beta.bin": bytes(range(256)),
                      "lr_gamma.dat": b""}
LISTING_ROOT_SUBDIRS = {"lr_sub": {"leaf.txt": b"leaf\n"}}
# Top-level entry names of the listing root (files + subdir), for `expect <= our`.
LISTING_ROOT_ENTRIES = set(LISTING_ROOT_FILES) | set(LISTING_ROOT_SUBDIRS)


def ensure_listing_root(ctx):
    """Idempotently seed the per-worker listing directory on BOTH data roots and
    return its logical path ('/lroot_<worker>').

    Safe to call from a test body or fixture; `_seed_file` skips files that
    already exist, and the cross-run wipe reclaims a stale tag's dir. Because the
    dir is named per xdist worker, concurrent workers never pollute one
    another's copy."""
    rel = "/lroot_" + worker_tag()
    for data in (ctx["our_data"], ctx["off_data"]):
        base = os.path.join(data, rel.lstrip("/"))
        os.makedirs(base, exist_ok=True)
        for name, payload in LISTING_ROOT_FILES.items():
            _seed_file(os.path.join(base, name), payload)
        for sub, files in LISTING_ROOT_SUBDIRS.items():
            for name, payload in files.items():
                _seed_file(os.path.join(base, sub, name), payload)
    return rel


# --------------------------------------------------------------------------- #
# Session isolation for create-exclusive working files.
#
# The two fleet data roots (FLEET_OUR_DATA / FLEET_OFF_DATA) PERSIST across
# fleet restarts and across pytest runs. Many conformance tests open with a
# create-NEW / O_EXCL flag (WRITE_NEW = kXR_new|kXR_delete|…) using FIXED file
# names (seq_full_off_0.bin, single_off_*.bin, pgw_*.bin, …). On a second run
# the file from the first run is still there, so the create fails with
# `st=4003 … Unable to create <f>; file exists` — the dominant conf-suite
# failure. The seeded deterministic tree (make_tree/make_rich_tree) must survive
# untouched, so we wipe ONLY the non-seeded working files, and only the STALE
# ones (mtime older than this process's import time) so a concurrent xdist
# worker's in-flight files are never removed.
#
# Top-level entries created by make_tree + make_rich_tree. Keep in sync with
# those two functions; everything else at the data-root top level is a
# test-created working artefact.
_SEEDED_TOPLEVEL = {
    "sub", "hello.txt", "data.bin",                       # make_tree
    "deep", "empty_dir", "many", "empty.txt", "big1m.bin",
    "with space.txt", "cksum.bin",                        # make_rich_tree
} | {"sz_%d.bin" % n for n in (1, 255, 4095, 4096, 4097, 8192, 65536)}

_wiped_roots = set()     # once-per-process guard, keyed by absolute data root


def _wipe_stale_working_files(root):
    """Remove PRIOR-run working files from one data root, preserving the seeded
    tree and any file created during THIS run.

    Idempotent and xdist-safe: a top-level entry is deleted only when it is (a)
    not part of the deterministic seeded tree and (b) older than _IMPORT_TIME,
    i.e. a leftover from an earlier run. Files a concurrently-running test just
    created are newer than _IMPORT_TIME and are left alone. Runs once per
    (process, root)."""
    root = os.path.abspath(root)
    if root in _wiped_roots:
        return
    _wiped_roots.add(root)
    try:
        entries = os.listdir(root)
    except OSError:
        return
    for name in entries:
        if name in _SEEDED_TOPLEVEL:
            continue
        p = os.path.join(root, name)
        try:
            # lstat: judge staleness by the entry itself (a symlink's own age),
            # never follow it, so a dangling/rich-tree link can't crash the walk.
            #
            # Threshold is _IMPORT_TIME exactly (no slack). Each conf file runs in
            # its OWN pytest process, so a prior file's process has fully exited —
            # and every file it created is therefore strictly OLDER than this
            # process's import — before this one imports. A negative margin would
            # instead PROTECT the previous file's just-written leftovers (created
            # <margin seconds ago), leaking its asymmetric root files into this
            # file's `ls /` differentials (cross-file contamination). Files THIS
            # process creates are written after import (import precedes any test),
            # so their mtime is > _IMPORT_TIME and they are always kept — which is
            # also what keeps a concurrent xdist worker's in-flight files safe.
            if os.lstat(p).st_mtime >= _IMPORT_TIME:
                continue                      # created this run — keep
        except OSError:
            continue
        try:
            if os.path.islink(p) or os.path.isfile(p):
                os.remove(p)
            else:
                shutil.rmtree(p, ignore_errors=True)
        except OSError:
            pass                              # racing teardown / already gone


# --------------------------------------------------------------------------- #
# Ownership harmonisation for the STOCK server's data.
#
# harmonize_perms() equalises the MODE bits, which is enough for read/write
# (umask 0 keeps out-of-band files 0666 so `nobody` can rw them). But chmod /
# chown / utime are OWNER-gated by POSIX: only the file's owner (or root) may
# change its mode. Our server runs as root, so it can chmod anything in its
# tree; the stock xrootd runs as `nobody` (-R nobody) and CANNOT chmod a
# root-owned file — it returns "operation not permitted", a spurious our-vs-off
# divergence on every chmod-parity test. The realistic fix (matching a genuine
# `-R nobody` xrootd deployment, where the data is owned by the service user) is
# to give `nobody` ownership of the files it must manage. Applied ONLY to the
# off tree; our tree stays root-owned. Because the mode triads are already
# equalised, each server still matches its OWNER triad and reports identical
# stat flags, so every differential stays exact.
def _nobody_ids():
    try:
        p = pwd.getpwnam("nobody")
        return p.pw_uid, p.pw_gid
    except (KeyError, OSError):
        return None


def chown_stock(*paths):
    """chown each path (recursively, for dirs) to `nobody` so the stock server
    can chmod/own it. Best-effort: a no-op when not privileged or when `nobody`
    is absent, so the harness degrades gracefully instead of erroring."""
    ids = _nobody_ids()
    if ids is None:
        return
    uid, gid = ids

    def _one(p):
        try:
            os.chown(p, uid, gid, follow_symlinks=False)
        except (OSError, NotImplementedError):
            try:
                os.chown(p, uid, gid)
            except OSError:
                pass

    for path in paths:
        if not path or not os.path.exists(path):
            continue
        if os.path.isdir(path) and not os.path.islink(path):
            for dirpath, dirnames, filenames in os.walk(path):
                for name in dirnames + filenames:
                    _one(os.path.join(dirpath, name))
            _one(path)
        else:
            _one(path)


def harmonize_perms(*roots):
    """Make the kXR readable/writable/xset stat flags AGREE across the pair, and
    grant the stock server (which runs as `nobody`) the access it needs.

    The fleet runs our nginx workers as root but the stock xrootd as `nobody`
    (-R; xrootd refuses to run as superuser). brix derives the stat flags from an
    owner/group/other permission check against geteuid()/getegid()
    (brix_stat_flags_from_stat, mirroring XrdXrootdProtocol::StatGen). For a file
    OWNED BY THE SEEDING PROCESS (root) that neither server owns as `nobody`, root
    matches the OWNER triad while nobody matches the OTHER triad — so a plain
    0644 seed reports readable|writable to our server but readable-only to the
    stock server, a spurious divergence. Mirroring the owner triad into the group
    and other triads makes owner-match and other-match identical, so both servers
    report the same flags AND `nobody` gains the read/write/traverse it needs to
    serve and mutate the tree. Applied byte-for-byte identically to both roots, so
    every differential stays exact. Symlinks are skipped (their own mode is
    irrelevant; the target is harmonized in its own right)."""
    def _mirror(p):
        try:
            if os.path.islink(p):
                return
            m = os.stat(p).st_mode
            owner = (m >> 6) & 0o7
            os.chmod(p, (owner << 6) | (owner << 3) | owner)
        except OSError:
            pass

    for root in roots:
        if not root or not os.path.exists(root):
            continue
        if os.path.isdir(root):
            for dirpath, dirnames, filenames in os.walk(root):
                for name in dirnames + filenames:
                    _mirror(os.path.join(dirpath, name))
            _mirror(root)                         # the export root itself
        else:
            _mirror(root)                         # a single seeded file


def _wait_both(t=15.0):
    """True once BOTH fleet ports accept a connection (bounded)."""
    return _wait(FLEET_OUR_PORT, t) and _wait(FLEET_OFF_PORT, t)


def start_pair(base, rich=True, our_port=OUR_PORT, off_port=OFF_PORT):
    """ATTACH to the fleet's shared interop pair and seed the deterministic tree.

    No server is spun up here: the fleet starts our nginx-xrootd ("interop-our",
    FLEET_OUR_PORT / FLEET_OUR_DATA) and the stock xrootd ("interop-off",
    FLEET_OFF_PORT / FLEET_OFF_DATA) exactly once in start_all_dedicated, and every
    conf module simply attaches — the same shape as tests/test_zip_member.py. The
    `base`, `our_port`, `off_port` and `rich` arguments are kept for signature
    compatibility with the old self-provisioning harness; `base` is unused and the
    ports are fixed by the fleet (a module that hard-shifted ports would otherwise
    reach a server that does not exist).

    Returns (procs, ctx) with procs == [] (stop_pair is then a no-op — the fleet
    owns lifecycle) and ctx carrying the same keys callers already use: our/off
    root:// urls, our_data/off_data disk roots, and our_port/off_port for the
    raw-wire clients. Raises RuntimeError if the fleet pair is not listening, so
    the existing `except RuntimeError: pytest.skip(...)` in every srv fixture
    turns a missing fleet into a clean skip (never a fixture ERROR)."""
    try:
        os.makedirs(FLEET_OUR_DATA, exist_ok=True)
        os.makedirs(FLEET_OFF_DATA, exist_ok=True)
        # Clear PRIOR-run create-exclusive leftovers before re-seeding, so a
        # rerun's WRITE_NEW opens don't hit "file exists" (root cause #1).
        _wipe_stale_working_files(FLEET_OUR_DATA)
        _wipe_stale_working_files(FLEET_OFF_DATA)
        tree = make_rich_tree if rich else make_tree
        tree(FLEET_OUR_DATA)
        tree(FLEET_OFF_DATA)
        harmonize_perms(FLEET_OUR_DATA, FLEET_OFF_DATA)
        # Give `nobody` ownership of the stock tree so its chmod/chown parity
        # (owner-gated by POSIX) matches our root-run server (root cause #2).
        chown_stock(FLEET_OFF_DATA)
    except Exception as exc:                      # noqa: BLE001 — re-raise as skip
        raise RuntimeError(f"interop tree seed failed: {exc}") from exc
    if not _wait_both():
        raise RuntimeError(
            f"fleet interop pair not listening on {FLEET_OUR_PORT}/{FLEET_OFF_PORT}"
            " (start_all_dedicated must launch interop-our + interop-off)")
    ctx = {"our": our_url(FLEET_OUR_PORT), "off": off_url(FLEET_OFF_PORT),
           "our_data": FLEET_OUR_DATA, "off_data": FLEET_OFF_DATA,
           "our_port": FLEET_OUR_PORT, "off_port": FLEET_OFF_PORT}
    return [], ctx


def _kill_proc(p):
    """Terminate p and its whole process group (servers fork children — nginx
    workers, the stock xrootd's helpers — that survive a bare SIGTERM and would
    otherwise accumulate across themed files and exhaust the box)."""
    if not p:
        return
    try:
        pgid = os.getpgid(p.pid)
    except (ProcessLookupError, OSError):
        pgid = None
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            if pgid is not None:
                os.killpg(pgid, sig)
            else:
                p.send_signal(sig)
        except (ProcessLookupError, OSError):
            break
        try:
            p.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            continue


def stop_pair(procs):
    for p in procs:
        _kill_proc(p)


def err_code(stderr_or_out):
    """Extract a coarse error category from xrdfs/xrdcp output for differential
    error-conformance (the tools print '[ERROR] ... (code)' / named errors)."""
    s = (stderr_or_out or "").lower()
    for key in ("no such file", "not found", "not authorized", "permission",
                "invalid", "already exists", "not a directory", "is a directory",
                "not empty", "no space", "unsupported", "exists"):
        if key in s:
            return key
    return "ok" if not s.strip() else "other"


def start_our_server(base, data, port=OUR_PORT):
    cfg = os.path.join(base, "our.conf")
    with open(cfg, "w") as f:
        f.write(render_config("nginx_official_interop_anon.conf",
                              BASE_DIR=base,
                              BIND_HOST=BIND,
                              PORT=port,
                              DATA_DIR=data))
    p = subprocess.Popen([NGINX_BIN, "-c", cfg, "-p", base],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    return p if _wait(port) else None


def start_official_server(base, data, port=OFF_PORT):
    cfg = os.path.join(base, "xrootd.cfg")
    admin = os.path.join(base, "admin")
    os.makedirs(admin, exist_ok=True)
    with open(cfg, "w") as f:
        f.write(
            f"xrd.port {port}\n"
            "all.export /\n"
            f"oss.localroot {data}\n"
            f"all.adminpath {admin}\n"
            f"all.pidpath {admin}\n"
            "xrootd.async off\n")
    p = subprocess.Popen([OFF_XROOTD, "-c", cfg, "-l", os.path.join(base, "xrd.log")],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    return p if _wait(port) else None


def run(argv, timeout=60):
    """Run a command; return (rc, stdout, stderr)."""
    r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def our_url(port=OUR_PORT):
    return f"root://{BIND}:{port}"


def off_url(port=OFF_PORT):
    return f"root://{BIND}:{port}"
