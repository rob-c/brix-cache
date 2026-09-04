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

from settings import BIND_HOST, TEST_ROOT

def _phase_chown_stock_1(path, uid, gid):
    if _expression_2(path):
        for dirpath, dirnames, filenames in os.walk(path):
            for name in dirnames + filenames:
                _chown_one(os.path.join(dirpath, name), uid, gid)
        _chown_one(path, uid, gid)
    else:
        _chown_one(path, uid, gid)

def _mirror(p):
    """Mirror a path's owner permission triad into its group+other triads (see
    harmonize_perms). Pure per-path helper; module-level so both harmonize_perms
    and its extracted walk (_phase_harmonize_perms_2) can reach it."""
    try:
        if os.path.islink(p):
            return
        m = os.stat(p).st_mode
        owner = (m >> 6) & 0o7
        mirrored = (owner << 6) | (owner << 3) | owner
        # Skip when already mirrored: chmod bumps ctime even when the mode
        # is unchanged, and re-runs from other xdist workers' start_pair()
        # would flap M/CTime under concurrent stat-parity tests.
        if (m & 0o777) != mirrored:
            os.chmod(p, mirrored)
    except OSError:
        pass


def _phase_harmonize_perms_2(root):
    if os.path.isdir(root):
        for dirpath, dirnames, filenames in os.walk(root):
            for name in dirnames + filenames:
                _mirror(os.path.join(dirpath, name))
        _mirror(root)                         # the export root itself
    else:
        _mirror(root)                         # a single seeded file


def _expression_1(path):
    return (
        not path or not os.path.exists(path)
    )

def _expression_2(path):
    return (
        os.path.isdir(path) and not os.path.islink(path)
    )

def _expression_3(root):
    return (
        not root or not os.path.exists(root)
    )


BIND = BIND_HOST

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
# Default ports for the standalone start_our_server / start_official_server pair
# (test_official_interop.py, test_deep_tree_special_files.py).  start_our_server
# now drives our nginx through the registry LifecycleHarness (port-pinned to the
# caller's worker_port band); start_official_server still spawns the stock xrootd
# daemon directly.  The differential srv fixtures instead spin an in-process pair
# via start_pair — see start_pair / FLEET_* below.
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
# SHARED data roots — these paths are a FLEET CONTRACT, not a library choice.
# The standing fleet pair (nginx_interop.conf "interop-our" + the stock
# "interop-off" xrootd backend in fleet_specs) exports exactly these two
# directories, and several conf modules (openflags, sessions, sessions_b,
# dirlist, prepfattr*) raw-wire straight to the fixed FLEET_*_PORTs. Keying
# these paths per xdist worker therefore desyncs seeding from what those
# servers serve (every seeded file becomes kXR_NotFound). Cross-worker safety
# on the shared trees comes from the machinery below instead: _seed_file is
# create-once, _wipe_stale_working_files AND reset_to_seeded_tree are
# age-gated by _entry_is_stale (this process's import time plus an absolute
# freshness floor), listing differentials use a per-worker lroot_<tag> dir, and
# harmonize_perms/chown_stock stat-and-skip so a concurrent re-seed never
# bumps ctime under a running stat-parity test.
FLEET_OUR_DATA = os.path.join(TEST_ROOT, "data-interop-our")
FLEET_OFF_DATA = os.path.join(TEST_ROOT, "data-interop-off")

# --------------------------------------------------------------------------- #
# Differential-conformance ports: each test_conf_* module owns a FIXED pair of
# ladder ports (official_interop_lib.worker_port, INTEROP category) and a
# module-scoped server fixture.  To make one fixed port per module safe, the
# conftest pins each interop module to a single xdist worker (auto-xdist_group),
# so two workers never instantiate the same module fixture and bind the same port
# — which would otherwise cross-talk into each other's data tree.  This replaced
# the old absolute per-worker band (30000-49925) so ports stay in the contiguous
# python-test range within TEST_PORT_START+2000.


def _chown_one(path, uid, gid):
    try:
        # Avoid a redundant chown: it bumps ctime and can flap another worker's
        # stat parity check even when the ownership is already correct.
        stat = os.stat(path, follow_symlinks=False)
        if stat.st_uid == uid and stat.st_gid == gid:
            return
    except OSError:
        pass
    try:
        os.chown(path, uid, gid, follow_symlinks=False)
    except (OSError, NotImplementedError):
        try:
            os.chown(path, uid, gid)
        except OSError:
            pass


def chown_stock(*paths):
    """Best-effort ownership handoff to the stock server's service user."""
    ids = _nobody_ids()
    if ids is None:
        return
    uid, gid = ids

    for path in paths:
        if _expression_1(path):
            continue
        _phase_chown_stock_1(path, uid, gid)


def worker_reachable(*dirs):
    """Make each directory usable by the de-escalated `nobody` worker.

    Since the always-on worker privilege drop (brix_imp_worker_deescalate), a
    root-launched worker serves as `nobody`.  Test dirs created under pytest's
    tmp_path sit below root-0700 `pytest-of-root/pytest-N` parents, so the
    worker cannot even TRAVERSE to them, let alone write.  chown_stock each
    leaf to `nobody`, then add o+x/g+x up the parent chain to /tmp so the
    worker can reach it (traversal only — no read bit added).  Best-effort,
    no-op unprivileged."""
    for d in dirs:
        chown_stock(str(d))
    for d in dirs:
        p = os.path.abspath(str(d))
        while p not in ("/", "/tmp"):
            try:
                mode = os.stat(p).st_mode & 0o7777
                if mode & 0o011 != 0o011:
                    os.chmod(p, mode | 0o011)
            except OSError:
                break
            p = os.path.dirname(p)


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
    irrelevant; the target is harmonized in its own right).  The per-path mirror
    is _mirror() at module scope (shared with the extracted walk helper)."""
    for root in roots:
        if _expression_3(root):
            continue
        _phase_harmonize_perms_2(root)


def _wait_both(t=15.0):
    """True once BOTH fleet ports accept a connection (bounded)."""
    return _wait(FLEET_OUR_PORT, t) and _wait(FLEET_OFF_PORT, t)


def central_pair(rich=True):
    """Seed and attach to the registry-managed differential server pair.

    The pytest registry owns ``interop-our`` and ``interop-off``.  Test modules
    must never replace an unavailable managed server with an ad-hoc pair: that
    hides fleet/setup regressions as skips and duplicates daemons under xdist.
    Callers are grouped on one worker because both servers intentionally expose
    these shared, byte-identical trees.
    """
    if not _wait_both():
        raise RuntimeError(
            "central interop pair unavailable: interop-our=%s interop-off=%s"
            % (FLEET_OUR_PORT, FLEET_OFF_PORT))
    os.makedirs(FLEET_OUR_DATA, exist_ok=True)
    os.makedirs(FLEET_OFF_DATA, exist_ok=True)
    _wipe_stale_working_files(FLEET_OUR_DATA)
    _wipe_stale_working_files(FLEET_OFF_DATA)
    tree = make_rich_tree if rich else make_tree
    tree(FLEET_OUR_DATA)
    tree(FLEET_OFF_DATA)
    harmonize_perms(FLEET_OUR_DATA, FLEET_OFF_DATA)
    chown_stock(FLEET_OFF_DATA)
    return {
        "our": our_url(FLEET_OUR_PORT),
        "off": off_url(FLEET_OFF_PORT),
        "our_data": FLEET_OUR_DATA,
        "off_data": FLEET_OFF_DATA,
        "our_port": FLEET_OUR_PORT,
        "off_port": FLEET_OFF_PORT,
    }


def start_pair(base=None, rich=True, our_port=None, off_port=None):
    """Provision an in-process differential pair via the registry LifecycleHarness.

    The differential-conformance fleet is no longer a fixed-port cross-process
    standing fleet attached-to via start_all_dedicated; each conf module spins its
    OWN pair in-process on dynamically-allocated ports, orchestrated by a
    LifecycleHarness this call owns:
      * "our server"  — our nginx-xrootd, template ``nginx_lc_interop_our.conf``
      * "off server"  — the STOCK xrootd, kind="xrootd", template
                        ``xrootd_interop_anon.cfg`` (the launcher spawns the real
                        daemon and reaps its process group on teardown)
    Both export the byte-identical deterministic tree seeded on FLEET_OUR_DATA /
    FLEET_OFF_DATA. Under the in-process harness both servers run as the invoking
    user, so their kXR stat flags already agree without root/nobody harmonisation
    (harmonize_perms/chown_stock stay as belt-and-braces no-ops off-root).

    ``base`` owns this pair's two export trees.  ``our_port`` /
    ``off_port`` are the fixed per-worker listens (every call site passes
    ``L.worker_port(base)``); the pair binds them directly — the old dynamic
    free_port allocation was retired in Phase 5. Returns (procs, ctx) where procs == the
    owning harness list (stop_pair closes it) and ctx carries the same keys
    callers use: our/off root:// urls, our_data/off_data disk roots, and
    our_port/off_port for the raw-wire clients. Raises RuntimeError on launch
    failure so each srv fixture's ``except RuntimeError: pytest.skip(...)`` turns a
    missing toolchain / launch error into a clean skip, never a fixture ERROR."""
    from server_launcher import LifecycleHarness
    from server_registry import NginxInstanceSpec

    try:
        if base is None:
            raise RuntimeError("interop pair requires a private base directory")
        our_data = os.path.join(str(base), "our-data")
        off_data = os.path.join(str(base), "off-data")
        os.makedirs(our_data, exist_ok=True)
        os.makedirs(off_data, exist_ok=True)
        # Clear PRIOR-run create-exclusive leftovers before re-seeding, so a
        # rerun's WRITE_NEW opens don't hit "file exists" (root cause #1).
        _wipe_stale_working_files(our_data)
        _wipe_stale_working_files(off_data)
        tree = make_rich_tree if rich else make_tree
        tree(our_data)
        tree(off_data)
        harmonize_perms(our_data, off_data)
        chown_stock(off_data)
    except Exception as exc:                      # noqa: BLE001 — re-raise as skip
        raise RuntimeError(f"interop tree seed failed: {exc}") from exc

    # Fixed ports, per-worker isolation.  Every call site passes fixed per-worker
    # ports via L.worker_port(base) (a deterministic band unique to this xdist
    # worker); bind those directly rather than the retired dynamic free_port
    # fallback.  The instance name carries worker_tag() so concurrent workers use
    # distinct registry prefixes for their own fixed-port pairs.  (A caller that
    # omits the ports would now fail loudly in endpoint_for — intended.)
    tag = worker_tag()
    harness = LifecycleHarness()
    try:
        prefname_host = socket.gethostbyname(socket.gethostname())
        prefname_listen = ""
        if prefname_host != BIND:
            prefname_listen = f"listen {prefname_host}:{our_port};"
        our_ep = harness.start(NginxInstanceSpec(
            name="lc-interop-our-%s" % tag,
            template="nginx_lc_interop_our.conf",
            port=our_port,
            protocol="root", readiness="tcp",
            data_root=our_data,
            template_values={"PREFNAME_LISTEN": prefname_listen}))
        off_ep = harness.start(NginxInstanceSpec(
            name="lc-interop-off-%s" % tag,
            template="xrootd_interop_anon.cfg",
            port=off_port,
            kind="xrootd", protocol="root", readiness="tcp",
            data_root=off_data))
    except Exception as exc:                      # noqa: BLE001 — clean up, re-raise as skip
        harness.close()
        raise RuntimeError(f"interop pair launch failed: {exc}") from exc

    ctx = {"our": our_url(our_ep.port), "off": off_url(off_ep.port),
           "our_data": our_data, "off_data": off_data,
           "our_port": our_ep.port, "off_port": off_ep.port}
    return [harness], ctx


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
    for item in procs:
        close = getattr(item, "close", None)
        if callable(close):
            item.close()          # in-process LifecycleHarness owns the pair
        else:
            _kill_proc(item)      # stock-xrootd Popen (start_official_server)


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
    """Start our nginx-xrootd anon server over ``data`` via the registry harness.

    Returns the owning ``LifecycleHarness`` (truthy; tear down with
    ``stop_pair([...])``, which routes it through ``.close()``), or ``None`` if
    it failed to come up so the two direct callers — test_official_interop.py's
    ``srv`` fixture and test_deep_tree_special_files.py's ``our`` fixture — keep
    their ``if not proc: pytest.skip(...)`` contract.  The port is pinned to the
    caller's ``port`` (a worker_port band) so ``our_url(port)`` still names the
    live listener; ``base`` is retained for signature compatibility (the harness
    owns its own prefix)."""
    from server_launcher import LifecycleHarness
    from server_registry import NginxInstanceSpec

    harness = LifecycleHarness()
    try:
        harness.start(NginxInstanceSpec(
            name="off-interop-our-%d" % port,
            template="nginx_official_interop_anon.conf",
            port=port, protocol="root", readiness="tcp",
            data_root=data,
            template_values={"BIND_HOST": BIND}))
    except Exception:                                 # launch/bind failure -> clean skip
        harness.close()
        return None
    return harness


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
