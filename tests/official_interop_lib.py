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
import shutil
import signal
import socket
import subprocess
import time

from settings import NGINX_BIN

BIND = "127.0.0.1"
OUR_PORT = 13990
OFF_PORT = 13991

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


def make_tree(root):
    """A small, deterministic data tree shared by both servers."""
    os.makedirs(os.path.join(root, "sub"), exist_ok=True)
    with open(os.path.join(root, "hello.txt"), "w") as f:
        f.write("hello world\n")
    with open(os.path.join(root, "data.bin"), "wb") as f:
        f.write(_det(4096))
    with open(os.path.join(root, "sub", "nested.txt"), "w") as f:
        f.write("nested\n")


def make_rich_tree(root):
    """A richer deterministic tree for edge-case conformance probing. Identical
    bytes on both servers so differential checks are exact."""
    make_tree(root)
    j = os.path.join
    os.makedirs(j(root, "deep", "a", "b", "c"), exist_ok=True)
    os.makedirs(j(root, "empty_dir"), exist_ok=True)
    os.makedirs(j(root, "many"), exist_ok=True)
    open(j(root, "empty.txt"), "w").close()                       # 0 bytes
    with open(j(root, "deep", "a", "b", "c", "leaf.txt"), "w") as f:
        f.write("leaf\n")
    # exact page-boundary sizes (pgread / read edge cases)
    for n in (1, 255, 4095, 4096, 4097, 8192, 65536):
        with open(j(root, f"sz_{n}.bin"), "wb") as f:
            f.write(_det(n, seed=n))
    with open(j(root, "big1m.bin"), "wb") as f:
        f.write(_det(1024 * 1024, seed=7))
    with open(j(root, "with space.txt"), "w") as f:
        f.write("spaced\n")
    for i in range(12):
        with open(j(root, "many", f"f{i:02d}.txt"), "w") as f:
            f.write(f"file {i}\n")
    # data files for checksum cross-checks
    with open(j(root, "cksum.bin"), "wb") as f:
        f.write(_det(10000, seed=3))


def start_pair(base, rich=True, our_port=OUR_PORT, off_port=OFF_PORT):
    """Launch our server + the stock server on identical trees.

    Returns (procs, ctx) where ctx has our/off urls and our_data/off_data paths.
    Raises RuntimeError if either server (or the tree setup) fails, so a caller
    that catches RuntimeError skips cleanly — important when many themed files run
    in one process and the box runs low on fds/processes (any setup error becomes
    a skip, never a fixture ERROR)."""
    try:
        our_data = os.path.join(base, "our_data")
        off_data = os.path.join(base, "off_data")
        os.makedirs(our_data, exist_ok=True)
        os.makedirs(off_data, exist_ok=True)
        tree = make_rich_tree if rich else make_tree
        tree(our_data)
        tree(off_data)
        ours = start_our_server(base, our_data, port=our_port)
        off = start_official_server(base, off_data, port=off_port)
    except Exception as exc:                      # noqa: BLE001 — re-raise as skip
        raise RuntimeError(f"server setup failed: {exc}") from exc
    if not ours or not off:
        stop_pair([ours, off])
        raise RuntimeError("server launch failed")
    ctx = {"our": our_url(our_port), "off": off_url(off_port),
           "our_data": our_data, "off_data": off_data}
    return [ours, off], ctx


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
    body = (
        "daemon off;\nworker_processes 1;\n"
        "pid {b}/our.pid;\nerror_log {b}/our-err.log info;\n"
        "thread_pool default threads=2 max_queue=4096;\n"
        "events {{ worker_connections 64; }}\n"
        "stream {{ server {{\n"
        "  listen {bind}:{port};\n  xrootd on;\n  xrootd_root {data};\n"
        "  xrootd_auth none;\n  xrootd_allow_write on;\n"
        "  xrootd_access_log {b}/our-access.log;\n}} }}\n"
    ).format(b=base, bind=BIND, port=port, data=data)
    with open(cfg, "w") as f:
        f.write(body)
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
