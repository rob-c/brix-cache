"""
Shared infrastructure for the real-XRootD <-> nginx-xrootd CMS mesh.

This module owns the *daemon lifecycle* for every CMS-mesh topology so the
topologies can be brought up once by the test harness (manage_test_servers.sh ->
cms_mesh_servers.py) instead of by each test.  The tests in
test_cms_mesh_interop.py only connect to the fixed ports below and skip if a
topology is not up.

It provides:
  * binary discovery + client helpers (xrdcp / xrdfs / curl, md5, etc.)
  * config builders for nginx managers / data nodes / dual-protocol nodes
  * a Mesh launcher (xrootd/cmsd via -b, nginx via its pid file)
  * PORTS: the fixed port map for every topology
  * per-topology build functions + start_all() / stop_all()

Everything binds 127.0.0.1 and uses the ports in PORTS; nothing here is
pytest-specific so cms_mesh_servers.py can import and run it standalone.
"""

import glob
import hashlib
import os
import shutil
import signal
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

from settings import NGINX_BIN, HOST, BIND_HOST
from mesh_config import render
from server_launcher import launch_fleet_nginx

# --------------------------------------------------------------------------- #
# Binaries / constants
# --------------------------------------------------------------------------- #

BRIX_BIN = shutil.which(os.environ.get("TEST_BRIX_BIN", "xrootd"))
CMSD_BIN = shutil.which(os.environ.get("TEST_CMSD_BIN", "cmsd"))
XRDFS_BIN = shutil.which(os.environ.get("TEST_XRDFS_BIN", "xrdfs"))
XRDCP_BIN = shutil.which(os.environ.get("TEST_XRDCP_BIN", "xrdcp"))
CURL_BIN = shutil.which("curl")

# The mesh's reference managers/data nodes are the *stock* xrootd/cmsd daemons
# (BRIX_BIN/CMSD_BIN above resolve from PATH by design — interop testing).  The
# SSS keytab admin, however, is our own clean-room tool: it ships as
# ``xrdsssadmin-brix`` (the ``-brix`` suffix keeps the brix client RPM
# co-installable with the stock xrootd *server* package, which owns
# /usr/bin/xrdsssadmin) and carries its own CLI, distinct from the stock tool's.
# Resolve it from the in-tree client build — like test_native_sss.py and the
# other SSS suites — NOT via PATH, where only the incompatible stock binary lives.
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")

# Where the harness drops the mesh's generated configs/data/logs.
MESH_DIR = os.environ.get("CMS_MESH_DIR", os.path.join(os.environ.get("TEST_ROOT", "/tmp/xrd-test"), "cms-mesh"))

# Unauthenticated XRootD client env (keep any ambient GSI proxy out).
_XRD_ENV = {
    k: v
    for k, v in os.environ.items()
    if k not in ("X509_USER_PROXY", "X509_USER_CERT", "X509_USER_KEY",
                 "XrdSecPROTOCOL", "XRD_SECPROTOCOL")
}
_XRD_ENV["XrdSecPROTOCOL"] = "unix"


def have_binaries():
    return all([BRIX_BIN, CMSD_BIN, XRDFS_BIN, XRDCP_BIN,
                NGINX_BIN and os.path.exists(NGINX_BIN)])


# --------------------------------------------------------------------------- #
# Fixed port map (disjoint from settings.py's <=13xxx ranges)
# --------------------------------------------------------------------------- #

PORTS = {
    # A: real manager + nginx data node
    "a_mgr": 21610, "a_mgr_cms": 21611, "a_nds": 21612,
    # B: nginx manager + real data node
    "b_mgr": 21620, "b_mgr_cms": 21621, "b_rds": 21622, "b_rds_cms": 21623,
    # C: nginx manager + nginx DS + real DS
    "c_mgr": 21630, "c_mgr_cms": 21631, "c_nds": 21632,
    "c_rds": 21634, "c_rds_cms": 21635,
    # D: real meta -> nginx sub -> nginx leaf
    "d_meta": 21640, "d_meta_cms": 21641, "d_sub": 21642, "d_sub_cms": 21643,
    "d_leaf": 21644,
    # pool: real mgr + 2 nginx
    "prm_mgr": 21660, "prm_mgr_cms": 21661, "prm_n1": 21662, "prm_n2": 21663,
    # pool: nginx mgr + 2 real
    "pnm_mgr": 21665, "pnm_mgr_cms": 21666,
    "pnm_r1": 21667, "pnm_r1_cms": 21668, "pnm_r2": 21669, "pnm_r2_cms": 21670,
    # write through real mgr -> nginx node
    "wrm_mgr": 21672, "wrm_mgr_cms": 21673, "wrm_nds": 21674,
    # write through nginx mgr -> real node
    "wnm_mgr": 21676, "wnm_mgr_cms": 21677, "wnm_rds": 21678, "wnm_rds_cms": 21679,
    # stat/ls: nginx mgr + real node
    "sl_mgr": 21681, "sl_mgr_cms": 21682, "sl_rds": 21683, "sl_rds_cms": 21684,
    # negative: nginx mgr + real node (restricted export)
    "neg_mgr": 21686, "neg_mgr_cms": 21687, "neg_rds": 21688, "neg_rds_cms": 21689,
    # failover: nginx mgr + real node (killable)
    "fo_mgr": 21691, "fo_mgr_cms": 21692, "fo_rds": 21693, "fo_rds_cms": 21694,
    # large-file integrity: nginx mgr + real node
    "lg_mgr": 21696, "lg_mgr_cms": 21697, "lg_rds": 21698, "lg_rds_cms": 21699,
    # baseline: real mgr + real node
    "bl_mgr": 21701, "bl_mgr_cms": 21702, "bl_rds": 21703, "bl_rds_cms": 21704,
    # multi-tier with real leaf
    "mrl_meta": 21706, "mrl_meta_cms": 21707, "mrl_sub": 21708, "mrl_sub_cms": 21709,
    "mrl_leaf": 21710, "mrl_leaf_cms": 21711,
    # tri-protocol: nginx mgr + dual nginx (root+https) + real
    "tri_mgr": 21720, "tri_mgr_cms": 21721, "tri_dual": 21722, "tri_dual_https": 21723,
    "tri_real": 21724, "tri_real_cms": 21725,
    # wide pool: nginx mgr + 2 nginx + 2 real
    "w_mgr": 21730, "w_mgr_cms": 21731, "w_n1": 21732, "w_n2": 21733,
    "w_r1": 21734, "w_r1_cms": 21735, "w_r2": 21736, "w_r2_cms": 21737,
    # real xrootd http (root:// + https://) behind nginx mgr
    "rh_mgr": 21740, "rh_mgr_cms": 21741, "rh_real": 21742, "rh_real_cms": 21743,
    "rh_real_http": 21744,
    # sss: nginx manager REQUIRING sss + a plain real node (fail-closed)
    "sss_mgr": 21746, "sss_mgr_cms": 21747, "sss_rds": 21748, "sss_rds_cms": 21749,
}

# Values above are the original development ports. This registry-owned external
# orchestrator receives its runtime ports from the central per-run ladder.
from port_ladder import rebase_named_ports
PORTS = rebase_named_ports(PORTS, category="cms-mesh")

# Lowest port whose listener marks a mesh as "up" (used by force-stop too).
PORT_MIN, PORT_MAX = min(PORTS.values()), max(PORTS.values())


def content(tag):
    """Deterministic seeded file content for a given tag."""
    return f"cmsmesh::{tag}\n"


def data_dir(topo, node):
    """Fixed on-disk export root for a topology's node (tests read writes here)."""
    return os.path.join(MESH_DIR, topo, f"{node}-data")


def node_cfg(topo, label):
    """Path of a real xrootd/cmsd node's config — pkill -f this to kill the node
    (both cmsd and xrootd were launched with -c <cfg>)."""
    return os.path.join(MESH_DIR, topo, "cfg", f"{label}.cfg")


# Manager front-door ports (where clients connect).  These are the listeners we
# gate startup/teardown on.  (Server-role cmsd ports are intentionally absent —
# a server cmsd never binds its own listen port.)
MANAGER_PORTS = [PORTS[k] for k in (
    "a_mgr", "b_mgr", "c_mgr", "d_meta", "prm_mgr", "pnm_mgr", "wrm_mgr",
    "wnm_mgr", "sl_mgr", "neg_mgr", "fo_mgr", "lg_mgr", "bl_mgr", "mrl_meta",
    "tri_mgr", "w_mgr", "rh_mgr", "sss_mgr")]

# NOTE: "sss_mgr" is intentionally absent from READY_PROBES below — its data
# node is refused registration by design (fail-closed sss), so a locate probe
# would never succeed.  Its listener is liveness-gated via MANAGER_PORTS, but
# only when the box can actually mint the sss keytab — see expected_manager_ports.

# (manager_port, namespace_path) readiness probes: a successful locate -> redirect
# proves that topology's data node(s) have registered and the manager will serve
# the path.  Covers every distinct node so "ready" means the whole mesh formed.
READY_PROBES = [
    (PORTS["a_mgr"], "/fileA.txt"),
    (PORTS["b_mgr"], "/fileB.txt"),
    (PORTS["c_mgr"], "/ngx/n.txt"), (PORTS["c_mgr"], "/real/r.txt"),
    (PORTS["d_meta"], "/fileD.txt"),
    (PORTS["prm_mgr"], "/a/x.txt"), (PORTS["prm_mgr"], "/b/y.txt"),
    (PORTS["pnm_mgr"], "/ra/x.txt"), (PORTS["pnm_mgr"], "/rb/y.txt"),
    (PORTS["wrm_mgr"], "/.probe"),
    (PORTS["wnm_mgr"], "/.probe"),
    (PORTS["sl_mgr"], "/d/f.txt"),
    (PORTS["neg_mgr"], "/real/here.txt"),
    (PORTS["fo_mgr"], "/f.txt"),
    (PORTS["lg_mgr"], "/big.bin"),
    (PORTS["bl_mgr"], "/base.txt"),
    (PORTS["mrl_meta"], "/fileE.txt"),
    (PORTS["tri_mgr"], "/dav/f.txt"), (PORTS["tri_mgr"], "/real/r.txt"),
    (PORTS["w_mgr"], "/na/f.txt"), (PORTS["w_mgr"], "/nb/f.txt"),
    (PORTS["w_mgr"], "/ra/f.txt"), (PORTS["w_mgr"], "/rb/f.txt"),
    (PORTS["rh_mgr"], "/h.txt"),
]


# --------------------------------------------------------------------------- #
# Process / readiness helpers
# --------------------------------------------------------------------------- #


def port_open(port, host=HOST, timeout=0.3):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def wait_port(port, up=True, tries=80, delay=0.25):
    for _ in range(tries):
        if port_open(port) == up:
            return True
        time.sleep(delay)
    return False


def wait_managers_up(ports, timeout=8.0, poll=0.2):
    """Return the count of ``ports`` that opened within ``timeout`` seconds.

    Bring-up liveness gate for the manager front doors.  A serial
    ``sum(wait_port(p) for p)`` is O(N × per-port budget): one manager that
    never binds (e.g. ``sss_mgr``, whose data node is refused by design, or a
    genuinely misconfigured node) burns that port's whole budget alone while the
    17 healthy managers already bound in the first round.  Poll every still-shut
    port together each round and stop the instant they are all up — so the gate
    costs the SLOWEST healthy manager (~1-2 s), not the sum, and a permanent
    laggard caps the wait at ``timeout`` instead of ``budget × laggards``."""
    deadline = time.time() + timeout
    remaining = list(ports)
    opened = 0
    while remaining:
        remaining = [p for p in remaining if not port_open(p)]
        opened = len(ports) - len(remaining)
        if not remaining or time.time() >= deadline:
            break
        time.sleep(poll)
    return opened


def expected_manager_ports():
    """``MANAGER_PORTS`` minus any topology this environment cannot launch.

    The sss fail-closed manager (``sss_mgr``) is only launched when
    ``xrdsssadmin-brix`` could mint its cmsd keytab — ``build_all`` skips it
    otherwise (``gen_sss_keytab`` returns ``None``).  ``build_all`` runs before
    this gate and builds/resolves the tool on demand, so whether it resolves now
    (:func:`_find_sssadmin`, a no-build lookup across the dev tree and PATH) is
    the reliable proxy for "sss_mgr was started".  Where it never resolves its
    front door never binds and waiting for it is dead time; drop it here so the
    liveness gate blocks only on managers that came up."""
    ports = list(MANAGER_PORTS)
    if _find_sssadmin() is None:
        ports = [p for p in ports if p != PORTS["sss_mgr"]]
    return ports


def md5_file(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_text(path):
    with open(path) as f:
        return f.read()


def gen_cert(root):
    cert = os.path.join(root, "cert.pem")
    key = os.path.join(root, "key.pem")
    if not os.path.exists(cert):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
             "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=localhost"],  # net-literal-allow: cert subject CN under test
            capture_output=True, check=False,
        )
    return cert, key


# --------------------------------------------------------------------------- #
# Mesh launcher
# --------------------------------------------------------------------------- #


class Mesh:
    """Owns one topology's scratch dir + daemons (under MESH_DIR/<name>)."""

    def __init__(self, name):
        self.name = name
        self.root = os.path.join(MESH_DIR, name)
        for sub in ("cfg", "logs", "run"):
            os.makedirs(os.path.join(self.root, sub), exist_ok=True)

    def write(self, fname, text):
        path = os.path.join(self.root, "cfg", fname)
        with open(path, "w") as f:
            f.write(text)
        return path

    def datadir(self, node):
        d = os.path.join(self.root, f"{node}-data")
        os.makedirs(d, exist_ok=True)
        return d

    def seed(self, datadir, relpath, body):
        full = os.path.join(datadir, relpath.lstrip("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(body)
        return full

    def brix_node(self, label, role, data_port, cms_port, data_dir_,
                    export, manager, http_port=None, cert=None, key=None):
        run = os.path.join(self.root, "run", label)
        # Clear stale admin sockets / pid files — a leftover .olb/.xrd admin
        # path from a prior run makes xrootd/cmsd refuse to start.
        shutil.rmtree(run, ignore_errors=True)
        os.makedirs(run, exist_ok=True)
        delay = ""
        if role in ("manager", "supervisor"):
            delay = "cms.delay startup 5 servers 1 lookup 2\n"
        http = ""
        if http_port is not None:
            http = (
                f"if exec xrootd\n"
                f"  xrd.protocol http:{http_port} libXrdHttp-5.so\n"
                f"  http.cert {cert}\n"
                f"  http.key {key}\n"
                f"  http.selfhttps2http no\n"
                f"fi\n"
            )
        cfg = self.write(
            f"{label}.cfg",
            render("mesh_cms_xrootd_node.cfg",
                   ROLE=role, MANAGER=manager, DATA_PORT=data_port,
                   CMS_PORT=cms_port, DATA_DIR=data_dir_, EXPORT=export,
                   RUN=run, DELAY=delay, HTTP=http),
        )
        clog = os.path.join(self.root, "logs", f"{label}-cmsd.log")
        xlog = os.path.join(self.root, "logs", f"{label}-xrootd.log")
        # start_new_session detaches the daemons from the launcher's session so
        # they survive it (and any HUP when a transient launching shell exits).
        # cwd=self.root: xrootd/cmsd with `-n <name>` create a bare "<name>/"
        # instance directory in their CWD (independent of all.adminpath); without
        # this they would litter the pytest CWD (the repo root) with one empty
        # dir per node.  Pin it under the mesh's /tmp working tree instead.
        subprocess.run([CMSD_BIN, "-c", cfg, "-n", label, "-l", clog, "-b"],
                       check=False, start_new_session=True, cwd=self.root)
        subprocess.run([BRIX_BIN, "-c", cfg, "-n", label, "-l", xlog, "-b"],
                       check=False, start_new_session=True, cwd=self.root)

    def nginx(self, label, conf_text):
        pid = os.path.join(self.root, "run", f"{label}.pid")
        err = os.path.join(self.root, "logs", f"{label}-error.log")
        if os.path.exists(pid):
            os.remove(pid)                       # stale pid blocks a clean start
        conf_text = conf_text.replace("{PID}", pid).replace("{ERR}", err)
        conf = self.write(f"{label}.conf", conf_text)
        # Route the raw nginx launch through the registry's fleet seam rather
        # than shelling out to NGINX_BIN here (phase-81 lifecycle policy): the
        # mesh still owns the config text, the fixed ports and this pid file, and
        # reaps the daemon via stop_all().  cwd=self.root for parity with the
        # xrootd/cmsd daemons — keep any relative artifact inside the mesh's /tmp
        # tree rather than the pytest CWD.
        launch_fleet_nginx(conf, cwd=self.root)


# --------------------------------------------------------------------------- #
# nginx config builders
# --------------------------------------------------------------------------- #


def cfg_manager(data_port, cms_port):
    return render("mesh_cms_manager.conf",
                  BIND_HOST=BIND_HOST, DATA_PORT=data_port, CMS_PORT=cms_port)


# In-tree build location (dev checkout).  In the RPM-installed test layout
# (/usr/share/brix/tests) there is no source client/ tree; the brix-cache-tests
# package pulls brix-cache-client, so the very same tool is on PATH as
# /usr/bin/xrdsssadmin-brix — hence the PATH fallback in the resolver below.
XRDSSSADMIN_BIN = os.path.join(CLIENT_DIR, "bin", "xrdsssadmin-brix")


def _find_sssadmin():
    """Locate ``xrdsssadmin-brix`` WITHOUT building it, or return ``None``.

    Resolution order mirrors how the tool actually reaches a running box:
    an explicit ``TEST_XRDSSSADMIN_BIN`` override (parity with the other
    ``TEST_*_BIN`` knobs), then the in-tree build (dev checkout), then the
    RPM-installed ``xrdsssadmin-brix`` on PATH (brix-cache-client)."""
    override = os.environ.get("TEST_XRDSSSADMIN_BIN")
    if override:
        return override if os.path.exists(override) else None
    if os.path.exists(XRDSSSADMIN_BIN):
        return XRDSSSADMIN_BIN
    return shutil.which("xrdsssadmin-brix")


def _ensure_sssadmin():
    """Return a usable ``xrdsssadmin-brix``, building it on demand, or ``None``.

    Prefers an already-resolvable binary (:func:`_find_sssadmin`); failing that,
    compiles it into ``client/bin`` in a dev checkout — mirroring the SSS pytest
    fixtures (test_native_sss.py et al.) so the fail-closed sss_mgr topology can
    launch even where the client tools were not pre-built.  Returns ``None`` when
    it is absent and cannot be built (no client/ tree, or no C compiler)."""
    found = _find_sssadmin()
    if found is not None:
        return found
    if not os.path.isdir(CLIENT_DIR):
        return None
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        return None
    subprocess.run(["make", "-C", CLIENT_DIR, "xrdsssadmin-brix"],
                   capture_output=True, text=True)
    return XRDSSSADMIN_BIN if os.path.exists(XRDSSSADMIN_BIN) else None


def gen_sss_keytab(path):
    """Mint an SSS keytab for the fail-closed sss_mgr via ``xrdsssadmin-brix``.

    The tool writes the same keytab text format nginx's SSS parser reads, so the
    one file serves both the cmsd registration handshake and nginx.  ``--id 1``
    keeps the key id within int64 range (nginx parses it with strtoll).  Returns
    the keytab path, or ``None`` if the tool is unavailable/unbuildable."""
    if os.path.exists(path):
        return path
    sssadmin = _ensure_sssadmin()
    if sssadmin is None:
        return None
    os.makedirs(os.path.dirname(path), exist_ok=True)
    subprocess.run([sssadmin, "-k", path, "add", "--id", "1",
                    "--user", "cmsnode", "--group", "cms", "--name", "cmsnode"],
                   capture_output=True, text=True, check=False)
    if os.path.exists(path):
        os.chmod(path, 0o600)
        return path
    return None


def cfg_manager_sss(data_port, cms_port, keytab):
    """Manager that REQUIRES sss on the CMS port — a data node must complete
    the kYR_xauth sss handshake to be admitted (fail-closed)."""
    return render("mesh_cms_manager_sss.conf",
                  BIND_HOST=BIND_HOST, DATA_PORT=data_port, CMS_PORT=cms_port,
                  KEYTAB=keytab)


def cfg_datanode(data_port, root, cms_mgr, paths):
    return render("mesh_cms_datanode.conf",
                  BIND_HOST=BIND_HOST, DATA_PORT=data_port, ROOT=root,
                  CMS_MGR=cms_mgr, PATHS=paths)

from split_continuation import load as _load_continuations
_load_continuations(globals(), __file__, "cms_mesh_lib_part2.py", "cms_mesh_lib_part3.py")
