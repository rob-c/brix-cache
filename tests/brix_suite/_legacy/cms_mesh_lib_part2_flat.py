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

def _phase_build_all_1(big):
    if not os.path.exists(big):
        with open(big, "wb") as f:
            f.write(os.urandom(16 * 1024 * 1024))


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


def cfg_submanager(data_port, cms_port, root, parent_cms):
    return render("mesh_cms_submanager.conf",
                  BIND_HOST=BIND_HOST, DATA_PORT=data_port, CMS_PORT=cms_port,
                  ROOT=root, PARENT_CMS=parent_cms)


def cfg_dual(root_port, https_port, root, cms_mgr, paths, cert, key, tmpbase):
    return render("mesh_cms_dual.conf",
                  BIND_HOST=BIND_HOST, ROOT_PORT=root_port, HTTPS_PORT=https_port,
                  ROOT=root, CMS_MGR=cms_mgr, PATHS=paths, CERT=cert, KEY=key,
                  TMPBASE=tmpbase)


# --------------------------------------------------------------------------- #
# Client helpers (used by the tests)
# --------------------------------------------------------------------------- #


def xrdfs_locate(mgr_port, path, timeout=15, retries=4):
    last = (1, "", "")
    for attempt in range(retries):
        r = subprocess.run([XRDFS_BIN, f"{HOST}:{mgr_port}", "locate", path],
                           capture_output=True, text=True, timeout=timeout,
                           env=_XRD_ENV)
        last = (r.returncode, r.stdout.strip(), r.stderr.strip())
        if r.returncode == 0:
            return last
        # Back off only BETWEEN attempts — sleeping after the final failed try
        # just adds dead time before returning failure.  This matters on the
        # readiness hot path: _probe_ready calls with retries=1, so the trailing
        # sleep was pure per-round overhead on every still-forming topology.
        if attempt < retries - 1:
            time.sleep(2)
    return last


def xrdcp_get(mgr_port, path, dst, timeout=60, retries=3):
    """Fetch via the manager, retrying transient redirect/connect failures
    (a data node may still be settling its first heartbeat).

    A hung transfer (e.g. an unserved path the manager waits on) is caught and
    returned as a clean non-zero result rather than raising TimeoutExpired, so
    callers never have to guard against the exception."""
    url = f"root://{HOST}:{mgr_port}//{path.lstrip('/')}"
    last = None
    for attempt in range(retries):
        try:
            last = subprocess.run([XRDCP_BIN, "-f", url, dst],
                                  capture_output=True, text=True, timeout=timeout,
                                  env=_XRD_ENV)
        except subprocess.TimeoutExpired as e:
            last = subprocess.CompletedProcess(
                e.cmd, returncode=124, stdout=e.stdout or "",
                stderr=(e.stderr or "") + f"\n[timeout after {timeout}s]")
        if last.returncode == 0:
            return last
        if attempt < retries - 1:
            time.sleep(2)
    return last


def xrdcp_put(mgr_port, src, path, timeout=60):
    return subprocess.run(
        [XRDCP_BIN, "-f", src, f"root://{HOST}:{mgr_port}//{path.lstrip('/')}"],
        capture_output=True, text=True, timeout=timeout, env=_XRD_ENV)


def xrdfs_stat(mgr_port, path, timeout=25):
    r = subprocess.run([XRDFS_BIN, f"{HOST}:{mgr_port}", "stat", path],
                       capture_output=True, text=True, timeout=timeout, env=_XRD_ENV)
    return r.returncode, r.stdout, r.stderr


def xrdfs_ls(mgr_port, path, timeout=25):
    r = subprocess.run([XRDFS_BIN, f"{HOST}:{mgr_port}", "ls", path],
                       capture_output=True, text=True, timeout=timeout, env=_XRD_ENV)
    return r.returncode, r.stdout, r.stderr


def https_get(port, path, dst, timeout=60):
    return subprocess.run(
        ["curl", "-ksS", "-o", dst, "-w", "%{http_code}",
         f"https://{HOST}:{port}/{path.lstrip('/')}"],
        capture_output=True, text=True, timeout=timeout)


def https_put(port, src, path, timeout=60):
    return subprocess.run(
        ["curl", "-ksS", "-T", src, "-w", "%{http_code}",
         f"https://{HOST}:{port}/{path.lstrip('/')}"],
        capture_output=True, text=True, timeout=timeout)


def located_port(stdout):
    ports = set()
    for line in stdout.splitlines():
        line = line.strip()
        if "]:" in line:
            try:
                ports.add(int(line.split("]:")[1].split()[0]))
            except (IndexError, ValueError):
                pass
        elif ":" in line:
            try:
                ports.add(int(line.split(":")[-1].split()[0]))
            except (IndexError, ValueError):
                pass
    return ports


def stat_size(stdout):
    for line in stdout.splitlines():
        line = line.strip()
        if line.lower().startswith("size:"):
            try:
                return int(line.split(":", 1)[1].strip())
            except ValueError:
                return None
    return None


# --------------------------------------------------------------------------- #
# Topology builders — each seeds deterministic content and launches daemons
# --------------------------------------------------------------------------- #


def _b(m, label, port, root, cms, paths):
    m.nginx(label, cfg_datanode(port, root, cms, paths))


def build_all():
    """Bring up every harness-managed CMS-mesh topology under MESH_DIR."""
    p = PORTS

    # A: real manager + nginx data node
    m = Mesh("a")
    m.brix_node("a-mgr", "manager", p["a_mgr"], p["a_mgr_cms"],
                  m.datadir("a-mgr"), "/", f"{HOST}:{p['a_mgr_cms']}")
    d = m.datadir("a-nds"); m.seed(d, "/fileA.txt", content("a"))
    _b(m, "a-nds", p["a_nds"], d, f"{HOST}:{p['a_mgr_cms']}", "/")

    # B: nginx manager + real data node
    m = Mesh("b")
    m.nginx("b-mgr", cfg_manager(p["b_mgr"], p["b_mgr_cms"]))
    d = m.datadir("b-rds"); m.seed(d, "/fileB.txt", content("b"))
    m.brix_node("b-rds", "server", p["b_rds"], p["b_rds_cms"], d, "/",
                  f"{HOST}:{p['b_mgr_cms']}")

    # C: nginx manager + nginx DS (/ngx) + real DS (/real)
    m = Mesh("c")
    m.nginx("c-mgr", cfg_manager(p["c_mgr"], p["c_mgr_cms"]))
    dn = m.datadir("c-nds"); m.seed(dn, "/ngx/n.txt", content("c-ngx"))
    _b(m, "c-nds", p["c_nds"], dn, f"{HOST}:{p['c_mgr_cms']}", "/ngx")
    dr = m.datadir("c-rds"); m.seed(dr, "/real/r.txt", content("c-real"))
    m.brix_node("c-rds", "server", p["c_rds"], p["c_rds_cms"], dr, "/real",
                  f"{HOST}:{p['c_mgr_cms']}")

    # D: real meta -> nginx sub -> nginx leaf
    m = Mesh("d")
    m.brix_node("d-meta", "manager", p["d_meta"], p["d_meta_cms"],
                  m.datadir("d-meta"), "/", f"{HOST}:{p['d_meta_cms']}")
    m.nginx("d-sub", cfg_submanager(p["d_sub"], p["d_sub_cms"],
            m.datadir("d-sub"), f"{HOST}:{p['d_meta_cms']}"))
    dl = m.datadir("d-leaf"); m.seed(dl, "/fileD.txt", content("d"))
    _b(m, "d-leaf", p["d_leaf"], dl, f"{HOST}:{p['d_sub_cms']}", "/")

    # pool: real manager + 2 nginx
    m = Mesh("prm")
    m.brix_node("prm-mgr", "manager", p["prm_mgr"], p["prm_mgr_cms"],
                  m.datadir("prm-mgr"), "/", f"{HOST}:{p['prm_mgr_cms']}")
    d1 = m.datadir("prm-n1"); m.seed(d1, "/a/x.txt", content("prm-a"))
    _b(m, "prm-n1", p["prm_n1"], d1, f"{HOST}:{p['prm_mgr_cms']}", "/a")
    d2 = m.datadir("prm-n2"); m.seed(d2, "/b/y.txt", content("prm-b"))
    _b(m, "prm-n2", p["prm_n2"], d2, f"{HOST}:{p['prm_mgr_cms']}", "/b")

    # pool: nginx manager + 2 real
    m = Mesh("pnm")
    m.nginx("pnm-mgr", cfg_manager(p["pnm_mgr"], p["pnm_mgr_cms"]))
    d1 = m.datadir("pnm-r1"); m.seed(d1, "/ra/x.txt", content("pnm-ra"))
    m.brix_node("pnm-r1", "server", p["pnm_r1"], p["pnm_r1_cms"], d1, "/ra",
                  f"{HOST}:{p['pnm_mgr_cms']}")
    d2 = m.datadir("pnm-r2"); m.seed(d2, "/rb/y.txt", content("pnm-rb"))
    m.brix_node("pnm-r2", "server", p["pnm_r2"], p["pnm_r2_cms"], d2, "/rb",
                  f"{HOST}:{p['pnm_mgr_cms']}")

    # write through real mgr -> nginx node (/.probe = readiness marker)
    m = Mesh("wrm")
    m.brix_node("wrm-mgr", "manager", p["wrm_mgr"], p["wrm_mgr_cms"],
                  m.datadir("wrm-mgr"), "/", f"{HOST}:{p['wrm_mgr_cms']}")
    dw = m.datadir("wrm-nds"); m.seed(dw, "/.probe", content("wrm-probe"))
    _b(m, "wrm-nds", p["wrm_nds"], dw, f"{HOST}:{p['wrm_mgr_cms']}", "/")

    # write through nginx mgr -> real node (/.probe = readiness marker)
    m = Mesh("wnm")
    m.nginx("wnm-mgr", cfg_manager(p["wnm_mgr"], p["wnm_mgr_cms"]))
    dw = m.datadir("wnm-rds"); m.seed(dw, "/.probe", content("wnm-probe"))
    m.brix_node("wnm-rds", "server", p["wnm_rds"], p["wnm_rds_cms"], dw, "/",
                  f"{HOST}:{p['wnm_mgr_cms']}")

    # stat/ls: nginx mgr + real node (4096-byte file)
    m = Mesh("sl")
    m.nginx("sl-mgr", cfg_manager(p["sl_mgr"], p["sl_mgr_cms"]))
    d = m.datadir("sl-rds"); m.seed(d, "/d/f.txt", "x" * 4096)
    m.brix_node("sl-rds", "server", p["sl_rds"], p["sl_rds_cms"], d, "/",
                  f"{HOST}:{p['sl_mgr_cms']}")

    # negative: nginx mgr + real node exporting /real only
    m = Mesh("neg")
    m.nginx("neg-mgr", cfg_manager(p["neg_mgr"], p["neg_mgr_cms"]))
    d = m.datadir("neg-rds"); m.seed(d, "/real/here.txt", content("neg"))
    m.brix_node("neg-rds", "server", p["neg_rds"], p["neg_rds_cms"], d,
                  "/real", f"{HOST}:{p['neg_mgr_cms']}")

    # failover: nginx mgr + real node (test kills the node by port)
    m = Mesh("fo")
    m.nginx("fo-mgr", cfg_manager(p["fo_mgr"], p["fo_mgr_cms"]))
    d = m.datadir("fo-rds"); m.seed(d, "/f.txt", content("fo"))
    m.brix_node("fo-rds", "server", p["fo_rds"], p["fo_rds_cms"], d, "/",
                  f"{HOST}:{p['fo_mgr_cms']}")

    # large-file integrity: nginx mgr + real node (16 MiB random file)
    m = Mesh("lg")
    m.nginx("lg-mgr", cfg_manager(p["lg_mgr"], p["lg_mgr_cms"]))
    d = m.datadir("lg-rds")
    big = os.path.join(d, "big.bin")
    _phase_build_all_1(big)
    m.brix_node("lg-rds", "server", p["lg_rds"], p["lg_rds_cms"], d, "/",
                  f"{HOST}:{p['lg_mgr_cms']}")

    # baseline: real mgr + real node
    m = Mesh("bl")
    m.brix_node("bl-mgr", "manager", p["bl_mgr"], p["bl_mgr_cms"],
                  m.datadir("bl-mgr"), "/", f"{HOST}:{p['bl_mgr_cms']}")
    d = m.datadir("bl-rds"); m.seed(d, "/base.txt", content("bl"))
    m.brix_node("bl-rds", "server", p["bl_rds"], p["bl_rds_cms"], d, "/",
                  f"{HOST}:{p['bl_mgr_cms']}")

    # multi-tier with a real leaf
    m = Mesh("mrl")
    m.brix_node("mrl-meta", "manager", p["mrl_meta"], p["mrl_meta_cms"],
                  m.datadir("mrl-meta"), "/", f"{HOST}:{p['mrl_meta_cms']}")
    m.nginx("mrl-sub", cfg_submanager(p["mrl_sub"], p["mrl_sub_cms"],
            m.datadir("mrl-sub"), f"{HOST}:{p['mrl_meta_cms']}"))
    d = m.datadir("mrl-leaf"); m.seed(d, "/fileE.txt", content("mrl"))
    m.brix_node("mrl-leaf", "server", p["mrl_leaf"], p["mrl_leaf_cms"], d,
                  "/", f"{HOST}:{p['mrl_sub_cms']}")

    # tri-protocol: nginx mgr + dual nginx (root + https) + real
    m = Mesh("tri")
    cert, key = gen_cert(m.root)
    m.nginx("tri-mgr", cfg_manager(p["tri_mgr"], p["tri_mgr_cms"]))
    dd = m.datadir("tri-dual"); m.seed(dd, "/dav/f.txt", content("tri-dav"))
    tb = os.path.join(m.root, "run", "tri-dual-tmp"); os.makedirs(tb, exist_ok=True)
    m.nginx("tri-dual", cfg_dual(p["tri_dual"], p["tri_dual_https"], dd,
            f"{HOST}:{p['tri_mgr_cms']}", "/dav", cert, key, tb))
    dr = m.datadir("tri-real"); m.seed(dr, "/real/r.txt", content("tri-real"))
    m.brix_node("tri-real", "server", p["tri_real"], p["tri_real_cms"], dr,
                  "/real", f"{HOST}:{p['tri_mgr_cms']}")

    # wide pool: nginx mgr + 2 nginx + 2 real
    m = Mesh("wide")
    m.nginx("w-mgr", cfg_manager(p["w_mgr"], p["w_mgr_cms"]))
    for label, port, path, tag in (("w-n1", p["w_n1"], "na", "w-na"),
                                    ("w-n2", p["w_n2"], "nb", "w-nb")):
        d = m.datadir(label); m.seed(d, f"/{path}/f.txt", content(tag))
        _b(m, label, port, d, f"{HOST}:{p['w_mgr_cms']}", f"/{path}")
    for label, port, cms, path, tag in (
            ("w-r1", p["w_r1"], p["w_r1_cms"], "ra", "w-ra"),
            ("w-r2", p["w_r2"], p["w_r2_cms"], "rb", "w-rb")):
        d = m.datadir(label); m.seed(d, f"/{path}/f.txt", content(tag))
        m.brix_node(label, "server", port, cms, d, f"/{path}",
                      f"{HOST}:{p['w_mgr_cms']}")

    # real xrootd http: root:// (CMS) + https:// (XrdHttp)
    m = Mesh("rh")
    cert, key = gen_cert(m.root)
    m.nginx("rh-mgr", cfg_manager(p["rh_mgr"], p["rh_mgr_cms"]))
    d = m.datadir("rh-real"); m.seed(d, "/h.txt", content("rh"))
    m.brix_node("rh-real", "server", p["rh_real"], p["rh_real_cms"], d, "/",
                  f"{HOST}:{p['rh_mgr_cms']}", http_port=p["rh_real_http"],
                  cert=cert, key=key)

    # sss: nginx manager that REQUIRES the cmsd sss handshake (W1a) + a plain
    # data node that does not present one → must be refused registration
    # (fail-closed).  The keytab is generated by xrdsssadmin into the manager's
    # cfg dir; the node is intentionally non-sss.  There is deliberately NO
    # READY_PROBE for this topology — the node never registers by design, which
    # is exactly what test_cms_sss_fail_closed asserts.
    m = Mesh("sss")
    kt = gen_sss_keytab(os.path.join(m.root, "cfg", "cms.keytab"))
    if kt is not None:
        m.nginx("sss-mgr", cfg_manager_sss(p["sss_mgr"], p["sss_mgr_cms"], kt))
        d = m.datadir("sss-rds"); m.seed(d, "/fileS.txt", content("sss"))
        m.brix_node("sss-rds", "server", p["sss_rds"], p["sss_rds_cms"], d,
                      "/", f"{HOST}:{p['sss_mgr_cms']}")


def _kill_pidfile_group(pidfile):
    """SIGKILL the whole process group named by an nginx master pidfile.

    nginx is launched with start_new_session=True, so the master is its own
    process-group leader (PGID == master pid) and killpg reaps the orphan-prone
    worker processes too — killing the master alone leaves workers holding the
    listen socket."""
    try:
        pid = int(read_text(pidfile).strip())
    except (OSError, ValueError):
        return
    for kill in (lambda: os.killpg(pid, signal.SIGKILL),
                 lambda: os.kill(pid, signal.SIGKILL)):
        try:
            kill()
            break
        except OSError:
            continue
    try:
        os.remove(pidfile)
    except OSError:
        pass
