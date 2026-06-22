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

from settings import NGINX_BIN, HOST, BIND_HOST

# --------------------------------------------------------------------------- #
# Binaries / constants
# --------------------------------------------------------------------------- #

XROOTD_BIN = shutil.which(os.environ.get("TEST_XROOTD_BIN", "xrootd"))
CMSD_BIN = shutil.which(os.environ.get("TEST_CMSD_BIN", "cmsd"))
XRDFS_BIN = shutil.which(os.environ.get("TEST_XRDFS_BIN", "xrdfs"))
XRDCP_BIN = shutil.which(os.environ.get("TEST_XRDCP_BIN", "xrdcp"))
CURL_BIN = shutil.which("curl")

# Where the harness drops the mesh's generated configs/data/logs.
MESH_DIR = os.environ.get("CMS_MESH_DIR", "/tmp/xrd-test/cms-mesh")

# Unauthenticated XRootD client env (keep any ambient GSI proxy out).
_XRD_ENV = {
    k: v
    for k, v in os.environ.items()
    if k not in ("X509_USER_PROXY", "X509_USER_CERT", "X509_USER_KEY",
                 "XrdSecPROTOCOL", "XRD_SECPROTOCOL")
}
_XRD_ENV["XrdSecPROTOCOL"] = "unix"


def have_binaries():
    return all([XROOTD_BIN, CMSD_BIN, XRDFS_BIN, XRDCP_BIN,
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

# Lowest port whose listener marks a mesh as "up" (used by force-stop too).
PORT_MIN, PORT_MAX = 21610, 21749


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
# would never succeed.  Its listener is still gated via MANAGER_PORTS.

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
             "-out", cert, "-days", "1", "-nodes", "-subj", "/CN=localhost"],
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

    def xrootd_node(self, label, role, data_port, cms_port, data_dir_,
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
            f"all.role {role}\n"
            f"all.manager {manager}\n"
            f"xrd.port {data_port}\n"
            f"if exec cmsd\n  xrd.port {cms_port}\nfi\n"
            f"oss.localroot {data_dir_}\n"
            f"all.export {export} r/w\n"
            f"all.adminpath {run}\n"
            f"all.pidpath {run}\n"
            f"{delay}{http}cms.trace all\n",
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
        subprocess.run([XROOTD_BIN, "-c", cfg, "-n", label, "-l", xlog, "-b"],
                       check=False, start_new_session=True, cwd=self.root)

    def nginx(self, label, conf_text):
        pid = os.path.join(self.root, "run", f"{label}.pid")
        err = os.path.join(self.root, "logs", f"{label}-error.log")
        if os.path.exists(pid):
            os.remove(pid)                       # stale pid blocks a clean start
        conf_text = conf_text.replace("{PID}", pid).replace("{ERR}", err)
        conf = self.write(f"{label}.conf", conf_text)
        # cwd=self.root for parity with the daemons — keep any relative artifact
        # inside the mesh's /tmp tree rather than the pytest CWD.
        subprocess.run([NGINX_BIN, "-c", conf], check=False,
                       start_new_session=True, cwd=self.root)


# --------------------------------------------------------------------------- #
# nginx config builders
# --------------------------------------------------------------------------- #


def cfg_manager(data_port, cms_port):
    return (
        "worker_processes 1;\nerror_log {ERR} info;\npid {PID};\n"
        "events { worker_connections 128; }\n"
        "stream {\n"
        f"    server {{ listen {BIND_HOST}:{data_port}; xrootd on; xrootd_auth none;"
        f" xrootd_manager_mode on; }}\n"
        f"    server {{ listen {BIND_HOST}:{cms_port}; xrootd_cms_server on; }}\n"
        "}\n"
    )


XRDSSSADMIN_BIN = shutil.which("xrdsssadmin")


def gen_sss_keytab(path):
    """Create an SSS keytab via xrdsssadmin.  The tool emits the same text
    format nginx's keytab parser reads, so one file works for both sides.
    `-n 1` keeps the key id within int64 range (nginx parses it with strtoll).
    Returns the path, or None if xrdsssadmin is unavailable."""
    if XRDSSSADMIN_BIN is None or os.path.exists(path):
        return path if os.path.exists(path) else None
    os.makedirs(os.path.dirname(path), exist_ok=True)
    subprocess.run([XRDSSSADMIN_BIN, "-n", "1", "-k", "cmskey",
                    "-u", "cmsnode", "-g", "cms", "add", path],
                   input="y\n", capture_output=True, text=True, check=False)
    if os.path.exists(path):
        os.chmod(path, 0o600)
        return path
    return None


def cfg_manager_sss(data_port, cms_port, keytab):
    """Manager that REQUIRES sss on the CMS port — a data node must complete
    the kYR_xauth sss handshake to be admitted (fail-closed)."""
    return (
        "worker_processes 1;\nerror_log {ERR} info;\npid {PID};\n"
        "events { worker_connections 128; }\n"
        "stream {\n"
        f"    server {{ listen {BIND_HOST}:{data_port}; xrootd on; xrootd_auth none;"
        f" xrootd_manager_mode on; }}\n"
        f"    server {{ listen {BIND_HOST}:{cms_port}; xrootd_cms_server on;"
        f" xrootd_cms_server_sss_keytab {keytab}; }}\n"
        "}\n"
    )


def cfg_datanode(data_port, root, cms_mgr, paths):
    return (
        "worker_processes 1;\nerror_log {ERR} info;\npid {PID};\n"
        "events { worker_connections 128; }\n"
        "stream {\n"
        f"    server {{\n"
        f"        listen {BIND_HOST}:{data_port};\n"
        f"        xrootd on; xrootd_root {root}; xrootd_auth none;\n"
        f"        xrootd_allow_write on;\n"
        f"        xrootd_cms_manager {cms_mgr}; xrootd_cms_paths {paths};\n"
        f"        xrootd_cms_interval 2; xrootd_listen_port {data_port};\n"
        f"    }}\n"
        "}\n"
    )


def cfg_submanager(data_port, cms_port, root, parent_cms):
    return (
        "worker_processes 1;\nerror_log {ERR} info;\npid {PID};\n"
        "events { worker_connections 128; }\n"
        "stream {\n"
        f"    server {{\n"
        f"        listen {BIND_HOST}:{data_port};\n"
        f"        xrootd on; xrootd_root {root}; xrootd_auth none;\n"
        f"        xrootd_manager_mode on;\n"
        f"        xrootd_cms_manager {parent_cms}; xrootd_cms_paths /;\n"
        f"        xrootd_cms_interval 2; xrootd_listen_port {data_port};\n"
        f"    }}\n"
        f"    server {{ listen {BIND_HOST}:{cms_port}; xrootd_cms_server on; }}\n"
        "}\n"
    )


def cfg_dual(root_port, https_port, root, cms_mgr, paths, cert, key, tmpbase):
    return (
        "worker_processes 1;\nerror_log {ERR} info;\npid {PID};\n"
        "events { worker_connections 128; }\n"
        "stream {\n"
        f"    server {{\n"
        f"        listen {BIND_HOST}:{root_port};\n"
        f"        xrootd on; xrootd_root {root}; xrootd_auth none;\n"
        f"        xrootd_allow_write on;\n"
        f"        xrootd_cms_manager {cms_mgr}; xrootd_cms_paths {paths};\n"
        f"        xrootd_cms_interval 2; xrootd_listen_port {root_port};\n"
        f"    }}\n"
        "}\n"
        "http {\n    access_log off;\n"
        f"    client_body_temp_path {tmpbase}/cbt;\n"
        f"    proxy_temp_path {tmpbase}/pt;\n"
        f"    fastcgi_temp_path {tmpbase}/ft;\n"
        f"    uwsgi_temp_path {tmpbase}/ut;\n"
        f"    scgi_temp_path {tmpbase}/st;\n"
        f"    server {{\n"
        f"        listen {BIND_HOST}:{https_port} ssl;\n        server_name localhost;\n"
        f"        ssl_certificate {cert};\n        ssl_certificate_key {key};\n"
        f"        location / {{ xrootd_webdav on; xrootd_webdav_root {root};"
        f" xrootd_webdav_auth none; xrootd_webdav_allow_write on; }}\n"
        f"    }}\n"
        "}\n"
    )


# --------------------------------------------------------------------------- #
# Client helpers (used by the tests)
# --------------------------------------------------------------------------- #


def xrdfs_locate(mgr_port, path, timeout=15, retries=4):
    last = (1, "", "")
    for _ in range(retries):
        r = subprocess.run([XRDFS_BIN, f"{HOST}:{mgr_port}", "locate", path],
                           capture_output=True, text=True, timeout=timeout,
                           env=_XRD_ENV)
        last = (r.returncode, r.stdout.strip(), r.stderr.strip())
        if r.returncode == 0:
            return last
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
    m.xrootd_node("a-mgr", "manager", p["a_mgr"], p["a_mgr_cms"],
                  m.datadir("a-mgr"), "/", f"{HOST}:{p['a_mgr_cms']}")
    d = m.datadir("a-nds"); m.seed(d, "/fileA.txt", content("a"))
    _b(m, "a-nds", p["a_nds"], d, f"{HOST}:{p['a_mgr_cms']}", "/")

    # B: nginx manager + real data node
    m = Mesh("b")
    m.nginx("b-mgr", cfg_manager(p["b_mgr"], p["b_mgr_cms"]))
    d = m.datadir("b-rds"); m.seed(d, "/fileB.txt", content("b"))
    m.xrootd_node("b-rds", "server", p["b_rds"], p["b_rds_cms"], d, "/",
                  f"{HOST}:{p['b_mgr_cms']}")

    # C: nginx manager + nginx DS (/ngx) + real DS (/real)
    m = Mesh("c")
    m.nginx("c-mgr", cfg_manager(p["c_mgr"], p["c_mgr_cms"]))
    dn = m.datadir("c-nds"); m.seed(dn, "/ngx/n.txt", content("c-ngx"))
    _b(m, "c-nds", p["c_nds"], dn, f"{HOST}:{p['c_mgr_cms']}", "/ngx")
    dr = m.datadir("c-rds"); m.seed(dr, "/real/r.txt", content("c-real"))
    m.xrootd_node("c-rds", "server", p["c_rds"], p["c_rds_cms"], dr, "/real",
                  f"{HOST}:{p['c_mgr_cms']}")

    # D: real meta -> nginx sub -> nginx leaf
    m = Mesh("d")
    m.xrootd_node("d-meta", "manager", p["d_meta"], p["d_meta_cms"],
                  m.datadir("d-meta"), "/", f"{HOST}:{p['d_meta_cms']}")
    m.nginx("d-sub", cfg_submanager(p["d_sub"], p["d_sub_cms"],
            m.datadir("d-sub"), f"{HOST}:{p['d_meta_cms']}"))
    dl = m.datadir("d-leaf"); m.seed(dl, "/fileD.txt", content("d"))
    _b(m, "d-leaf", p["d_leaf"], dl, f"{HOST}:{p['d_sub_cms']}", "/")

    # pool: real manager + 2 nginx
    m = Mesh("prm")
    m.xrootd_node("prm-mgr", "manager", p["prm_mgr"], p["prm_mgr_cms"],
                  m.datadir("prm-mgr"), "/", f"{HOST}:{p['prm_mgr_cms']}")
    d1 = m.datadir("prm-n1"); m.seed(d1, "/a/x.txt", content("prm-a"))
    _b(m, "prm-n1", p["prm_n1"], d1, f"{HOST}:{p['prm_mgr_cms']}", "/a")
    d2 = m.datadir("prm-n2"); m.seed(d2, "/b/y.txt", content("prm-b"))
    _b(m, "prm-n2", p["prm_n2"], d2, f"{HOST}:{p['prm_mgr_cms']}", "/b")

    # pool: nginx manager + 2 real
    m = Mesh("pnm")
    m.nginx("pnm-mgr", cfg_manager(p["pnm_mgr"], p["pnm_mgr_cms"]))
    d1 = m.datadir("pnm-r1"); m.seed(d1, "/ra/x.txt", content("pnm-ra"))
    m.xrootd_node("pnm-r1", "server", p["pnm_r1"], p["pnm_r1_cms"], d1, "/ra",
                  f"{HOST}:{p['pnm_mgr_cms']}")
    d2 = m.datadir("pnm-r2"); m.seed(d2, "/rb/y.txt", content("pnm-rb"))
    m.xrootd_node("pnm-r2", "server", p["pnm_r2"], p["pnm_r2_cms"], d2, "/rb",
                  f"{HOST}:{p['pnm_mgr_cms']}")

    # write through real mgr -> nginx node (/.probe = readiness marker)
    m = Mesh("wrm")
    m.xrootd_node("wrm-mgr", "manager", p["wrm_mgr"], p["wrm_mgr_cms"],
                  m.datadir("wrm-mgr"), "/", f"{HOST}:{p['wrm_mgr_cms']}")
    dw = m.datadir("wrm-nds"); m.seed(dw, "/.probe", content("wrm-probe"))
    _b(m, "wrm-nds", p["wrm_nds"], dw, f"{HOST}:{p['wrm_mgr_cms']}", "/")

    # write through nginx mgr -> real node (/.probe = readiness marker)
    m = Mesh("wnm")
    m.nginx("wnm-mgr", cfg_manager(p["wnm_mgr"], p["wnm_mgr_cms"]))
    dw = m.datadir("wnm-rds"); m.seed(dw, "/.probe", content("wnm-probe"))
    m.xrootd_node("wnm-rds", "server", p["wnm_rds"], p["wnm_rds_cms"], dw, "/",
                  f"{HOST}:{p['wnm_mgr_cms']}")

    # stat/ls: nginx mgr + real node (4096-byte file)
    m = Mesh("sl")
    m.nginx("sl-mgr", cfg_manager(p["sl_mgr"], p["sl_mgr_cms"]))
    d = m.datadir("sl-rds"); m.seed(d, "/d/f.txt", "x" * 4096)
    m.xrootd_node("sl-rds", "server", p["sl_rds"], p["sl_rds_cms"], d, "/",
                  f"{HOST}:{p['sl_mgr_cms']}")

    # negative: nginx mgr + real node exporting /real only
    m = Mesh("neg")
    m.nginx("neg-mgr", cfg_manager(p["neg_mgr"], p["neg_mgr_cms"]))
    d = m.datadir("neg-rds"); m.seed(d, "/real/here.txt", content("neg"))
    m.xrootd_node("neg-rds", "server", p["neg_rds"], p["neg_rds_cms"], d,
                  "/real", f"{HOST}:{p['neg_mgr_cms']}")

    # failover: nginx mgr + real node (test kills the node by port)
    m = Mesh("fo")
    m.nginx("fo-mgr", cfg_manager(p["fo_mgr"], p["fo_mgr_cms"]))
    d = m.datadir("fo-rds"); m.seed(d, "/f.txt", content("fo"))
    m.xrootd_node("fo-rds", "server", p["fo_rds"], p["fo_rds_cms"], d, "/",
                  f"{HOST}:{p['fo_mgr_cms']}")

    # large-file integrity: nginx mgr + real node (16 MiB random file)
    m = Mesh("lg")
    m.nginx("lg-mgr", cfg_manager(p["lg_mgr"], p["lg_mgr_cms"]))
    d = m.datadir("lg-rds")
    big = os.path.join(d, "big.bin")
    if not os.path.exists(big):
        with open(big, "wb") as f:
            f.write(os.urandom(16 * 1024 * 1024))
    m.xrootd_node("lg-rds", "server", p["lg_rds"], p["lg_rds_cms"], d, "/",
                  f"{HOST}:{p['lg_mgr_cms']}")

    # baseline: real mgr + real node
    m = Mesh("bl")
    m.xrootd_node("bl-mgr", "manager", p["bl_mgr"], p["bl_mgr_cms"],
                  m.datadir("bl-mgr"), "/", f"{HOST}:{p['bl_mgr_cms']}")
    d = m.datadir("bl-rds"); m.seed(d, "/base.txt", content("bl"))
    m.xrootd_node("bl-rds", "server", p["bl_rds"], p["bl_rds_cms"], d, "/",
                  f"{HOST}:{p['bl_mgr_cms']}")

    # multi-tier with a real leaf
    m = Mesh("mrl")
    m.xrootd_node("mrl-meta", "manager", p["mrl_meta"], p["mrl_meta_cms"],
                  m.datadir("mrl-meta"), "/", f"{HOST}:{p['mrl_meta_cms']}")
    m.nginx("mrl-sub", cfg_submanager(p["mrl_sub"], p["mrl_sub_cms"],
            m.datadir("mrl-sub"), f"{HOST}:{p['mrl_meta_cms']}"))
    d = m.datadir("mrl-leaf"); m.seed(d, "/fileE.txt", content("mrl"))
    m.xrootd_node("mrl-leaf", "server", p["mrl_leaf"], p["mrl_leaf_cms"], d,
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
    m.xrootd_node("tri-real", "server", p["tri_real"], p["tri_real_cms"], dr,
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
        m.xrootd_node(label, "server", port, cms, d, f"/{path}",
                      f"{HOST}:{p['w_mgr_cms']}")

    # real xrootd http: root:// (CMS) + https:// (XrdHttp)
    m = Mesh("rh")
    cert, key = gen_cert(m.root)
    m.nginx("rh-mgr", cfg_manager(p["rh_mgr"], p["rh_mgr_cms"]))
    d = m.datadir("rh-real"); m.seed(d, "/h.txt", content("rh"))
    m.xrootd_node("rh-real", "server", p["rh_real"], p["rh_real_cms"], d, "/",
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
        m.xrootd_node("sss-rds", "server", p["sss_rds"], p["sss_rds_cms"], d,
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


def stop_all():
    """Tear down every mesh daemon reliably (process groups + cfg match + ports).

    Order matters: kill nginx by process group first (catches orphaned workers),
    then xrootd/cmsd by their config path, then sweep any survivor still holding
    one of our ports, then block until the manager front doors are actually free
    so a relaunch cannot race a lingering listener."""
    # 1. nginx masters + their worker groups, via the pid files we wrote.
    for pidfile in glob.glob(os.path.join(MESH_DIR, "*", "run", "*.pid")):
        _kill_pidfile_group(pidfile)

    # 2. xrootd + cmsd: command line carries `-c <MESH_DIR>/<topo>/cfg/<file>`.
    #    Deliberately NOT a bare `-f MESH_DIR`: that also matches the launcher
    #    process whose cmdline carries CMS_MESH_DIR=<MESH_DIR>, killing ourselves.
    subprocess.run(["pkill", "-9", "-f", f"{MESH_DIR}/[^ ]*/cfg/"], check=False)
    # 3. nginx masters whose pid file was missing/stale (matched by their .conf).
    subprocess.run(["pkill", "-9", "-f", f"{MESH_DIR}/[^ ]*/cfg/[^ ]*\\.conf"],
                   check=False)

    # 4. Single ss sweep: SIGKILL anything still listening on one of our ports.
    try:
        out = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True).stdout
    except Exception:
        out = ""
    for line in out.splitlines():
        if "pid=" not in line:
            continue
        for port in range(PORT_MIN, PORT_MAX + 1):
            if f":{port} " in line:
                pid = line.split("pid=")[1].split(",")[0]
                subprocess.run(["kill", "-9", pid], check=False)
                break

    # 5. Wait for the front doors to clear (≤10s) so a relaunch starts clean.
    for _ in range(40):
        if not any(port_open(p) for p in MANAGER_PORTS):
            return
        time.sleep(0.25)


def wait_ready(timeout=120):
    """Block until the mesh has actually formed: probe each topology's manager
    with a locate for a known path until it redirects (returns a data port).

    This replaces a blind settle-sleep — a redirect proves the manager is up
    AND that topology's data node(s) have registered and answer selection.
    Returns (ready_count, total, still_pending_probes)."""
    pending = list(READY_PROBES)
    total = len(pending)
    deadline = time.time() + timeout
    while pending:
        still = []
        for mgr, path in pending:
            try:
                rc, stdout, _ = xrdfs_locate(mgr, path, timeout=10, retries=1)
                if rc != 0 or located_port(stdout) is None:
                    still.append((mgr, path))
            except Exception:
                still.append((mgr, path))
        pending = still
        if not pending or time.time() >= deadline:
            break
        time.sleep(2)
    return total - len(pending), total, pending
