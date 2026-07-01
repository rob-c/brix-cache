"""
Hybrid two-tier cross-backend mesh — daemon lifecycle + config builders.

Topology (see docs/superpowers/specs/2026-06-27-hybrid-mesh-design.md):

      client
        | root://
        v
    a) nginx redirector (tier-1 CMS manager)
        |  registers: b, c
    +---+----+
    v        v
 b) nginx  c) xrootd PSS         (read/write-through proxies, origin = g)
    proxy    proxy
    +---+----+
        |  origin
        v
    g) xrootd redirector (tier-2 cmsd manager)
        |  registers: d, e, f
   +----+----+
   v    v    v
 d)xrd e)xrd f)nginx              (data servers)

This module owns ONLY the hybrid mesh; it reuses cms_mesh_lib's Mesh launcher,
nginx config builders, binary discovery and process helpers so there is a single
source of truth for "how a stock xrootd/cmsd or nginx node is started".

Everything binds 127.0.0.1.  Ports come from PORTS below (a fresh, dedicated band
disjoint from the managed fleet, the cluster-* instances and the cms-mesh band).
Nothing here is pytest-specific, so hybrid_mesh_servers.py can run it standalone.
"""

import glob
import os
import shutil
import signal
import subprocess
import time

import cms_mesh_lib as cml
from cms_mesh_lib import (
    CMSD_BIN,
    HOST,
    Mesh,
    XROOTD_BIN,
    have_binaries,
    port_open,
    read_text,
    wait_port,
)
from settings import BIND_HOST

# --------------------------------------------------------------------------- #
# Scratch root + dedicated port band
# --------------------------------------------------------------------------- #

# A dedicated working tree, separate from the cms-mesh tree, so the two meshes
# never share a config/data/run directory or a teardown sweep.
MESH_DIR = os.environ.get("HYBRID_MESH_DIR", "/tmp/xrd-test/hybrid-mesh")

# Dedicated, env-overridable band 11300-11330 (verified disjoint from the fleet
# 11094-11123, cluster-* ~11160-12600, and the cms-mesh 21610-21749 bands).
# Each node carries root:// on its *_data port; HTTP-family protocols (S3 ingest,
# WebDAV) ride dedicated *_s3 / *_http ports added below.
def _p(env, default):
    return int(os.environ.get(env) or default)


PORTS = {
    # a) nginx tier-1 redirector (CMS manager): client front door + CMS server
    "a_data":  _p("HYBRID_REDIR_PORT",         11300),
    "a_cms":   _p("HYBRID_REDIR_CMS_PORT",     11301),
    "a_s3":    _p("HYBRID_REDIR_S3_PORT",      11320),  # S3 front door
    "a_dav":   _p("HYBRID_REDIR_DAV_PORT",     11321),  # WebDAV front door
    # b) nginx read/write-through proxy (registers with a, origin = g)
    "b_data":  _p("HYBRID_PROXY_NGINX_PORT",   11302),
    "b_s3":    _p("HYBRID_PROXY_NGINX_S3_PORT", 11322),  # S3 relay -> f
    "b_dav":   _p("HYBRID_PROXY_NGINX_DAV_PORT", 11323),  # WebDAV proxy -> g
    # c) xrootd PSS read/write-through proxy (registers with a, origin = g)
    "c_data":  _p("HYBRID_PROXY_XRD_PORT",     11304),
    "c_cms":   _p("HYBRID_PROXY_XRD_CMS_PORT", 11305),
    "c_http":  _p("HYBRID_PROXY_XRD_HTTP_PORT", 11327),  # XrdHttp on the proxy
    # g) xrootd tier-2 redirector (cmsd manager)
    "g_data":  _p("HYBRID_TIER2_REDIR_PORT",   11310),
    "g_cms":   _p("HYBRID_TIER2_REDIR_CMS_PORT", 11311),
    "g_http":  _p("HYBRID_TIER2_REDIR_HTTP_PORT", 11324),  # XrdHttp redirector
    # d) xrootd data server
    "d_data":  _p("HYBRID_DS_D_PORT",          11312),
    "d_cms":   _p("HYBRID_DS_D_CMS_PORT",      11313),
    "d_http":  _p("HYBRID_DS_D_HTTP_PORT",     11325),
    # e) xrootd data server
    "e_data":  _p("HYBRID_DS_E_PORT",          11314),
    "e_cms":   _p("HYBRID_DS_E_CMS_PORT",      11315),
    "e_http":  _p("HYBRID_DS_E_HTTP_PORT",     11326),
    # f) nginx data server
    "f_data":  _p("HYBRID_DS_F_PORT",          11316),
    "f_s3":    _p("HYBRID_DS_F_S3_PORT",       11318),  # S3 origin over the store
    "f_dav":   _p("HYBRID_DS_F_DAV_PORT",      11319),  # WebDAV origin (https, direct)
    # Plain-HTTP WebDAV origin used as the single-port handoff target: the stock
    # XrdHttp redirector g redirects HTTP to the data port over http:// (stock
    # multiplexes plain XrdHttp there), so f's data port splices to THIS plain
    # listener (not the https one) — see xrootd_http_handoff.
    "f_dav_http": _p("HYBRID_DS_F_DAV_HTTP_PORT", 11328),
}

PORT_MIN, PORT_MAX = 11300, 11330

# S3 bucket name == the cluster export's leaf, so an S3 object `key` lands at
# <store>/mesh/key — i.e. the SAME on-disk path as root:// "/mesh/key".  That is
# what makes an S3 PUT visible to root:// and WebDAV through the cluster.
S3_BUCKET = "mesh"

# The two redirector front doors clients ever connect to.
MANAGER_PORTS = [PORTS["a_data"], PORTS["g_data"]]

# Exported logical namespace shared by every data server in the cluster.
EXPORT = "/mesh"

# Readiness probes: a locate that redirects proves the registrations below it
# formed.  Probing the tier-2 redirector g for a seeded path proves d/e/f
# registered with g; probing tier-1 a proves b/c registered with a AND that the
# proxy->g->DS chain resolves end-to-end.
SEED_REL = "fileD.txt"            # seeded directly on every DS (see build_all)
READY_PROBES = [
    (PORTS["g_data"], f"{EXPORT}/{SEED_REL}"),
    (PORTS["a_data"], f"{EXPORT}/{SEED_REL}"),
]


# --------------------------------------------------------------------------- #
# Stock-xrootd config builder (manager / server / pss-proxy), launched via Mesh
# --------------------------------------------------------------------------- #


def _xrd_cfg(role, data_port, cms_port, manager, run, export,
             localroot=None, pss_origin=None, http_port=None,
             cert=None, key=None):
    """Assemble a stock xrootd/cmsd config.

    role        "manager" (redirector g) or "server" (d/e or pss-proxy c)
    manager     "host:port" of the cmsd this node registers WITH
    pss_origin  when set, this is a proxy: load libXrdPss and forward to origin
    """
    lines = [
        f"all.role {role}",
        f"all.manager {manager}",
        f"xrd.port {data_port}",
        "if exec cmsd",
        f"  xrd.port {cms_port}",
        "fi",
    ]
    if localroot is not None:
        lines.append(f"oss.localroot {localroot}")
    if pss_origin is not None:
        # Clustered proxy server: byte I/O is satisfied by forwarding to the
        # tier-2 redirector, which in turn locates the holding data server.
        lines.append("ofs.osslib libXrdPss-5.so")
        lines.append(f"pss.origin {pss_origin}")
        lines.append("pss.setopt DebugLevel 1")
    lines.append(f"all.export {export} r/w")
    lines.append(f"all.adminpath {run}")
    lines.append(f"all.pidpath {run}")
    if role in ("manager", "supervisor"):
        lines.append("cms.delay startup 5 servers 1 lookup 2")
    if http_port is not None:
        lines += [
            "if exec xrootd",
            f"  xrd.protocol http:{http_port} libXrdHttp-5.so",
            f"  http.cert {cert}",
            f"  http.key {key}",
            "  http.selfhttps2http no",
            "fi",
        ]
    lines.append("cms.trace all")
    return "\n".join(lines) + "\n"


def launch_xrootd(m, label, cfg_text):
    """Write cfg_text and launch cmsd + xrootd for a stock node under mesh m.

    Mirrors Mesh.xrootd_node's launch discipline (clear stale admin/pid dir,
    detach via -b/start_new_session, cwd under the mesh tree) but takes a fully
    custom config so we can express manager / pss-proxy / http roles."""
    run = os.path.join(m.root, "run", label)
    shutil.rmtree(run, ignore_errors=True)
    os.makedirs(run, exist_ok=True)
    cfg = m.write(f"{label}.cfg", cfg_text)
    clog = os.path.join(m.root, "logs", f"{label}-cmsd.log")
    xlog = os.path.join(m.root, "logs", f"{label}-xrootd.log")
    subprocess.run([CMSD_BIN, "-c", cfg, "-n", label, "-l", clog, "-b"],
                   check=False, start_new_session=True, cwd=m.root)
    subprocess.run([XROOTD_BIN, "-c", cfg, "-n", label, "-l", xlog, "-b"],
                   check=False, start_new_session=True, cwd=m.root)


# --------------------------------------------------------------------------- #
# nginx proxy-that-registers config builder (node b)
# --------------------------------------------------------------------------- #


def _http_temp(tmpbase):
    """nginx http{} temp-path directives, pinned under the node's run tree so a
    PUT body / proxied response never lands in the compiled-in prefix."""
    return (
        f"    client_body_temp_path {tmpbase}/cbt;\n"
        f"    proxy_temp_path {tmpbase}/pt;\n"
        f"    fastcgi_temp_path {tmpbase}/ft;\n"
        f"    uwsgi_temp_path {tmpbase}/ut;\n"
        f"    scgi_temp_path {tmpbase}/st;\n"
        "    client_max_body_size 1g;\n"
    )


def _s3_forward_server(listen_port, upstream_port):
    """An http server that transparently forwards S3 REST to an upstream nginx S3
    handler (S3 is plain HTTP, so a reverse proxy carries it unchanged).  Request
    buffering off so PUT bodies stream straight through the ingest chain."""
    return (
        f"    server {{\n"
        f"        listen {BIND_HOST}:{listen_port};\n"
        f"        location / {{\n"
        f"            proxy_pass http://{BIND_HOST}:{upstream_port};\n"
        f"            proxy_http_version 1.1;\n"
        f"            proxy_request_buffering off;\n"
        f"        }}\n"
        f"    }}\n"
    )


def _s3_origin_server(listen_port, root, bucket):
    """An http server that IS the S3 object store over `root`, bucket==`bucket`.
    Objects land at <root>/<bucket>/<key>, which equals the root:// path
    /<bucket>/<key> — the cross-protocol ingest hinge."""
    return (
        f"    server {{\n"
        f"        listen {BIND_HOST}:{listen_port};\n"
        f"        location / {{\n"
        f"            xrootd_s3 on; xrootd_s3_storage_backend posix:{root};\n"
        f"            xrootd_s3_bucket {bucket}; xrootd_s3_allow_write on;\n"
        f"            xrootd_s3_max_keys 1000;\n"
        f"        }}\n"
        f"    }}\n"
    )


def _webdav_origin_server(listen_port, root, cert, key, tls=True):
    """A server that IS the WebDAV store over `root` (davs GET /mesh/K ->
    <root>/mesh/K).  tls=True -> https (direct davs); tls=False -> plain http
    (the single-port handoff target, reached via the stock redirector's http://
    data-port redirect)."""
    ssl_kw = " ssl" if tls else ""
    ssl_lines = (
        f"        ssl_certificate {cert};\n        ssl_certificate_key {key};\n"
        if tls else ""
    )
    return (
        f"    server {{\n"
        f"        listen {BIND_HOST}:{listen_port}{ssl_kw};\n"
        f"        server_name localhost;\n"
        f"{ssl_lines}"
        f"        location / {{\n"
        f"            xrootd_webdav on; xrootd_webdav_storage_backend posix:{root};\n"
        f"            xrootd_webdav_auth none; xrootd_webdav_allow_write on;\n"
        f"        }}\n"
        f"    }}\n"
    )


def _webdav_proxy_server(listen_port, root, upstream_url, cert, key):
    """A direct https WebDAV data server.

    NOTE: the WebDAV reverse-proxy directives (xrootd_webdav_proxy /
    _upstream) that once relayed the upstream's 307 to the holding data server
    were retired in the legacy-proxy cleanup; only xrootd_webdav_proxy_certs
    (GSI client auth) survives. This node now serves its own export directly
    (no relay hop) — `upstream_url` is retained in the signature for callers
    but is no longer wired into a proxy."""
    _ = upstream_url  # relay hop retired — kept for call-site compatibility
    return (
        f"    server {{\n"
        f"        listen {BIND_HOST}:{listen_port} ssl;\n"
        f"        server_name localhost;\n"
        f"        ssl_certificate {cert};\n        ssl_certificate_key {key};\n"
        f"        location / {{\n"
        f"            xrootd_webdav on; xrootd_webdav_storage_backend posix:{root};\n"
        f"            xrootd_webdav_auth none; xrootd_webdav_allow_write on;\n"
        f"        }}\n"
        f"    }}\n"
    )


def cfg_node_a(data_port, cms_port, s3_front_upstream, tmpbase, cert, key,
               dav_upstream_port):
    """Tier-1 nginx redirector: root:// CMS manager (stream) + S3 front door that
    forwards into the ingest chain (http)."""
    return (
        "worker_processes 1;\nerror_log {ERR} debug;\npid {PID};\n"
        "events { worker_connections 128; }\n"
        "stream {\n"
        f"    server {{ listen {BIND_HOST}:{data_port}; xrootd on; xrootd_auth none;"
        f" xrootd_manager_mode on; }}\n"
        f"    server {{ listen {BIND_HOST}:{cms_port}; xrootd_cms_server on; }}\n"
        "}\n"
        "http {\n    access_log off;\n"
        + _http_temp(tmpbase)
        + _s3_forward_server(PORTS["a_s3"], s3_front_upstream)
        + _webdav_proxy_server(PORTS["a_dav"], tmpbase,
                               f"https://{BIND_HOST}:{dav_upstream_port}",
                               cert, key)
        + "}\n"
    )


def cfg_node_b(data_port, cms_mgr, paths, upstream, s3_upstream, tmpbase,
               cert, key, dav_upstream_port):
    """Tier-1 nginx proxy: root:// read/write-through proxy that registers with a
    (stream) + S3 relay forwarding to f's S3 origin (http)."""
    return (
        "worker_processes 1;\nerror_log {ERR} debug;\npid {PID};\n"
        "events { worker_connections 128; }\n"
        "stream {\n"
        f"    server {{\n"
        f"        listen {BIND_HOST}:{data_port};\n"
        f"        xrootd on; xrootd_auth none;\n"
        f"        xrootd_allow_write on;\n"
        f"        xrootd_tap_proxy on;\n"
        f"        xrootd_tap_proxy_upstream {BIND_HOST}:{upstream};\n"
        f"        xrootd_tap_proxy_auth anonymous;\n"
        f"        xrootd_cms_manager {cms_mgr}; xrootd_cms_paths {paths};\n"
        f"        xrootd_cms_interval 2; xrootd_listen_port {data_port};\n"
        f"    }}\n"
        "}\n"
        "http {\n    access_log off;\n"
        + _http_temp(tmpbase)
        + _s3_forward_server(PORTS["b_s3"], s3_upstream)
        + _webdav_proxy_server(PORTS["b_dav"], tmpbase,
                               f"https://{BIND_HOST}:{dav_upstream_port}",
                               cert, key)
        + "}\n"
    )


def cfg_node_f(data_port, root, cms_mgr, paths, tmpbase, cert, key):
    """Tier-2 nginx data server: root:// data node registering with g (stream) +
    S3 object-store origin over the same store (http).

    The S3 handler strips the (single) bucket name and writes keys directly under
    xrootd_s3_root, so the S3 root is <store>/mesh (== the root:// export's
    on-disk dir): an S3 PUT of key K -> <store>/mesh/K == root:// "/mesh/K"."""
    s3_root = root + EXPORT       # EXPORT begins with '/', root has no trailing /
    return (
        "worker_processes 1;\nerror_log {ERR} debug;\npid {PID};\n"
        "events { worker_connections 128; }\n"
        "stream {\n"
        f"    server {{\n"
        f"        listen {BIND_HOST}:{data_port};\n"
        f"        xrootd on; xrootd_storage_backend posix:{root}; xrootd_auth none;\n"
        f"        xrootd_allow_write on;\n"
        f"        xrootd_cms_manager {cms_mgr}; xrootd_cms_paths {paths};\n"
        f"        xrootd_cms_interval 2; xrootd_listen_port {data_port};\n"
        # Single-port mux: an HTTP client the stock redirector sent to this
        # data port is spliced to the local plain-http WebDAV listener.
        f"        xrootd_http_handoff {BIND_HOST}:{PORTS['f_dav_http']};\n"
        f"    }}\n"
        "}\n"
        "http {\n    access_log off;\n"
        + _http_temp(tmpbase)
        + _s3_origin_server(PORTS["f_s3"], s3_root, S3_BUCKET)
        + _webdav_origin_server(PORTS["f_dav"], root, cert, key, tls=True)
        + _webdav_origin_server(PORTS["f_dav_http"], root, cert, key, tls=False)
        + "}\n"
    )


# --------------------------------------------------------------------------- #
# Bring the whole mesh up
# --------------------------------------------------------------------------- #


def _tmp(m, label):
    """Create and return an http temp base for an nginx node under its run tree."""
    base = os.path.join(m.root, "run", f"{label}-tmp")
    os.makedirs(base, exist_ok=True)
    return base


def build_all():
    """Provision and launch all 7 nodes of the hybrid mesh under MESH_DIR."""
    p = PORTS
    # The reused Mesh launcher roots everything at cms_mesh_lib.MESH_DIR; repoint
    # it at our dedicated hybrid tree so the two meshes never share a config/data/
    # run directory (and our stop_all sweep, which targets MESH_DIR, matches).
    cml.MESH_DIR = MESH_DIR
    m = Mesh("hybrid")          # single mesh tree; all nodes live under it

    g_cms = f"{HOST}:{p['g_cms']}"
    a_cms = f"{HOST}:{p['a_cms']}"
    # One self-signed cert shared by every WebDAV/XrdHttp listener in the mesh.
    cert, key = cml.gen_cert(m.root)

    # --- Tier 2: storage cluster behind a stock xrootd redirector ---------- #
    # g) redirector (cmsd manager) — no storage of its own; XrdHttp redirector
    # for the WebDAV plane (307s a davs GET to the holding data server).
    g_run_root = m.datadir("g")
    launch_xrootd(m, "g", _xrd_cfg(
        "manager", p["g_data"], p["g_cms"], g_cms,
        os.path.join(m.root, "run", "g"), EXPORT, localroot=g_run_root,
        http_port=p["g_http"], cert=cert, key=key))

    # d, e) stock xrootd data servers; each seeded with the same logical path
    # under its OWN store so the cluster has the file regardless of which DS g
    # picks (and so direct-addressed equivalence reads compare backends later).
    # Each also serves WebDAV directly via XrdHttp.
    for label in ("d", "e"):
        dd = m.datadir(label)
        m.seed(dd, f"{EXPORT}/{SEED_REL}", cml.content(f"hybrid-{label}"))
        launch_xrootd(m, label, _xrd_cfg(
            "server", p[f"{label}_data"], p[f"{label}_cms"], g_cms,
            os.path.join(m.root, "run", label), EXPORT, localroot=dd,
            http_port=p[f"{label}_http"], cert=cert, key=key))

    # f) nginx data server registering with g; also the S3 object-store origin
    # (an S3 PUT here lands in the cluster namespace, see _s3_origin_server) and
    # a WebDAV origin over the same store.
    df = m.datadir("f")
    m.seed(df, f"{EXPORT}/{SEED_REL}", cml.content("hybrid-f"))
    m.nginx("f", cfg_node_f(p["f_data"], df, g_cms, EXPORT, _tmp(m, "f"),
                            cert, key))

    # --- Tier 1: nginx redirector fronting the two proxies ----------------- #
    # a) nginx CMS manager (root:// client front door) + S3 front door + WebDAV
    # front door (proxies the davs plane down the b -> g chain).
    m.nginx("a", cfg_node_a(p["a_data"], p["a_cms"], p["b_s3"], _tmp(m, "a"),
                            cert, key, p["b_dav"]))

    # b) nginx read/write-through proxy: root:// registers with a (origin g) +
    # S3 relay + WebDAV proxy to g's XrdHttp redirector.
    m.nginx("b", cfg_node_b(p["b_data"], a_cms, EXPORT, p["g_data"],
                            p["f_s3"], _tmp(m, "b"), cert, key, p["g_http"]))

    # c) stock xrootd PSS proxy: registers with a, origin = g; XrdHttp too.
    launch_xrootd(m, "c", _xrd_cfg(
        "server", p["c_data"], p["c_cms"], a_cms,
        os.path.join(m.root, "run", "c"), EXPORT,
        pss_origin=f"{HOST}:{p['g_data']}",
        http_port=p["c_http"], cert=cert, key=key))


# --------------------------------------------------------------------------- #
# Teardown + readiness (mirrors cms_mesh_lib patterns, scoped to MESH_DIR)
# --------------------------------------------------------------------------- #


def _kill_pidfile_group(pidfile):
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
    """Tear down every hybrid-mesh daemon (nginx groups, xrootd/cmsd by cfg,
    then a port sweep), then wait for the front doors to clear."""
    for pidfile in glob.glob(os.path.join(MESH_DIR, "*", "run", "*.pid")):
        _kill_pidfile_group(pidfile)
    subprocess.run(["pkill", "-9", "-f", f"{MESH_DIR}/[^ ]*/cfg/"], check=False)

    try:
        out = subprocess.run(["ss", "-tlnp"], capture_output=True,
                             text=True).stdout
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

    for _ in range(40):
        if not any(port_open(p) for p in MANAGER_PORTS):
            return
        time.sleep(0.25)


def wait_ready(timeout=120):
    """Block until both redirector tiers resolve a seeded path (locate redirect).

    Returns (ready_count, total, still_pending_probes)."""
    pending = list(READY_PROBES)
    total = len(pending)
    deadline = time.time() + timeout
    while pending:
        still = []
        for mgr, path in pending:
            # A still-forming cluster answers locate with kXR_wait, so the probe
            # can hit its own timeout — that just means "not ready yet", not an
            # error, so swallow it and re-probe next round.
            try:
                rc, stdout, _ = cml.xrdfs_locate(mgr, path, timeout=3, retries=1)
                ok = rc == 0 and bool(cml.located_port(stdout))
            except Exception:
                ok = False
            if not ok:
                still.append((mgr, path))
        pending = still
        if not pending or time.time() >= deadline:
            break
        time.sleep(0.4)
    return total - len(pending), total, pending
