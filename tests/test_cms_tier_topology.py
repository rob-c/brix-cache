"""
CMS multi-tier topology suite — assert a whole cmsd cluster wires itself up in
the correct shape and that the logs prove it.

This mirrors the "Live 4-tier cluster on xrd1":

    mgr (manager)
      └─ sub1 (sub-manager)                -> mgr
           ├─ leafA (client / data leaf)   -> sub1
           ├─ leafB (client / data leaf)   -> sub1
           └─ sub2 (sub-manager)           -> sub1
                └─ leafC (client)          -> sub2

The whole tree is stood up as ONE brix nginx master hosting all six nodes as
separate stream server blocks on 127.0.0.1 (each a distinct cmsd node identity
via ``brix_listen_port``); they connect to each other purely over the CMS wire
protocol on loopback.  No certificates or data backends are needed:

  * managers / sub-managers use ``brix_cms_server on`` (the block's handler),
  * leaf clients get a trivial ``return "";`` stream handler and only register
    upward via ``brix_cms_manager`` — role auto-derives to ``client``.

The assertions read exclusively from the error log the auto-role feature emits:

  * ``brix: cmsd role: this node is a {manager|sub-manager|client} ...``
      one proof line per node (worker-0 only).
  * ``brix: cmsd-action op=register peer=<child> dir=in ... server: <parent>``
      the parent side of every tree edge (who registered into whom).
  * ``brix: cmsd-action op=login peer=<parent> dir=out ... detail=...``
      the child side of every edge (who each node registers UP to, and whether
      brix treated it as a sub-manager (Manager bit) or a leaf/client).

So the test verifies (a) every node derived the RIGHT role, (b) every edge of
the tree is present and points the RIGHT way, (c) the single-connection gate
holds (all control-plane actions come from one worker even with N workers), and
(d) the cluster settles with no collisions/retries.

Run:
    PYTHONPATH=tests pytest tests/test_cms_tier_topology.py -v

The nginx used must carry the CMS auto-role feature: the test auto-selects one
by launching a one-node manager and confirming it emits a 'cmsd role:' line —
it prefers $TEST_NGINX_BIN, then a locally-built dynamic module (via system
nginx), then a statically-linked objs/nginx (as built fresh in CI).  It skips
cleanly if no feature-capable nginx is found.
"""

import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

# Fixture setup launches nginx + polls for cluster settle; that easily exceeds
# the repo-default 30s per-test timeout (which is charged to the first test that
# triggers the module-scoped fixture).  Give the whole module generous headroom.
pytestmark = pytest.mark.timeout(120)

try:
    from settings import NGINX_BIN as _SETTINGS_NGINX_BIN
except Exception:  # pragma: no cover - settings import is best-effort
    _SETTINGS_NGINX_BIN = None

HOST = "127.0.0.1"
REPO = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------- #
# Topology declaration — the single source of truth for the expected tree.
# `upstream` names another node (its cmsd parent) or None for the root manager.
# --------------------------------------------------------------------------- #
NODES = [
    {"name": "mgr",   "role": "manager",     "cms_server": True,  "upstream": None},
    {"name": "sub1",  "role": "sub-manager", "cms_server": True,  "upstream": "mgr"},
    {"name": "leafA", "role": "client",      "cms_server": False, "upstream": "sub1"},
    {"name": "leafB", "role": "client",      "cms_server": False, "upstream": "sub1"},
    {"name": "sub2",  "role": "sub-manager", "cms_server": True,  "upstream": "sub1"},
    {"name": "leafC", "role": "client",      "cms_server": False, "upstream": "sub2"},
]


# --------------------------------------------------------------------------- #
# Locate a brix-capable nginx (static objs/nginx, or system nginx + the dynamic
# module) so the test runs both in CI and on a deployed host.
# --------------------------------------------------------------------------- #
def _module_prelude():
    """load_module lines for the dynamic brix build, or '' if not found."""
    so_candidates = [
        REPO / "build" / "modules" / "ngx_stream_brix_module.so",
        Path("/usr/lib64/nginx/modules/ngx_stream_brix_module.so"),
        Path("/usr/share/nginx/modules/ngx_stream_brix_module.so"),
    ]
    for so in so_candidates:
        if so.exists():
            stream_so = so.with_name("ngx_stream_module.so")
            lines = []
            if stream_so.exists():
                lines.append(f'load_module "{stream_so}";')
            lines.append(f'load_module "{so}";')
            return "\n".join(lines) + "\n"
    return ""


def _probe_feature(nginx_bin, prelude, workdir, idx):
    """True only if (nginx_bin + prelude) not merely parses brix_cms_server but
    actually emits the auto-role proof line — i.e. it carries THIS feature.

    A binary can understand the directives yet predate the auto-role work (a
    stale statically-linked objs/nginx), so we launch a one-node manager and
    confirm 'cmsd role:' shows up before trusting it."""
    pdir = workdir / f"probe{idx}"
    pdir.mkdir(exist_ok=True)
    port = _free_ports(1)[0]
    log = pdir / "error.log"
    cfg = pdir / "probe.conf"
    cfg.write_text(
        f"{prelude}"
        f"error_log {log} notice;\n"
        f"pid {pdir/'nginx.pid'};\n"
        "events { worker_connections 64; }\n"
        f"stream {{ server {{ listen {HOST}:{port}; brix_cms_server on; "
        f"brix_listen_port {port}; }} }}\n"
    )
    if subprocess.run([nginx_bin, "-t", "-c", str(cfg)],
                      capture_output=True, text=True).returncode != 0:
        return False
    if subprocess.run([nginx_bin, "-c", str(cfg)],
                      capture_output=True, text=True).returncode != 0:
        return False
    try:
        deadline = time.time() + 6
        while time.time() < deadline:
            if log.exists() and "cmsd role:" in log.read_text(errors="replace"):
                return True
            time.sleep(0.25)
        return False
    finally:
        subprocess.run([nginx_bin, "-c", str(cfg), "-s", "stop"],
                       capture_output=True, text=True)


def _resolve_nginx(workdir):
    """Return (nginx_bin, module_prelude) for an nginx that carries the auto-role
    feature, or pytest.skip if none does.

    Priority: an explicit TEST_NGINX_BIN, then the locally-built dynamic module
    (freshest brix on a deployed host), then a statically-linked objs/nginx
    (freshest in CI, where the module is compiled in and no prelude is needed)."""
    prelude = _module_prelude()
    env_bin = os.environ.get("TEST_NGINX_BIN")
    candidates = []
    if env_bin:
        candidates += [(env_bin, ""), (env_bin, prelude)]
    if prelude:  # a locally-built .so exists → try it via system nginx first
        for b in (shutil.which("nginx"), "/usr/sbin/nginx"):
            if b:
                candidates.append((b, prelude))
    for b in (_SETTINGS_NGINX_BIN, shutil.which("nginx"), "/usr/sbin/nginx"):
        if b:
            candidates.append((b, ""))

    seen, idx = set(), 0
    for b, pre in candidates:
        key = (b, pre)
        if key in seen:
            continue
        seen.add(key)
        if not (os.path.isfile(b) and os.access(b, os.X_OK)):
            continue
        idx += 1
        if _probe_feature(b, pre, workdir, idx):
            return b, pre
    pytest.skip("no auto-role-capable nginx found (set TEST_NGINX_BIN to a brix "
                "nginx built with the CMS auto-role feature, or build the module "
                "so build/modules/ngx_stream_brix_module.so exists)")


def _free_ports(n):
    """Grab n distinct free loopback TCP ports (closed just before launch)."""
    socks, ports = [], []
    for _ in range(n):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, 0))
        socks.append(s)
        ports.append(s.getsockname()[1])
    for s in socks:
        s.close()
    return ports


# --------------------------------------------------------------------------- #
# Config rendering
# --------------------------------------------------------------------------- #
def _render_conf(nodes_by_name, prelude, workdir):
    blocks = []
    for node in NODES:
        port = nodes_by_name[node["name"]]["port"]
        up = node["upstream"]
        lines = [f"    server {{  # {node['name']} ({node['role']})",
                 f"        listen {HOST}:{port};",
                 f"        brix_listen_port {port};"]
        if node["cms_server"]:
            lines.append("        brix_cms_server on;")
        else:
            # leaf client needs *some* stream handler; it only registers upward.
            lines.append('        return "";')
        if up is not None:
            up_port = nodes_by_name[up]["port"]
            lines.append(f"        brix_cms_manager {HOST}:{up_port};")
        lines.append("        brix_cms_paths /;")
        lines.append("        brix_cms_interval 2;   # fast heartbeat for the test")
        lines.append("    }")
        blocks.append("\n".join(lines))

    conf = (
        f"{prelude}"
        "worker_processes 3;   # >1 so the worker-0 single-connection gate is exercised\n"
        f"error_log {workdir/'error.log'} notice;\n"
        f"pid {workdir/'nginx.pid'};\n"
        "events { worker_connections 256; }\n"
        "stream {\n" + "\n".join(blocks) + "\n}\n"
    )
    path = workdir / "tier.conf"
    path.write_text(conf)
    return path


# --------------------------------------------------------------------------- #
# Log parsing
# --------------------------------------------------------------------------- #
_ROLE_RE = re.compile(
    r"cmsd role: this node is a (?P<role>manager|sub-manager|client) "
    r"\(listen :(?P<port>\d+), upstream_manager=(?P<up>\S+),"
)
_REGISTER_RE = re.compile(
    r"cmsd-action op=register peer=(?P<peer>[\d.]+:\d+) dir=in\b"
    r".*?server: (?P<server>[\d.]+:\d+)"
)
_LOGIN_RE = re.compile(
    r"cmsd-action op=login peer=(?P<peer>[\d.]+:\d+) dir=out\b"
    r".*?detail=(?P<detail>.+?)(?:, client:|$)"
)
_PID_RE = re.compile(r"\[notice\] (\d+)#(\d+):.*cmsd-action")
_OUT_PID_RE = re.compile(r"\[notice\] (\d+)#(\d+):.*cmsd-action op=\S+ .*dir=out")
_LOGIN_OUT_RE = re.compile(r"cmsd-action op=login peer=[\d.]+:\d+ dir=out")


def _parse(text):
    roles = {}                       # port -> (role, upstream_str)
    edges_in = set()                 # (child_port, parent_port) from register
    logins = set()                   # (parent_port, detail) from op=login dir=out
    action_pids = set()              # worker PIDs of ALL cmsd-action lines
    out_pids = set()                 # worker PIDs of dir=out (outbound) actions
    login_out = 0                    # count of op=login dir=out lines
    for line in text.splitlines():
        m = _ROLE_RE.search(line)
        if m:
            roles[int(m["port"])] = (m["role"], m["up"])
        m = _REGISTER_RE.search(line)
        if m:
            child = int(m["peer"].split(":")[1])
            parent = int(m["server"].split(":")[1])
            edges_in.add((child, parent))
        m = _LOGIN_RE.search(line)
        if m:
            # peer is the PARENT the child dialed; the detail is the child's
            # self-classification (sub-manager vs leaf/client).  The login line
            # does NOT name the child (multiple children share one parent) — the
            # per-child edge is pinned by the register lines instead.
            parent_port = int(m["peer"].split(":")[1])
            logins.add((parent_port, m["detail"].strip()))
        m = _PID_RE.search(line)
        if m:
            action_pids.add(m.group(1))
        m = _OUT_PID_RE.search(line)
        if m:
            out_pids.add(m.group(1))
        if _LOGIN_OUT_RE.search(line):
            login_out += 1
    return roles, edges_in, logins, action_pids, out_pids, login_out


# --------------------------------------------------------------------------- #
# Fixture: bring the whole tree up once, wait for it to settle, tear down.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def tier(tmp_path_factory):
    workdir = tmp_path_factory.mktemp("cms-tier")
    nginx_bin, prelude = _resolve_nginx(workdir)

    ports = _free_ports(len(NODES))
    nodes_by_name = {n["name"]: {**n, "port": p} for n, p in zip(NODES, ports)}
    conf = _render_conf(nodes_by_name, prelude, workdir)

    check = subprocess.run([nginx_bin, "-t", "-c", str(conf)],
                           capture_output=True, text=True)
    assert check.returncode == 0, f"nginx -t failed:\n{check.stderr}"

    start = subprocess.run([nginx_bin, "-c", str(conf)],
                           capture_output=True, text=True)
    assert start.returncode == 0, f"nginx start failed:\n{start.stderr}"

    logpath = workdir / "error.log"
    expected_roles = len(NODES)
    expected_edges = sum(1 for n in NODES if n["upstream"] is not None)   # 5

    # Poll until the tree has fully registered (all role lines + all edges), or
    # time out.  Register edges appear together with the child's upward login, so
    # roles-complete + edges-complete implies the whole tree has wired up.
    deadline = time.time() + 25
    parsed = ({}, set(), set(), set(), set(), 0)
    try:
        while time.time() < deadline:
            text = logpath.read_text(errors="replace") if logpath.exists() else ""
            parsed = _parse(text)
            roles, edges_in = parsed[0], parsed[1]
            if (len(roles) >= expected_roles
                    and len(edges_in) >= expected_edges):
                break
            time.sleep(0.5)
        text = logpath.read_text(errors="replace")
        yield {
            "nodes": nodes_by_name,
            "log": text,
            "parsed": _parse(text),
            "workdir": workdir,
        }
    finally:
        subprocess.run([nginx_bin, "-c", str(conf), "-s", "stop"],
                       capture_output=True, text=True)
        # belt-and-braces: kill the master if the pidfile survived
        pidfile = workdir / "nginx.pid"
        if pidfile.exists():
            try:
                os.kill(int(pidfile.read_text().strip()), 15)
            except (ProcessLookupError, ValueError, OSError):
                pass


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #
def test_every_node_derived_its_expected_role(tier):
    """Each node logs exactly the role the topology says it should have."""
    roles = tier["parsed"][0]
    nodes = tier["nodes"]
    problems = []
    for node in NODES:
        port = nodes[node["name"]]["port"]
        got = roles.get(port)
        if got is None:
            problems.append(f"{node['name']} (:{port}) — no 'cmsd role:' line")
        elif got[0] != node["role"]:
            problems.append(
                f"{node['name']} (:{port}) — role {got[0]!r}, expected "
                f"{node['role']!r}")
    assert not problems, "role derivation mismatches:\n  " + "\n  ".join(problems)


def test_role_upstream_field_matches_topology(tier):
    """The role line's upstream_manager= names the correct parent (or none)."""
    roles = tier["parsed"][0]
    nodes = tier["nodes"]
    problems = []
    for node in NODES:
        port = nodes[node["name"]]["port"]
        _role, up = roles.get(port, (None, None))
        if node["upstream"] is None:
            expect = "none"
        else:
            expect = f"{HOST}:{nodes[node['upstream']]['port']}"
        if up != expect:
            problems.append(
                f"{node['name']} (:{port}) — upstream_manager={up!r}, "
                f"expected {expect!r}")
    assert not problems, "upstream mismatches:\n  " + "\n  ".join(problems)


def test_every_tree_edge_registered_into_correct_parent(tier):
    """For each child->parent edge, the PARENT logged an op=register for it."""
    edges_in = tier["parsed"][1]
    nodes = tier["nodes"]
    missing = []
    for node in NODES:
        if node["upstream"] is None:
            continue
        child = nodes[node["name"]]["port"]
        parent = nodes[node["upstream"]]["port"]
        if (child, parent) not in edges_in:
            missing.append(
                f"{node['name']} (:{child}) -> {node['upstream']} (:{parent})")
    assert not missing, (
        "tree edges the parent never logged as registered:\n  "
        + "\n  ".join(missing)
        + f"\n\nobserved register edges (child->parent): {sorted(edges_in)}")


def test_no_unexpected_registration_edges(tier):
    """The parent side registered ONLY the edges the topology declares."""
    edges_in = tier["parsed"][1]
    nodes = tier["nodes"]
    expected = set()
    for node in NODES:
        if node["upstream"] is not None:
            expected.add((nodes[node["name"]]["port"],
                          nodes[node["upstream"]]["port"]))
    unexpected = edges_in - expected
    assert not unexpected, (
        f"unexpected register edges (child->parent ports): {sorted(unexpected)}")


def test_each_child_logs_upward_login_with_correct_role_detail(tier):
    """Every non-root node logged op=login dir=out to its parent, and the detail
    marks it a sub-manager (Manager bit) vs a leaf/client.

    A login line names the PARENT dialed, not the child, so children that share
    a parent collapse to one (parent, detail) pair.  We therefore assert, for
    each parent, that a login line carrying the RIGHT self-classification exists
    for every distinct child role beneath it.  (Which specific child made each
    edge is pinned separately by the register lines.)"""
    logins = tier["parsed"][2]
    nodes = tier["nodes"]
    substr = {"sub-manager": "sub-manager", "client": "leaf/client"}
    problems = []
    for node in NODES:
        if node["upstream"] is None:
            continue
        parent = nodes[node["upstream"]]["port"]
        want = substr[node["role"]]
        if not any(pp == parent and want in detail for pp, detail in logins):
            problems.append(
                f"{node['name']} ({node['role']}) — no op=login dir=out to "
                f"parent :{parent} carrying {want!r}")
    assert not problems, (
        "upward-login problems:\n  " + "\n  ".join(problems)
        + f"\n\nobserved (parent_port, detail) logins: {sorted(logins)}")


def test_upstream_client_is_gated_to_a_single_worker(tier):
    """The worker-0 single-connection gate: every OUTBOUND cms-action (the
    upstream login/load) comes from one worker PID, and each node opens exactly
    ONE upstream login — not one per worker — even with multiple workers.

    (Inbound 'dir=in' registrations are handled by whichever worker accept()s
    the connection, so those legitimately spread across workers; only the
    outbound client side is gated.)"""
    _roles, _edges, _logins, action_pids, out_pids, login_out = tier["parsed"]
    assert action_pids, "no cmsd-action lines were logged at all"
    assert out_pids, "no outbound (dir=out) cms-action lines were logged"
    assert len(out_pids) == 1, (
        f"outbound cms-action lines came from {len(out_pids)} worker PIDs "
        f"{sorted(out_pids)} — the upstream CMS client is not gated to one worker")

    expected_logins = sum(1 for n in NODES if n["upstream"] is not None)  # 5
    assert login_out == expected_logins, (
        f"expected exactly {expected_logins} upstream logins (one per non-root "
        f"node), saw {login_out} — without the worker gate each of N workers "
        "would open its own upstream connection")


def test_cluster_settles_without_collisions_or_retries(tier):
    """A correctly-wired single-connection tree settles cleanly: no duplicate
    logins, no unreachable-manager retries, no heartbeat failures."""
    log = tier["log"]
    bad_markers = [
        "already logged in",
        "cannot reach cluster manager",
        "CMS load heartbeat failed",
        "CMS write handler: send_load failed",
    ]
    hits = [m for m in bad_markers if m in log]
    assert not hits, f"instability markers found in the log: {hits}"
