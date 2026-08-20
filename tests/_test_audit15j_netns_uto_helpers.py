"""Tranche 10 — a netns harness for `brix_cms_server_tcp_user_timeout`.

The audit (`testsuite-combinatorial-coverage-audit-2026-08-15.md`, appendix +
tranche-9 note) carried this directive as its last residual, deferred because
"the accept leg needs unacked outbound data against a peer whose kernel has
stopped answering, and no local userspace peer can be made to stop answering (a
closed socket RSTs; a SIGSTOPped process still ACKs from kernel context)".

That is true of a *userspace* peer and false of the machine.  A peer whose
kernel stops answering is one packet-filter rule away: drop everything addressed
to the node's socket and its kernel never sees — so never ACKs — anything the
manager sends.  `CAP_NET_ADMIN` inside a private network namespace is enough to
install that rule unprivileged, exactly as `_perf_netem_helpers` synthesizes a
BDP link unprivileged.

Two differences from that harness, both simplifications:

  * **`lo` is enough — no veth, no second namespace.**  The perf harness needs
    two namespaces because two veth ends in one namespace bypass the egress
    *qdisc* (the kernel short-circuits local delivery), and `tc netem` is a
    qdisc.  Netfilter is not a qdisc: its hooks run on loopback delivery, so an
    `nft` DROP on `lo` really does black-hole the packet.  Verified: with
    `TCP_USER_TIMEOUT` 2 s the sender aborts `ETIMEDOUT` at ~2.5 s, and without
    it the same connection is still healthy at 20 s.
  * **`nft`, not `iptables`.**  On this kernel `iptables` refuses inside the
    namespace (no legacy tables); `nft` works.

`podman unshare unshare -n -m` is kept verbatim from the perf harness, for the
reason documented there: brix force-drops a root-capable worker to `nobody`
(uid 65534), and a bare `unshare -Ur` maps only one uid, so that `setuid` fails
and the worker exits fatal.  `podman unshare` installs the operator's full
rootless `/etc/subuid` map.  The manager's export therefore lives under `/tmp`
(world-traversable) rather than under a pytest `tmp_path`, whose `basetemp`
ancestors are 0700 and cannot be traversed by the dropped worker.

Isolation of the knob.  The accept leg has a *userspace* competitor that reaps
the very same peer: the post-login idle watchdog, whose source comment
(`server_recv_frame.c:217-222`) says it exists to reap "a black-holed node the
ping send cannot detect".  Every arm therefore pins
`brix_cms_server_idle_timeout` far beyond the observation window, so within that
window the kernel is the only thing that can end the session — the same
isolation the client-leg tests get from holding `brix_cms_send_timeout` at 30 s.
`brix_cms_server_interval 1` keeps a ping in flight each second so there is
always unacked outbound data for the option to act on.

Ports are fixed and unledgered on purpose: a private netns has its own port
space, so these listeners cannot collide with the fleet or with a concurrent
session.  Nothing here is a lifecycle-registered instance.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

# The wire layout of a CMS node LOGIN is owned by the conformance helpers; this
# harness only needs a node that reaches the logged-in state.
from _test_cms_wire_pup_conformance_helpers import (  # noqa: E402
    CMS_MODE_SERVER,
    CMS_RR_LOGIN,
    _build_frame,
    _login_payload_with_mode,
)

# Exit code a child uses to signal "prerequisite absent" (mirrors autotools).
SKIP_EXIT = 77

# Verbatim from _perf_netem_helpers: podman's full rootless uid map (so the
# worker can drop to nobody) wrapping a nested netns that keeps CAP_NET_ADMIN.
_NS_LAUNCH = ["podman", "unshare", "unshare", "-n", "-m"]

# The manager binds the PRIVATE namespace's own loopback, which is a different
# interface from the host's; settings.HOST names the fleet host and does not
# exist in there.
MGR_HOST = "127.0.0.1"  # net-literal-allow: loopback inside the private netns
# Inside the private netns nothing else exists, so a fixed base needs no ledger.
PORT_BASE = 41200
# The node's advertised data port — never dialled, it only has to parse.
NODE_DPORT = 31999


# --------------------------------------------------------------------------- #
# Availability probe (parent side) — never raises.
# --------------------------------------------------------------------------- #

def netns_uto_available():
    """Return (ok: bool, reason: str).

    ok only when the whole chain works: `podman unshare` (the rootless subuid
    map), a nested `unshare -n` that still owns CAP_NET_ADMIN, a loopback that
    can be brought up, and an `nft` filter chain to hang a DROP rule on.
    """
    probe = (
        "ip link set lo up && "
        "nft add table inet brixuto && "
        "nft add chain inet brixuto input "
        "'{ type filter hook input priority 0; }' && "
        "echo OK"
    )
    try:
        # Generous: the probe itself is ~3s idle, but podman's first launch on a
        # box already running a full suite has been measured past 60s, and a
        # timeout here reads as "unavailable" and silently skips the gate.
        r = subprocess.run(_NS_LAUNCH + ["bash", "-c", probe],
                           capture_output=True, text=True, timeout=180)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, f"podman/unshare/nft unavailable: {e}"
    if r.returncode == 0 and "OK" in r.stdout:
        return True, "podman-unshare + nested netns with nft available"
    return False, (r.stderr or r.stdout or "namespace launch failed").strip()


# --------------------------------------------------------------------------- #
# nginx config — self-contained: no lifecycle registry exists in the namespace.
# --------------------------------------------------------------------------- #

_CONF = """\
worker_processes 1;
error_log {log}/error.log info;
pid {log}/nginx.pid;
daemon on;
events {{ worker_connections 128; }}
stream {{
    server {{
        listen {host}:{port};
        brix_root on; brix_storage_backend posix:{data}; brix_auth none;
        brix_manager_mode on;
        brix_cms_server on;
        brix_cms_server_interval 1;
        brix_cms_server_login_timeout 30s;
        brix_cms_server_idle_timeout {idle};
{uto}    }}
}}
"""


def write_conf(workdir, name, port, dataroot, uto, idle="600s"):
    """Render one arm's manager config; `uto` is a value like "2s" or None."""
    body = _CONF.format(
        log=os.path.join(workdir, name), data=dataroot, host=MGR_HOST,
        port=port, idle=idle,
        uto=("" if uto is None
             else f"        brix_cms_server_tcp_user_timeout {uto};\n"))
    path = os.path.join(workdir, f"{name}.conf")
    with open(path, "w") as fh:
        fh.write(body)
    return path


# --------------------------------------------------------------------------- #
# Parent — stage files, run the child in the namespace, read the result back.
# --------------------------------------------------------------------------- #

def run_uto_matrix(nginx_bin, workdir, arms):
    """Run every arm in one private namespace and return a result dict.

    `arms` is a list of {"name", "uto", "drop", "watch_s"}.  Returns
    ``{"available": False, "reason": ...}`` when the namespace stack is absent.
    """
    ok, reason = netns_uto_available()
    if not ok:
        return {"available": False, "reason": reason}
    if not os.access(nginx_bin, os.X_OK):
        return {"available": False, "reason": f"nginx not executable: {nginx_bin}"}

    os.chmod(workdir, 0o755)
    # The worker drops to nobody and must traverse every ancestor of the export;
    # a pytest tmp_path sits under 0700 basetemp ancestors it cannot enter.
    dataroot = tempfile.mkdtemp(prefix="brixuto-", dir="/tmp")
    os.chmod(dataroot, 0o755)
    try:
        spec = {"nginx_bin": nginx_bin, "workdir": workdir,
                "dataroot": dataroot, "arms": []}
        for i, arm in enumerate(arms):
            port = PORT_BASE + i
            os.makedirs(os.path.join(workdir, arm["name"]), exist_ok=True)
            os.chmod(os.path.join(workdir, arm["name"]), 0o755)
            spec["arms"].append({
                **arm,
                "port": port,
                "conf": write_conf(workdir, arm["name"], port, dataroot,
                                   arm["uto"]),
            })
        spec_path = os.path.join(workdir, "spec.json")
        with open(spec_path, "w") as fh:
            json.dump(spec, fh)

        env = dict(os.environ)
        # podman unshare may sanitize env — the child needs tests/ importable
        # for the CMS wire helpers.
        env["PYTHONPATH"] = os.pathsep.join(
            [os.path.dirname(os.path.abspath(__file__)),
             env.get("PYTHONPATH", "")]).strip(os.pathsep)

        budget = 90 + sum(a["watch_s"] for a in arms)
        try:
            r = subprocess.run(
                _NS_LAUNCH + [sys.executable, os.path.abspath(__file__),
                              "--inside", spec_path],
                capture_output=True, text=True, env=env, timeout=budget)
        except subprocess.TimeoutExpired:
            return {"available": False, "reason": f"child exceeded {budget}s"}
        if r.returncode == SKIP_EXIT:
            return {"available": False,
                    "reason": r.stderr.strip() or "child skip"}
        if r.returncode != 0:
            return {"available": False,
                    "reason": f"child exit {r.returncode}: "
                              f"{(r.stderr or r.stdout).strip()[-500:]}"}
        with open(os.path.join(workdir, "result.json")) as fh:
            return json.load(fh)
    finally:
        shutil.rmtree(dataroot, ignore_errors=True)


# --------------------------------------------------------------------------- #
# Child — inside the namespace, owns CAP_NET_ADMIN over a private netns.
# --------------------------------------------------------------------------- #

def _sh(*argv, check=True):
    r = subprocess.run(argv, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(argv)} -> {r.returncode}: {r.stderr}")
    return r


def _nft(rule):
    _sh("nft", *rule.split())


def _boot(nginx_bin, workdir, conf, port):
    """Start the manager and wait until it accepts; returns nothing."""
    _sh(nginx_bin, "-t", "-p", workdir, "-c", conf)
    _sh(nginx_bin, "-p", workdir, "-c", conf)
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            socket.create_connection((MGR_HOST, port), timeout=2).close()
            return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"manager never accepted on {port}")


def _read(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        return b""


def _run_arm(spec, arm):
    """Boot one manager, log a node in, optionally silence the node's kernel,
    and watch for the manager to tear the session down."""
    workdir, log = spec["workdir"], os.path.join(spec["workdir"], arm["name"],
                                                 "error.log")
    _boot(spec["nginx_bin"], workdir, arm["conf"], arm["port"])
    node = None
    try:
        node = socket.create_connection((MGR_HOST, arm["port"]), timeout=10)
        node.sendall(_build_frame(
            0, CMS_RR_LOGIN, 0,
            _login_payload_with_mode(NODE_DPORT, CMS_MODE_SERVER)))
        node_port = node.getsockname()[1]

        # Wait for registration — the ping timer arms with it, and only a
        # registered session produces the disconnect NOTICE under test.
        registered, deadline = False, time.time() + 10
        while time.time() < deadline:
            if b"CMS server: registered" in _read(log):
                registered = True
                break
            time.sleep(0.2)
        pre = len(_read(log))

        if arm["drop"]:
            _nft(f"add rule inet brixuto input tcp dport {node_port} drop")

        torn, t0 = None, time.time()
        while time.time() - t0 < arm["watch_s"]:
            new = _read(log)[pre:]
            if b"disconnected (blacklisted" in new or b"ping to" in new:
                torn = round(time.time() - t0, 2)
                break
            time.sleep(0.2)
        tail = _read(log)[pre:].decode("utf8", "replace")
        return {"name": arm["name"], "registered": registered,
                "node_port": node_port, "torn_down_after": torn,
                "etimedout": "Connection timed out" in tail,
                "watch_s": arm["watch_s"], "log_tail": tail[-2000:]}
    finally:
        if node is not None:
            node.close()
        if arm["drop"]:
            # Flush rather than track handles: each arm owns the whole chain.
            _sh("nft", "flush", "chain", "inet", "brixuto", "input",
                check=False)
        _sh(spec["nginx_bin"], "-p", workdir, "-c", arm["conf"], "-s", "stop",
            check=False)


def _inside(spec_path):
    with open(spec_path) as fh:
        spec = json.load(fh)
    try:
        _sh("ip", "link", "set", "lo", "up")
        _nft("add table inet brixuto")
        _nft("add chain inet brixuto input "
             "{ type filter hook input priority 0 ; }")
    except (RuntimeError, FileNotFoundError) as e:
        sys.stderr.write(f"namespace setup failed: {e}\n")
        return SKIP_EXIT

    arms = {}
    for arm in spec["arms"]:
        arms[arm["name"]] = _run_arm(spec, arm)
    with open(os.path.join(spec["workdir"], "result.json"), "w") as fh:
        json.dump({"available": True, "arms": arms}, fh)
    return 0


def _main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "--inside":
        return _inside(argv[1])

    default_arms = [
        {"name": "kernel", "uto": "2s", "drop": True, "watch_s": 15.0},
        {"name": "control", "uto": None, "drop": True, "watch_s": 12.0},
        {"name": "healthy", "uto": "2s", "drop": False, "watch_s": 8.0},
    ]
    nginx_bin = os.environ.get("TEST_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
    with tempfile.TemporaryDirectory(prefix="uto-netns-", dir="/tmp") as wd:
        res = run_uto_matrix(nginx_bin, wd, default_arms)
    if not res.get("available"):
        print(f"UNAVAILABLE: {res.get('reason')}")
        return SKIP_EXIT
    for name, arm in res["arms"].items():
        print(f"{name:8s} registered={arm['registered']} "
              f"torn_down_after={arm['torn_down_after']} "
              f"etimedout={arm['etimedout']}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
