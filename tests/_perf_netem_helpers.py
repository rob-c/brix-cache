"""Phase-33 P0/P3-B3 — unprivileged high-BDP A/B throughput harness (netem).

The magnitude of the P3-B3 socket-buffer knob (`brix_socket_sndbuf` /
`brix_socket_rcvbuf`) was documented (phase-33 § P0/P3-B3, phase-88 audit § 4)
as blocked on a physical high-BDP perf host, on the stated premise that *"a
userspace relay can't synthesize a server-socket BDP — only a real link or root
`netem` can"*.

That premise is refuted here: a user+network namespace (`unshare -Ur -n`) grants
`CAP_NET_ADMIN` **inside** the namespace, so a fully unprivileged process can

  1. build a `veth` pair (server end + client end),
  2. attach `tc netem delay <d> rate <r>` to **both** ends to synthesize an
     arbitrary bandwidth-delay product (BDP = rate × 2·delay), and
  3. run the existing A/B measurer (`_perf_ab_helpers.measure_read_throughput`)
     across that link — server one end, client the other —

with no root, no dedicated NIC, and no VM.  This is a genuine server-*socket*
BDP (the server's `SO_SNDBUF` must hold a full BDP of unacknowledged data to
keep the pipe full), which is exactly the regime the P3-B3 knob targets and the
regime loopback cannot reach.  Measured result on the dev box, autotuning ceiling
pinned (128 KiB) below the BDP: at a 30 ms synthesized RTT / 400 mbit the
window-limited baseline runs ~4 MiB/s (≈ 128 KiB ÷ 30 ms, exactly as the ceiling
predicts) while the pinned `brix_socket_sndbuf` fills the pipe at ~33 MiB/s — a
**~8× gain**; at 40 ms / 500 mbit it is baseline ~3 → tuned ~36 MiB/s (~12×).
The magnitude the P0 perf host was for, measured unprivileged.

Why `podman unshare`, not bare `unshare -Ur`.  brix hard-refuses to serve from a
root-capable worker (`brix_worker_user`: *"pre-auth parsing must never run as a
root-capable identity"*) — a root master force-drops the worker to `nobody`
(uid 65534).  A bare `unshare -Ur` maps only a single uid, so that drop
(`setuid(65534)`) fails and the worker exits fatal.  `podman unshare` installs
the operator's full rootless `/etc/subuid` map (uid 0 **and** the 65534 the
worker drops to are both mapped), and a *nested* `unshare -n` under it still owns
`CAP_NET_ADMIN` for `ip`/`tc` — so the launcher is `podman unshare unshare -n`.
The served data dir is made world-traversable (0755 / files 0644) so the
dropped-to-`nobody` worker can read it.

Isolation of the knob under test.  `tc netem` alone caps only bandwidth+latency;
whether a *larger* server send buffer helps then depends on the kernel's send
autotuning ceiling (`net.ipv4.tcp_wmem[2]`, which **is** per-netns writable) and
on `net.core.wmem_max` (global, not namespaced — it clamps an explicit
`SO_SNDBUF`).  To model a host whose autotuning ceiling sits *below* the BDP —
precisely when an explicit `SO_SNDBUF` earns its keep — the child pins a low
`tcp_wmem` max while leaving `tcp_rmem` generous (so the client's receive window
is never the bottleneck).  The baseline server then autotunes to that low
ceiling and starves the BDP pipe; the tuned server's pinned `brix_socket_sndbuf`
(clamped only by the global `wmem_max`) escapes the ceiling and fills it.  The
delta is the knob's magnitude — the number the perf host was needed for.

Two netns, not one.  Two veth ends in the *same* netns do NOT traverse netem:
the kernel short-circuits traffic between two local addresses on one host via
the loopback delivery path, bypassing the veth egress qdisc (verified — ping
stays ~0.2 ms with a 20 ms qdisc attached).  So the server end stays in the
child netns while the client end is moved into a second netns pinned by a
`sleep` holder; packets between them now genuinely egress the netem device
(ping ≈ 2·delay).  The measurer runs in the client netns via `nsenter`.

Structure.  The parent process (`run_ab_over_bdp`) prepares a work directory (a
seeded, world-readable data file + two nginx configs, baseline and tuned) and
re-execs *this module* under `podman unshare unshare -n -m --inside <spec.json>`.
The child, owning the private network namespaces, straddles the netem'd veth,
boots both servers, drives the measurer (nsenter'd into the client netns) against
each, proves the synthesized RTT with `ping`, and writes the result JSON back.
Everything is unprivileged and self-skips (exit 77 / `available=False`) when
podman / namespaces / `tc` are unavailable — so it is CI-safe like every other
perf leg.
"""
import json
import os
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time

# Deterministic link endpoints inside the private namespace.  A /30 is plenty
# for the two veth ends; the addresses never escape the namespace.
_NET = "10.77.0"
SRV_IP = f"{_NET}.1"
CLI_IP = f"{_NET}.2"
_SRV_DEV = "s0"
_CLI_DEV = "c0"

# Exit code a child uses to signal "prerequisite absent" (mirrors autotools).
SKIP_EXIT = 77


# --------------------------------------------------------------------------- #
# Availability probe (parent side) — never raises.
# --------------------------------------------------------------------------- #

# The launcher: a nested net namespace inside podman's full rootless uid map.
# See the module docstring for why the bare `unshare -Ur` single-uid map cannot
# host a brix worker (which force-drops to nobody/65534).
_NS_LAUNCH = ["podman", "unshare", "unshare", "-n", "-m"]


def netns_bdp_available():
    """Return (ok: bool, reason: str).

    ok is True only when the full launcher chain works: `podman unshare` (the
    rootless subuid map that lets a brix worker drop to `nobody`) wrapping a
    nested `unshare -n` that still owns CAP_NET_ADMIN to build a veth pair AND
    attach `tc netem`.  Cheap: one throwaway namespace that builds + tears down
    a netem'd veth pair.
    """
    probe = (
        "ip link add p0 type veth peer name p1 && "
        "tc qdisc add dev p0 root netem delay 1ms && "
        "echo OK"
    )
    try:
        r = subprocess.run(
            _NS_LAUNCH + ["bash", "-c", probe],
            capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, f"podman/unshare/tc unavailable: {e}"
    if r.returncode == 0 and "OK" in r.stdout:
        return True, "podman-unshare + nested netns with tc netem available"
    return False, (r.stderr or r.stdout or "namespace launch failed").strip()


# --------------------------------------------------------------------------- #
# nginx config (self-contained — no lifecycle registry inside the namespace).
# --------------------------------------------------------------------------- #

_CONF = """\
daemon on;
worker_processes 1;
error_log {workdir}/{name}-error.log info;
pid {workdir}/{name}.pid;
events {{ worker_connections 256; }}
stream {{
    server {{
        listen {ip}:{port};
        brix_root on;
        brix_storage_backend posix:{dataroot};
        brix_socket_sndbuf {sndbuf};
        brix_socket_rcvbuf {rcvbuf};
    }}
}}
"""


def _write_conf(workdir, name, port, dataroot, sndbuf, rcvbuf):
    conf = os.path.join(workdir, f"{name}.conf")
    with open(conf, "w") as fh:
        fh.write(_CONF.format(workdir=workdir, name=name, ip=SRV_IP, port=port,
                              dataroot=dataroot, sndbuf=sndbuf, rcvbuf=rcvbuf))
    return conf


# --------------------------------------------------------------------------- #
# Parent entrypoint.
# --------------------------------------------------------------------------- #

def run_ab_over_bdp(nginx_bin, workdir, size_mib=8, delay_ms=15,
                    rate_mbit=400, sndbuf="4m", rcvbuf="4m", runs=3,
                    wmem_cap=131072):
    """Boot baseline+tuned root:// servers over a synthesized BDP link and A/B them.

    Returns a result dict (see the child's JSON below), or one with
    ``{"available": False, "reason": ...}`` when namespaces/tc are absent.  All
    work happens in the child namespace; the parent only stages files and reads
    the result back.
    """
    ok, reason = netns_bdp_available()
    if not ok:
        return {"available": False, "reason": reason}

    os.chmod(workdir, 0o755)
    size = size_mib * 1024 * 1024

    # The worker force-drops to `nobody`, so it must *traverse* every ancestor of
    # the export.  The caller's workdir (e.g. pytest's tmp_path) sits under 0700
    # ancestors (the basetemp chain) the dropped worker cannot enter, even with
    # the leaf chmod'd — so the served tree lives under /tmp instead, whose only
    # ancestor is /tmp itself (1777, world-traversable).  Configs/spec stay in
    # workdir: only the root-mapped nginx *master* reads those, and root can
    # traverse 0700 dirs it owns.
    dataroot = tempfile.mkdtemp(prefix="brixdata-", dir="/tmp")
    bigbin = os.path.join(dataroot, "big.bin")
    # Deterministic filler — only the byte count matters to the read path.
    with open(bigbin, "wb") as fh:
        fh.write(b"\x5a" * size)
    os.chmod(dataroot, 0o755)
    os.chmod(bigbin, 0o644)

    try:
        port_base = 41000
        base_conf = _write_conf(workdir, "base", port_base, dataroot, "0", "0")
        tuned_conf = _write_conf(workdir, "tuned", port_base + 1, dataroot,
                                 sndbuf, rcvbuf)

        spec = {
            "nginx_bin": nginx_bin,
            "workdir": workdir,
            "size": size,
            "delay_ms": delay_ms,
            "rate_mbit": rate_mbit,
            "runs": runs,
            "wmem_cap": wmem_cap,
            "base": {"conf": base_conf, "port": port_base},
            "tuned": {"conf": tuned_conf, "port": port_base + 1},
        }
        spec_path = os.path.join(workdir, "spec.json")
        with open(spec_path, "w") as fh:
            json.dump(spec, fh)

        env = dict(os.environ)
        # The child imports _perf_ab_helpers / settings — keep tests/ importable.
        # (podman unshare may sanitize env, so the child self-inserts its dir too.)
        env["PYTHONPATH"] = os.pathsep.join(
            [os.path.dirname(os.path.abspath(__file__)),
             env.get("PYTHONPATH", "")]).strip(os.pathsep)

        r = subprocess.run(
            _NS_LAUNCH + [sys.executable, os.path.abspath(__file__),
                          "--inside", spec_path],
            capture_output=True, text=True, env=env, timeout=300)
        if r.returncode == SKIP_EXIT:
            return {"available": False,
                    "reason": r.stderr.strip() or "child skip"}
        if r.returncode != 0:
            return {"available": False,
                    "reason": f"child exit {r.returncode}: {r.stderr.strip()}"}

        result_path = os.path.join(workdir, "result.json")
        with open(result_path) as fh:
            return json.load(fh)
    finally:
        shutil.rmtree(dataroot, ignore_errors=True)


# --------------------------------------------------------------------------- #
# Child (inside the namespace) — owns CAP_NET_ADMIN over the private netns.
# --------------------------------------------------------------------------- #

def _sh(cmd, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} -> {r.returncode}: {r.stderr}")
    return r


def _tune_netns(delay_ms, rate_mbit, wmem_cap, dev, nsenter=None):
    """Apply netem + the tcp autotuning window to one netns.

    `nsenter` is a prefix list (`["nsenter","-t",pid,"-n"]`) to run inside the
    peer netns, or None for the current one.
    """
    pre = nsenter or []
    _sh(pre + ["ip", "link", "set", dev, "up"])
    _sh(pre + ["ip", "link", "set", "lo", "up"])
    # netem on the egress of each end → RTT ≈ 2·delay; rate caps bandwidth; a
    # large limit keeps the qdisc from dropping a full BDP of in-flight packets.
    _sh(pre + ["tc", "qdisc", "add", "dev", dev, "root", "netem",
               "delay", f"{delay_ms}ms", "rate", f"{rate_mbit}mbit",
               "limit", "200000"])
    # Model an autotuning ceiling below the BDP so the explicit SO_SNDBUF knob
    # is the variable under test; keep the receive side generous.
    _sh(pre + ["sysctl", "-qw",
               f"net.ipv4.tcp_wmem=4096 16384 {wmem_cap}",
               "net.ipv4.tcp_rmem=4096 262144 16777216"], check=False)


def _setup_link(delay_ms, rate_mbit, wmem_cap):
    """Straddle a netem'd veth pair across two netns and return the client pid.

    Two ends in ONE netns will NOT traverse netem: the kernel short-circuits
    traffic between two local addresses on the same host via the loopback
    delivery path, bypassing the veth egress qdisc entirely (verified: ping
    stays ~0.2 ms).  The server end therefore stays in this (child) netns while
    the client end is moved into a second netns held open by a `sleep` process;
    packets between them now genuinely egress the netem device (ping ≈ 2·delay).
    """
    # A holder process pins the client netns; its pid names /proc/<pid>/ns/net.
    holder = subprocess.Popen(["unshare", "-n", "sleep", "3600"])
    # Wait for the holder's netns to exist before moving the veth into it.
    deadline = time.time() + 5
    while time.time() < deadline and not os.path.exists(
            f"/proc/{holder.pid}/ns/net"):
        time.sleep(0.02)
    ns = ["nsenter", "-t", str(holder.pid), "-n"]

    _sh(["ip", "link", "set", "lo", "up"])
    _sh(["ip", "link", "add", _SRV_DEV, "type", "veth",
         "peer", "name", _CLI_DEV])
    _sh(["ip", "link", "set", _CLI_DEV, "netns", str(holder.pid)])
    _sh(["ip", "addr", "add", f"{SRV_IP}/24", "dev", _SRV_DEV])
    _sh(ns + ["ip", "addr", "add", f"{CLI_IP}/24", "dev", _CLI_DEV])
    _tune_netns(delay_ms, rate_mbit, wmem_cap, _SRV_DEV)
    _tune_netns(delay_ms, rate_mbit, wmem_cap, _CLI_DEV, nsenter=ns)
    return holder.pid


def _boot_nginx(nginx_bin, conf, workdir):
    r = subprocess.run([nginx_bin, "-p", workdir + "/", "-c", conf],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"nginx boot failed: {r.stderr or r.stdout}")


def _stop_nginx(workdir, tag):
    """SIGTERM a booted `daemon on` nginx via its pid file, then reap.

    nginx double-forks and reparents to init, so it outlives this child unless
    explicitly stopped — leaking the master *and* the netns it pins.  The pid
    file is ``{workdir}/{tag}.pid`` (see `_CONF`)."""
    pidfile = os.path.join(workdir, f"{tag}.pid")
    try:
        with open(pidfile) as fh:
            pid = int(fh.read().strip())
    except (OSError, ValueError):
        return
    for sig in (15, 9):
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            return
        # Give the master a moment to exit gracefully before escalating.
        for _ in range(30):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.05)


def _measure_in_client(holder_pid, port, size, runs):
    """Run the A/B measurer from inside the client netns (via nsenter → this
    module's `--measure` mode) and return its result dict."""
    ns = ["nsenter", "-t", str(holder_pid), "-n"]
    r = subprocess.run(
        ns + [sys.executable, os.path.abspath(__file__), "--measure",
              SRV_IP, str(port), str(size), str(runs)],
        capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        raise RuntimeError(f"measure failed: {r.stderr or r.stdout}")
    return json.loads(r.stdout.strip().splitlines()[-1])


def _rtt_ms_client(holder_pid):
    """Parse the average RTT (ms) of `ping` from the client netns — proves the
    synthesized delay is actually on the wire, not just configured."""
    ns = ["nsenter", "-t", str(holder_pid), "-n"]
    r = subprocess.run(ns + ["ping", "-c", "3", "-W", "2", SRV_IP],
                       capture_output=True, text=True, timeout=15)
    for line in r.stdout.splitlines():
        if "rtt min/avg/max" in line or "round-trip min/avg/max" in line:
            return float(line.split("=")[1].strip().split("/")[1])
    return 0.0


def _measure_mode(argv):
    """`--measure <ip> <port> <size> <runs>` — run inside the client netns."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from _perf_ab_helpers import measure_read_throughput
    ip, port, size, runs = argv[0], int(argv[1]), int(argv[2]), int(argv[3])
    res = measure_read_throughput(ip, port, b"/big.bin", size, runs=runs,
                                  warmup=1)
    print(json.dumps(res))
    return 0


def _inside(spec_path):
    with open(spec_path) as fh:
        spec = json.load(fh)
    workdir = spec["workdir"]
    try:
        holder_pid = _setup_link(spec["delay_ms"], spec["rate_mbit"],
                                 spec["wmem_cap"])
    except (RuntimeError, OSError) as e:
        sys.stderr.write(str(e))
        return SKIP_EXIT

    # Ground-truth the autotuning ceiling actually in force in the server netns
    # (the sysctl write is best-effort; a silent miss lets the baseline autotune
    # free and collapses the A/B contrast).
    _wmem = subprocess.run(["sysctl", "-n", "net.ipv4.tcp_wmem"],
                           capture_output=True, text=True)
    wmem_effective = _wmem.stdout.strip()

    size = spec["size"]
    results = {}
    booted = []
    try:
        for tag in ("base", "tuned"):
            _boot_nginx(spec["nginx_bin"], spec[tag]["conf"], workdir)
            booted.append(tag)
            results[tag] = _measure_in_client(holder_pid, spec[tag]["port"],
                                              size, spec["runs"])
        rtt = _rtt_ms_client(holder_pid)
    finally:
        # Stop every server booted this run (daemon-on nginx outlives us and
        # would pin its netns), then release the netns holder (a bare `sleep`).
        for tag in booted:
            _stop_nginx(workdir, tag)
        try:
            os.kill(holder_pid, 15)
        except ProcessLookupError:
            pass
    bdp = int(spec["rate_mbit"] * 1e6 / 8 * (2 * spec["delay_ms"] / 1000.0))
    # Compare on the MEDIAN sample, not best-of-N.  netem's rate limiter queues
    # data, so a window-limited baseline occasionally drains one run as a
    # near-line-rate burst; best-of-N (min transfer time) latches onto exactly
    # that transient and understates the A/B contrast.  The median tracks the
    # sustained rate — the quantity the socket-buffer knob actually moves — and
    # is robust to a single burst outlier in either direction.
    base_med = statistics.median(results["base"]["samples_mib_s"])
    tuned_med = statistics.median(results["tuned"]["samples_mib_s"])
    out = {
        "available": True,
        "rtt_ms": rtt,
        "bdp_bytes": bdp,
        "delay_ms": spec["delay_ms"],
        "rate_mbit": spec["rate_mbit"],
        "size": size,
        "wmem_effective": wmem_effective,
        "baseline": results["base"],
        "tuned": results["tuned"],
        "baseline_median_mib_s": base_med,
        "tuned_median_mib_s": tuned_med,
        "ratio": (tuned_med / base_med) if base_med else 0.0,
    }
    with open(os.path.join(workdir, "result.json"), "w") as fh:
        json.dump(out, fh, indent=2)
    return 0


# --------------------------------------------------------------------------- #
# CLI — parent (default) prints a human summary; `--inside` is the child.
# --------------------------------------------------------------------------- #

def _main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "--inside":
        return _inside(argv[1])
    if argv and argv[0] == "--measure":
        return _measure_mode(argv[1:])

    import argparse

    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--nginx-bin",
                    default=os.environ.get("TEST_NGINX_BIN",
                                           "/tmp/nginx-1.28.3/objs/nginx"))
    ap.add_argument("--size-mib", type=int, default=32)
    ap.add_argument("--delay-ms", type=int, default=20)
    ap.add_argument("--rate-mbit", type=int, default=500)
    ap.add_argument("--sndbuf", default="4m")
    ap.add_argument("--rcvbuf", default="4m")
    ap.add_argument("--runs", type=int, default=4)
    ap.add_argument("--json", help="write the full result dict here")
    args = ap.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="perf-netem-") as wd:
        res = run_ab_over_bdp(
            args.nginx_bin, wd, size_mib=args.size_mib, delay_ms=args.delay_ms,
            rate_mbit=args.rate_mbit, sndbuf=args.sndbuf, rcvbuf=args.rcvbuf,
            runs=args.runs)
    if not res.get("available"):
        print(f"UNAVAILABLE: {res.get('reason')}")
        return SKIP_EXIT
    print(f"BDP link: RTT={res['rtt_ms']:.1f} ms  rate={res['rate_mbit']} mbit "
          f"BDP={res['bdp_bytes'] / 1024:.0f} KiB")
    print(f"baseline (autotuned): {res['baseline']['best_mib_s']:.0f} MiB/s")
    print(f"tuned    (SO_SNDBUF): {res['tuned']['best_mib_s']:.0f} MiB/s")
    print(f"ratio tuned/baseline: {res['ratio']:.2f}x")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(res, fh, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(_main())
