#!/usr/bin/env python3
"""
run_http_reorder.py — HTTP GET under packet reordering: repo xrdcp + curl, against
the nginx module (WebDAV/HTTP) and the official xrootd (XrdHttp).

WHY: the over-HTTP analog of run_xrdcp_loss.py.  NOTE: the official `xrdcp` CLI
     CANNOT copy http:// URLs ("http file protocol is not supported" — the
     XrdClHttp plugin enables the XrdCl API, not the xrdcp front-end; verified on
     /usr/bin/xrdcp and the docs build).  So the official-client-over-http leg is
     impossible; this uses the repo `xrdcp` (which has native http transport) and
     `curl` (the neutral standard http client) so the two SERVER stacks can still
     be compared head-to-head under reorder.

Clients:  repo = ./client/bin/xrdcp http://   ;   curl = /usr/bin/curl
Servers:  nginx  = this repo's module, http{} location brix_webdav (anonymous)
          xrootd = official daemon, xrd.protocol XrdHttp (plain http, anonymous)

client -> fault_proxy(reorder pct/ms) -> {nginx|xrootd}.  Byte-exact (md5) checked.

Run (from repo root):
  PYTHONPATH=tests python3 tests/resilience/run_http_reorder.py \
      --levels 0,0.0001,0.001,0.01,0.1,1.0 --reorder-ms 50 --size-mib 64 --reps 8
"""
import argparse
import hashlib
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from server_launcher import LifecycleHarness
from server_registry import NginxInstanceSpec

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import servers  # noqa: E402

REPO_XRDCP = os.path.join(servers.CLIENT_BIN, "xrdcp")
CURL = shutil.which("curl") or "/usr/bin/curl"
XRDHTTP_LIB = "/usr/lib64/libXrdHttp-5.so"
FILE_NAME = "h.bin"


def md5_file(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_port(port, proc, tries=80):
    for _ in range(tries):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
            return True
        except OSError:
            if proc.poll() is not None:
                return False
            time.sleep(0.1)
    return False


def start_nginx_http(prefix, data):
    """Stand up the WebDAV/HTTP reorder-harness nginx through the registry
    harness, serving the pre-seeded ``data`` tree.  Returns ``(port, harness)``;
    the caller closes the harness to tear it down."""
    harness = LifecycleHarness()
    endpoint = harness.start(NginxInstanceSpec(
        name="resil-http-reorder",
        template="nginx_resilience_http_reorder.conf",
        protocol="http",
        readiness="tcp",
        data_root=data,
    ))
    return endpoint.port, harness


def start_brix_http(prefix, data):
    for sub in ("admin", "run", "logs"):
        os.makedirs(os.path.join(prefix, sub), exist_ok=True)
    port = free_port()
    cfg = os.path.join(prefix, "xrootd.cfg")
    with open(cfg, "w") as fh:
        fh.write(f"""all.export /
oss.localroot {data}
all.adminpath {prefix}/admin
all.pidpath {prefix}/run
xrd.protocol XrdHttp:{port} {XRDHTTP_LIB}
""")
    env = dict(os.environ)
    env.pop("LD_LIBRARY_PATH", None)
    proc = subprocess.Popen([servers.BRIX_BIN, "-c", cfg, "-l",
                             os.path.join(prefix, "logs", "xrootd.log")],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            env=env)
    if not wait_port(port, proc):
        proc.kill()
        sys.exit("xrootd XrdHttp failed to start")
    return port, proc


def http_get(client, port, want, timeout):
    """Download http://127.0.0.1:<port>/h.bin with the chosen client; (ok, secs)."""
    dst = tempfile.mktemp(suffix=".bin")
    url = f"http://127.0.0.1:{port}/{FILE_NAME}"
    if client == "repo":
        argv = [REPO_XRDCP, "-f", "-s", url, dst]
    else:  # curl
        argv = [CURL, "-s", "--max-time", str(timeout), "-o", dst, url]
    env = dict(os.environ)
    env.pop("LD_LIBRARY_PATH", None)
    env.pop("X509_USER_PROXY", None)
    start = time.monotonic()
    try:
        r = subprocess.run(argv, env=env, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        _rm(dst)
        return (False, float(timeout), "timeout")
    secs = time.monotonic() - start
    try:
        if r.returncode != 0:
            return (False, secs, f"rc={r.returncode}")
        if not os.path.exists(dst) or md5_file(dst) != want:
            return (False, secs, "md5")
        return (True, secs, "ok")
    finally:
        _rm(dst)


def _rm(p):
    try:
        os.unlink(p)
    except OSError:
        pass


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fault", choices=["reorder", "loss"], default="reorder",
                    help="reorder = hold %% of chunks back by --reorder-ms; "
                         "loss = sever the TCP stream with %% probability per chunk")
    ap.add_argument("--levels", default="0,0.0001,0.001,0.01,0.1,1.0")
    ap.add_argument("--reorder-ms", type=int, default=50)
    ap.add_argument("--size-mib", type=int, default=64)
    ap.add_argument("--reps", type=int, default=8)
    ap.add_argument("--timeout", type=int, default=120)
    args = ap.parse_args()

    if not os.path.isfile(REPO_XRDCP):
        sys.exit(f"repo xrdcp not built: {REPO_XRDCP}")
    if not servers.BRIX_BIN:
        sys.exit("official xrootd not on PATH")
    if not os.path.isfile(XRDHTTP_LIB):
        sys.exit(f"XrdHttp server lib missing: {XRDHTTP_LIB}")

    levels = [float(x) for x in args.levels.split(",") if x.strip() != ""]
    size_bytes = args.size_mib * 1024 * 1024

    base = os.path.join(servers.PREFIX, "http_reorder")
    shutil.rmtree(base, ignore_errors=True)
    ng_dir = os.path.join(base, "nginx")
    xr_dir = os.path.join(base, "xrootd")
    ng_data = os.path.join(ng_dir, "data")
    xr_data = os.path.join(xr_dir, "data")
    os.makedirs(ng_data, exist_ok=True)
    os.makedirs(xr_data, exist_ok=True)
    src = os.path.join(ng_data, FILE_NAME)
    subprocess.run(["dd", "if=/dev/urandom", f"of={src}", "bs=1M",
                    f"count={args.size_mib}"], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)
    want = md5_file(src)
    shutil.copy(src, os.path.join(xr_data, FILE_NAME))

    print(f"[setup] HTTP reorder  levels={levels}%  size={args.size_mib}MiB  "
          f"reps={args.reps}  reorder-ms={args.reorder_ms}")
    print("[note] official xrdcp cannot copy http:// (CLI limit) — clients: "
          "repo xrdcp + curl")

    ng_port, ng_harness = start_nginx_http(ng_dir, ng_data)
    xr_port, xr_proc = start_brix_http(xr_dir, xr_data)
    smap = {"nginx": ng_port, "xrootd": xr_port}
    print(f"[up] nginx http :{ng_port}   xrootd XrdHttp :{xr_port}")

    pairs = [("repo", "nginx"), ("repo", "xrootd"),
             ("curl", "nginx"), ("curl", "xrootd")]
    rows = []
    try:
        for client, sname in pairs:
            for level in levels:
                for rep in range(1, args.reps + 1):
                    with servers.FaultProxy(smap[sname]) as fp:
                        if level > 0:
                            if args.fault == "loss":
                                fp.set_loss(level)
                            else:
                                fp.set_reorder(level, args.reorder_ms)
                        ok, secs, why = http_get(client, fp.listen, want,
                                                 args.timeout)
                    mbps = (size_bytes / secs / 1e6) if ok and secs > 0 else 0
                    print(f"  {client:5s}→{sname:6s} {args.fault}={level:>7g}% rep{rep}: "
                          f"{'OK ' if ok else 'FAIL'} {secs:6.2f}s {mbps:7.1f}MB/s ({why})")
                    rows.append(dict(client=client, server=sname, level=level,
                                     ok=ok, secs=round(secs, 3)))
    finally:
        ng_harness.close()
        xr_proc.terminate()
        try:
            xr_proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            xr_proc.kill()

    print_summary(rows, pairs, levels, size_bytes, args.reps)


def print_summary(rows, pairs, levels, size_bytes, reps):
    def med_mbps(client, server, level):
        good = sorted(r["secs"] for r in rows if r["client"] == client
                      and r["server"] == server and r["level"] == level and r["ok"])
        return size_bytes / good[len(good) // 2] / 1e6 if good else None

    cols = [("repo", "nginx"), ("repo", "xrootd"), ("curl", "nginx"), ("curl", "xrootd")]

    def okn(client, server, level):
        cell = [r for r in rows if r["client"] == client and r["server"] == server
                and r["level"] == level]
        return sum(1 for r in cell if r["ok"]), len(cell)

    # Per-level success rate — the key metric under loss (severs => failed GETs).
    print("\n=== HTTP byte-exact ok/N per level ===")
    hdr = f"    {'level%':>9s}" + "".join(f"{c+'→'+s:>16s}" for c, s in cols)
    print(hdr)
    print("    " + "-" * (len(hdr) - 4))
    for level in levels:
        line = f"    {level:>9g}"
        for c, s in cols:
            o, n = okn(c, s, level)
            line += f"{f'{o}/{n}':>16s}"
        print(line)

    print("\n=== HTTP median MB/s of SUCCESSFUL GETs ===")
    print(hdr)
    print("    " + "-" * (len(hdr) - 4))
    for level in levels:
        line = f"    {level:>9g}"
        for c, s in cols:
            v = med_mbps(c, s, level)
            line += f"{(f'{v:.1f}' if v is not None else '-'):>16s}"
        print(line)


if __name__ == "__main__":
    main()
