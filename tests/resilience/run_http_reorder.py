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

client -> brix-fault-proxy(reorder pct/ms) -> {nginx|xrootd}.  Byte-exact (md5) checked.

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
from settings import BIND_HOST, HOST

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
    from ephemeral_port import free_port as assigned_port
    return assigned_port(BIND_HOST)


def wait_port(port, proc, tries=80):
    for _ in range(tries):
        try:
            socket.create_connection((HOST, port), timeout=0.3).close()
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
    """Download http://{HOST}:<port>/h.bin with the chosen client; (ok, secs)."""
    dst = tempfile.mktemp(suffix=".bin")
    url = f"http://{HOST}:{port}/{FILE_NAME}"
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
    args = _parse_args()
    _validate_prerequisites()
    levels = [float(value) for value in args.levels.split(",") if value.strip()]
    size_bytes = args.size_mib * 1024 * 1024
    setup = _prepare_data(args, levels)
    ng_port, ng_harness = start_nginx_http(setup["ng_dir"], setup["ng_data"])
    xr_port, xr_proc = start_brix_http(setup["xr_dir"], setup["xr_data"])
    ports = {"nginx": ng_port, "xrootd": xr_port}
    print(f"[up] nginx http :{ng_port}   xrootd XrdHttp :{xr_port}")
    pairs = [("repo", "nginx"), ("repo", "xrootd"),
             ("curl", "nginx"), ("curl", "xrootd")]
    try:
        rows = _run_matrix(args, levels, size_bytes, setup["checksum"], ports, pairs)
    finally:
        _stop_servers(ng_harness, xr_proc)
    print_summary(rows, pairs, levels, size_bytes, args.reps)


def _parse_args():
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
    return ap.parse_args()


def _validate_prerequisites():
    if not os.path.isfile(REPO_XRDCP):
        sys.exit(f"repo xrdcp not built: {REPO_XRDCP}")
    if not servers.BRIX_BIN:
        sys.exit("official xrootd not on PATH")
    if not os.path.isfile(XRDHTTP_LIB):
        sys.exit(f"XrdHttp server lib missing: {XRDHTTP_LIB}")


def _prepare_data(args, levels):
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
    return {"ng_dir": ng_dir, "xr_dir": xr_dir, "ng_data": ng_data,
            "xr_data": xr_data, "checksum": want}


def _run_matrix(args, levels, size_bytes, checksum, ports, pairs):
    rows = []
    cases = ((client, server, level, repetition)
             for client, server in pairs
             for level in levels
             for repetition in range(1, args.reps + 1))
    for case in cases:
        rows.append(_run_case(args, size_bytes, checksum, ports, case))
    return rows


def _run_case(args, size_bytes, checksum, ports, case):
    client, server, level, repetition = case
    with servers.FaultProxy(ports[server]) as proxy:
        _configure_fault(proxy, args, level)
        succeeded, seconds, reason = http_get(
            client, proxy.listen, checksum, args.timeout
        )
    rate = size_bytes / seconds / 1e6 if succeeded and seconds > 0 else 0
    outcome = "OK " if succeeded else "FAIL"
    print(f"  {client:5s}→{server:6s} {args.fault}={level:>7g}% rep{repetition}: "
          f"{outcome} {seconds:6.2f}s {rate:7.1f}MB/s ({reason})")
    return dict(client=client, server=server, level=level,
                ok=succeeded, secs=round(seconds, 3))


def _configure_fault(proxy, args, level):
    if level <= 0:
        return
    if args.fault == "loss":
        proxy.set_loss(level)
        return
    proxy.set_reorder(level, args.reorder_ms)


def _stop_servers(nginx_harness, xrootd_process):
    nginx_harness.close()
    xrootd_process.terminate()
    try:
        xrootd_process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        xrootd_process.kill()


def print_summary(rows, pairs, levels, size_bytes, reps):
    cols = [("repo", "nginx"), ("repo", "xrootd"), ("curl", "nginx"), ("curl", "xrootd")]
    hdr = f"    {'level%':>9s}" + "".join(f"{c+'→'+s:>16s}" for c, s in cols)
    _print_table("HTTP byte-exact ok/N per level", hdr, levels, cols,
                 lambda client, server, level: _success_cell(
                     rows, client, server, level))
    _print_table("HTTP median MB/s of SUCCESSFUL GETs", hdr, levels, cols,
                 lambda client, server, level: _rate_cell(
                     rows, client, server, level, size_bytes))
    del pairs, reps


def _print_table(title, hdr, levels, columns, cell_value):
    print(f"\n=== {title} ===")
    print(hdr)
    print("    " + "-" * (len(hdr) - 4))
    for level in levels:
        line = f"    {level:>9g}"
        for client, server in columns:
            line += f"{cell_value(client, server, level):>16s}"
        print(line)


def _matching_rows(rows, client, server, level):
    return [row for row in rows
            if row["client"] == client
            and row["server"] == server
            and row["level"] == level]


def _success_cell(rows, client, server, level):
    cell = _matching_rows(rows, client, server, level)
    succeeded = sum(1 for row in cell if row["ok"])
    return f"{succeeded}/{len(cell)}"


def _rate_cell(rows, client, server, level, size_bytes):
    seconds = sorted(row["secs"] for row in _matching_rows(
        rows, client, server, level) if row["ok"])
    if not seconds:
        return "-"
    rate = size_bytes / seconds[len(seconds) // 2] / 1e6
    return f"{rate:.1f}"


if __name__ == "__main__":
    main()
