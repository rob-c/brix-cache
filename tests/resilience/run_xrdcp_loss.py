#!/usr/bin/env python3
"""
run_xrdcp_loss.py — xrdcp download under packet loss: repo client vs official client.

WHAT: for each (client, server) pair × loss level × N reps, download a seeded file
      with `xrdcp` through the in-repo fault proxy (`lossy <pct>`) and record
      wall-clock time, effective throughput, and byte-exactness (md5).

      Clients:  repo     = ./client/bin/xrdcp   (native libbrix, resilient)
                official = /usr/bin/xrdcp        (XRootD XrdCl)
      Servers:  nginx    = this repo's nginx module (root://, anonymous)
                xrootd   = official xrootd daemon  (root://, anonymous)

      Default pairs are the diagonal the comparison asks for —
        repo→nginx   and   official→xrootd
      `--matrix` additionally runs the cross pairs (repo→xrootd, official→nginx),
      which isolate whether a difference comes from the client or the server.

WHY:  apples-to-apples (anonymous, same file, same fault proxy, same loss grid)
      comparison of how the repo's native client + module hold up under wire loss
      versus the stock XRootD client + server.

HOW:  client -> brix-fault-proxy(lossy pct) -> {nginx|xrootd}. Both servers come up once
      (anonymous) under /tmp/xrd-resilience; identical content is seeded into both.
      The fault proxy severs the TCP stream with <pct>% probability per 64 KB chunk
      (application-visible reset — see client/apps/diag/brix_fault_proxy.c). Each copy is bounded
      by a wall-clock --timeout; a client that can't finish is recorded as a failure.

NOTE: the two clients have different built-in recovery windows (repo: XRDC_MAX_STALL_MS,
      default 30 s; official: XrdCl XRD_* defaults). This compares out-of-the-box
      behaviour; the per-copy --timeout is the common outer bound.

Run (from repo root):
  PYTHONPATH=tests python3 tests/resilience/run_xrdcp_loss.py
  PYTHONPATH=tests python3 tests/resilience/run_xrdcp_loss.py \
      --levels 0,0.0001,0.001,0.01,0.1,1.0 --size-mib 64 --reps 5 --matrix
"""
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import servers  # noqa: E402

REPO_XRDCP = os.path.join(servers.CLIENT_BIN, "xrdcp")
OFFICIAL_XRDCP = shutil.which("xrdcp") or "/usr/bin/xrdcp"
FILE_PATH = "/loss/big.bin"
HOST = os.environ.get("TEST_HOST", "127.0.0.1")


def _md5_file(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def client_env(name, max_stall_ms, repo_backoff_ms):
    """Environment for a client variant. All drop LD_LIBRARY_PATH (a conda prefix
    breaks the system XRootD libs) and any ambient X509 proxy (anonymous transfers).
    The repo variants get the resilience window; `repo-fast` additionally minimises
    the transport-fault backoff (XRDC_BACKOFF_BASE_MS) for maximal throughput under
    reset-style loss."""
    env = dict(os.environ)
    env.pop("LD_LIBRARY_PATH", None)
    env.pop("X509_USER_PROXY", None)
    if name.startswith("repo"):
        env["XRDC_MAX_STALL_MS"] = str(max_stall_ms)
    if name == "repo-fast":
        env["XRDC_BACKOFF_BASE_MS"] = str(repo_backoff_ms)
    return env


def copy_once(client_bin, env, port, want_md5, expect_bytes, timeout):
    """One `xrdcp root://{HOST}:<port>//path <tmp>` download through the proxy.
    Returns (ok, secs, reason). ok = rc 0 AND byte-exact (size + md5)."""
    dst = tempfile.mktemp(suffix=".bin", dir=os.environ.get("TMPDIR", "/tmp"))
    url = f"root://{HOST}:{port}/{FILE_PATH}"  # //loss/big.bin
    argv = [client_bin, "-f", "-s", url, dst]
    start = time.monotonic()
    try:
        r = subprocess.run(argv, env=env, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        _rm(dst)
        return (False, float(timeout), "timeout")
    secs = time.monotonic() - start
    try:
        if r.returncode != 0:
            err = r.stderr.decode(errors="replace").strip().replace("\n", " ")
            return (False, secs, f"rc={r.returncode}:{err[-90:]}")
        if not os.path.exists(dst):
            return (False, secs, "no-output")
        if os.path.getsize(dst) != expect_bytes:
            return (False, secs, f"short:{os.path.getsize(dst)}/{expect_bytes}")
        if _md5_file(dst) != want_md5:
            return (False, secs, "md5-mismatch")
        return (True, secs, "ok")
    finally:
        _rm(dst)


def _rm(p):
    try:
        os.unlink(p)
    except OSError:
        pass


def _parser():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fault", choices=["loss", "reorder"], default="loss",
                    help="loss = sever %%/chunk (default); reorder = hold %% of chunks "
                         "back by --reorder-ms (out-of-order delivery)")
    ap.add_argument("--reorder-ms", type=int, default=50,
                    help="hold-back delay for the reorder fault (ms)")
    ap.add_argument("--levels", default="0,0.0001,0.001,0.01,0.1,1.0",
                    help="comma-separated percentages (fractional ok)")
    ap.add_argument("--size-mib", type=int, default=64, help="test file size (MiB)")
    ap.add_argument("--reps", type=int, default=5, help="reps per (pair, level) cell")
    ap.add_argument("--timeout", type=int, default=120, help="per-copy wall-clock (s)")
    ap.add_argument("--max-stall", type=int, default=30000,
                    help="XRDC_MAX_STALL_MS for the repo client (resilience window)")
    ap.add_argument("--repo-backoff-ms", type=int, default=1,
                    help="XRDC_BACKOFF_BASE_MS for the repo-fast variant (default 1; "
                         "the stock repo client uses 25)")
    ap.add_argument("--matrix", action="store_true",
                    help="also run the cross pairs (repo-fast→xrootd, official→nginx, "
                         "repo→xrootd)")
    return ap


def _validate_binaries():
    requirements = [
        (os.path.isfile(REPO_XRDCP), f"repo xrdcp not built: {REPO_XRDCP}"),
        (os.path.isfile(OFFICIAL_XRDCP),
         f"official xrdcp not found: {OFFICIAL_XRDCP}"),
        (bool(servers.BRIX_BIN), "official xrootd daemon not on PATH"),
        (os.path.isfile(servers.NGINX_BIN),
         f"nginx not built: {servers.NGINX_BIN}"),
    ]
    for available, message in requirements:
        if not available:
            sys.exit(message)


def _pairs(include_matrix):
    pairs = [("repo", "nginx"), ("repo-fast", "nginx"), ("official", "xrootd")]
    if include_matrix:
        pairs += [("repo-fast", "xrootd"), ("official", "nginx"), ("repo", "xrootd")]
    return pairs


def _print_setup(args, levels):
    print(f"[setup] levels={levels}%  size={args.size_mib}MiB  reps={args.reps}  "
          f"timeout={args.timeout}s  max-stall={args.max_stall}ms  "
          f"repo-fast backoff={args.repo_backoff_ms}ms (stock=25)")
    print(f"[clients] repo/repo-fast={REPO_XRDCP}  official={OFFICIAL_XRDCP}")


def _run_copy(args, client_name, server_name, client_bin, env, server, level,
              rep, want, size_bytes):
    with servers.FaultProxy(server.port) as proxy:
        if args.fault == "reorder":
            proxy.set_reorder(level, args.reorder_ms)
        else:
            proxy.set_loss(level)
        passed, secs, reason = copy_once(
            client_bin, env, proxy.listen, want, size_bytes, args.timeout)
    mbps = size_bytes / secs / 1e6 if passed and secs > 0 else 0
    verdict = "OK " if passed else "FAIL"
    print(f"  {client_name:8s}→{server_name:6s} {args.fault}={level:>7g}% "
          f"rep{rep}: {verdict} {secs:7.2f}s {mbps:7.1f}MB/s ({reason})")
    return dict(client=client_name, server=server_name, level=level, rep=rep,
                ok=passed, secs=round(secs, 3), reason=reason)


def _run_pair(args, pair, clients, servers_by_name, levels, want, size_bytes):
    client_name, server_name = pair
    env = client_env(client_name, args.max_stall, args.repo_backoff_ms)
    rows = []
    for level in levels:
        for rep in range(1, args.reps + 1):
            rows.append(_run_copy(
                args, client_name, server_name, clients[client_name], env,
                servers_by_name[server_name], level, rep, want, size_bytes))
    return rows


def _run_matrix(args, pairs, levels, size_bytes):
    clients = {"repo": REPO_XRDCP, "repo-fast": REPO_XRDCP,
               "official": OFFICIAL_XRDCP}
    rows = []
    with servers.NginxAnon() as nginx, servers.XrootdAnon() as xrootd:
        servers_by_name = {"nginx": nginx, "xrootd": xrootd}
        print(f"[up] nginx anon :{nginx.port}   xrootd anon :{xrootd.port}")
        source = servers.seed_file(nginx.data, FILE_PATH, size_bytes)
        servers.seed_file(xrootd.data, FILE_PATH, size_bytes, src=source)
        want = _md5_file(source)
        print(f"[seed] {args.size_mib}MiB into both (md5={want[:12]}…)\n")
        for pair in pairs:
            rows.extend(_run_pair(
                args, pair, clients, servers_by_name, levels, want, size_bytes))
    return rows


def main():
    args = _parser().parse_args()
    _validate_binaries()
    levels = [float(x) for x in args.levels.split(",") if x.strip() != ""]
    size_bytes = args.size_mib * 1024 * 1024
    pairs = _pairs(args.matrix)
    _print_setup(args, levels)
    rows = _run_matrix(args, pairs, levels, size_bytes)
    print_summary(rows, pairs, levels, size_bytes, args.reps)


def _successful_times(rows, client_name, server_name, level):
    return sorted(
        row["secs"] for row in rows
        if row["client"] == client_name
        and row["server"] == server_name
        and row["level"] == level
        and row["ok"])


def _print_cell(rows, pair, level, size_bytes, reps):
    client_name, server_name = pair
    good = _successful_times(rows, client_name, server_name, level)
    if not good:
        print(f"    {level:>8g} {0:3d}/{reps:<2d} {'-':>8s} {'-':>8s}")
        return
    median = good[len(good) // 2]
    mbps = size_bytes / median / 1e6 if median > 0 else 0
    print(f"    {level:>8g} {len(good):3d}/{reps:<2d} {median:8.2f} {mbps:8.1f}")


def _print_pair_summary(rows, pair, levels, size_bytes, reps):
    client_name, server_name = pair
    print(f"\n  {client_name} → {server_name}")
    header = f"    {'loss%':>8s} {'ok/N':>6s} {'med s':>8s} {'MB/s':>8s}"
    print(header)
    print("    " + "-" * (len(header) - 4))
    for level in levels:
        _print_cell(rows, pair, level, size_bytes, reps)


def _median_mbps(rows, pair, level, size_bytes):
    good = _successful_times(rows, pair[0], pair[1], level)
    if not good:
        return None
    return size_bytes / good[len(good) // 2] / 1e6


def _format_rate(value):
    return f"{value:.1f}" if value is not None else "-"


def _print_head_to_head(rows, levels, size_bytes):
    print("\n  HEAD-TO-HEAD  (median MB/s of successful copies)")
    print(f"    {'loss%':>8s} {'repo→nginx':>13s} {'repo-fast→nginx':>17s} "
          f"{'official→xrootd':>17s}")
    print("    " + "-" * 58)
    head = [("repo", "nginx"), ("repo-fast", "nginx"), ("official", "xrootd")]
    for level in levels:
        rates = [_median_mbps(rows, pair, level, size_bytes) for pair in head]
        values = [_format_rate(value) for value in rates]
        print(f"    {level:>8g} {values[0]:>13} {values[1]:>17} {values[2]:>17}")


def print_summary(rows, pairs, levels, size_bytes, reps):
    print("\n=== SUMMARY (byte-exact ok/N + median time / throughput of successes) ===")
    for pair in pairs:
        _print_pair_summary(rows, pair, levels, size_bytes, reps)
    head = [("repo", "nginx"), ("repo-fast", "nginx"), ("official", "xrootd")]
    if all(pair in pairs for pair in head):
        _print_head_to_head(rows, levels, size_bytes)


if __name__ == "__main__":
    main()
