#!/usr/bin/env python3
"""
run_xrdcp_loss.py — xrdcp download under packet loss: repo client vs official client.

WHAT: for each (client, server) pair × loss level × N reps, download a seeded file
      with `xrdcp` through the in-repo fault proxy (`lossy <pct>`) and record
      wall-clock time, effective throughput, and byte-exactness (md5).

      Clients:  repo     = ./client/bin/xrdcp   (native libxrdc, resilient)
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

HOW:  client -> fault_proxy(lossy pct) -> {nginx|xrootd}. Both servers come up once
      (anonymous) under /tmp/xrd-resilience; identical content is seeded into both.
      The fault proxy severs the TCP stream with <pct>% probability per 64 KB chunk
      (application-visible reset — see tests/c/fault_proxy.c). Each copy is bounded
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
    """One `xrdcp root://127.0.0.1:<port>//path <tmp>` download through the proxy.
    Returns (ok, secs, reason). ok = rc 0 AND byte-exact (size + md5)."""
    dst = tempfile.mktemp(suffix=".bin", dir=os.environ.get("TMPDIR", "/tmp"))
    url = f"root://127.0.0.1:{port}/{FILE_PATH}"  # //loss/big.bin
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


def main():
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
    args = ap.parse_args()

    if not os.path.isfile(REPO_XRDCP):
        sys.exit(f"repo xrdcp not built: {REPO_XRDCP}")
    if not os.path.isfile(OFFICIAL_XRDCP):
        sys.exit(f"official xrdcp not found: {OFFICIAL_XRDCP}")
    if not servers.XROOTD_BIN:
        sys.exit("official xrootd daemon not on PATH")
    if not os.path.isfile(servers.NGINX_BIN):
        sys.exit(f"nginx not built: {servers.NGINX_BIN}")

    levels = [float(x) for x in args.levels.split(",") if x.strip() != ""]
    size_bytes = args.size_mib * 1024 * 1024
    clients = {"repo": REPO_XRDCP, "repo-fast": REPO_XRDCP,
               "official": OFFICIAL_XRDCP}
    pairs = [("repo", "nginx"), ("repo-fast", "nginx"), ("official", "xrootd")]
    if args.matrix:
        pairs += [("repo-fast", "xrootd"), ("official", "nginx"), ("repo", "xrootd")]

    print(f"[setup] levels={levels}%  size={args.size_mib}MiB  reps={args.reps}  "
          f"timeout={args.timeout}s  max-stall={args.max_stall}ms  "
          f"repo-fast backoff={args.repo_backoff_ms}ms (stock=25)")
    print(f"[clients] repo/repo-fast={REPO_XRDCP}  official={OFFICIAL_XRDCP}")

    rows = []
    with servers.NginxAnon() as ng, servers.XrootdAnon() as xr:
        smap = {"nginx": ng, "xrootd": xr}
        print(f"[up] nginx anon :{ng.port}   xrootd anon :{xr.port}")
        src = servers.seed_file(ng.data, FILE_PATH, size_bytes)
        servers.seed_file(xr.data, FILE_PATH, size_bytes, src=src)
        want = _md5_file(src)
        print(f"[seed] {args.size_mib}MiB into both (md5={want[:12]}…)\n")

        for cname, sname in pairs:
            client_bin = clients[cname]
            env = client_env(cname, args.max_stall, args.repo_backoff_ms)
            srv = smap[sname]
            for level in levels:
                for rep in range(1, args.reps + 1):
                    with servers.FaultProxy(srv.port) as fp:
                        if args.fault == "reorder":
                            fp.set_reorder(level, args.reorder_ms)
                        else:
                            fp.set_loss(level)
                        ok, secs, why = copy_once(client_bin, env, fp.listen, want,
                                                  size_bytes, args.timeout)
                    mbps = (size_bytes / secs / 1e6) if ok and secs > 0 else 0
                    print(f"  {cname:8s}→{sname:6s} {args.fault}={level:>7g}% rep{rep}: "
                          f"{'OK ' if ok else 'FAIL'} {secs:7.2f}s {mbps:7.1f}MB/s ({why})")
                    rows.append(dict(client=cname, server=sname, level=level, rep=rep,
                                     ok=ok, secs=round(secs, 3), reason=why))

    print_summary(rows, pairs, levels, size_bytes, args.reps)


def print_summary(rows, pairs, levels, size_bytes, reps):
    print("\n=== SUMMARY (byte-exact ok/N + median time / throughput of successes) ===")
    for cname, sname in pairs:
        print(f"\n  {cname} → {sname}")
        hdr = f"    {'loss%':>8s} {'ok/N':>6s} {'med s':>8s} {'MB/s':>8s}"
        print(hdr)
        print("    " + "-" * (len(hdr) - 4))
        for level in levels:
            cell = [r for r in rows if r["client"] == cname and r["server"] == sname
                    and r["level"] == level]
            good = sorted(r["secs"] for r in cell if r["ok"])
            okn = len(good)
            if good:
                med = good[len(good) // 2]
                mbps = size_bytes / med / 1e6 if med > 0 else 0
                print(f"    {level:>8g} {okn:3d}/{reps:<2d} {med:8.2f} {mbps:8.1f}")
            else:
                print(f"    {level:>8g} {okn:3d}/{reps:<2d} {'-':>8s} {'-':>8s}")

    # Head-to-head: stock repo, tuned repo, and official side by side (MB/s).
    head = [("repo", "nginx"), ("repo-fast", "nginx"), ("official", "xrootd")]
    if all(p in pairs for p in head):
        def med_mbps(cname, sname, level):
            good = sorted(r["secs"] for r in rows if r["client"] == cname
                          and r["server"] == sname and r["level"] == level and r["ok"])
            return size_bytes / good[len(good) // 2] / 1e6 if good else None

        print("\n  HEAD-TO-HEAD  (median MB/s of successful copies)")
        print(f"    {'loss%':>8s} {'repo→nginx':>13s} {'repo-fast→nginx':>17s} "
              f"{'official→xrootd':>17s}")
        print("    " + "-" * 58)
        for level in levels:
            def fmt(v):
                return f"{v:.1f}" if v is not None else "-"
            a = med_mbps("repo", "nginx", level)
            b = med_mbps("repo-fast", "nginx", level)
            c = med_mbps("official", "xrootd", level)
            print(f"    {level:>8g} {fmt(a):>13} {fmt(b):>17} {fmt(c):>17}")


if __name__ == "__main__":
    main()
