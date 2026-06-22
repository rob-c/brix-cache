#!/usr/bin/env python3
"""
run_loss_sweep.py — wire-loss sweep for the native xrdfs client over root://+GSI.

WHAT: for each server (this repo's nginx module, and the official xrootd daemon)
      x each loss level x N reps, run `xrdfs ... cat <file>` through the in-repo
      fault proxy with `lossy <pct>` engaged, and record how long the transfer
      took and whether it completed byte-exact.

WHY:  re-runs the resilience comparison with the *current* client against both
      backends, on dedicated ports isolated from the main test suite.

HOW:  client -> fault_proxy(lossy pct) -> {nginx|xrootd}.  Both servers are
      brought up self-contained by tests/resilience/servers.py.  Results are
      written as per-rep CSV and printed as a per-cell summary table.

Run (from repo root):
  PYTHONPATH=tests python3 tests/resilience/run_loss_sweep.py
  PYTHONPATH=tests python3 tests/resilience/run_loss_sweep.py \
      --losses 0,1,5,10,12,15 --reps 5 --size-mib 256 --timeout 240
"""
import argparse
import csv
import os
import select
import statistics
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import servers  # noqa: E402


def measure(url, file_path, expected_bytes, timeout, client_max_stall_ms=None):
    """Run one `xrdfs <url> cat <file_path>`, streaming stdout to /dev/null while
    counting bytes, bounded by a wall-clock deadline.

    client_max_stall_ms sets XRDC_MAX_STALL_MS for the client (the resilience
    window): a positive value widens/narrows it, 0 disables resilience (fail
    fast), None leaves the client's built-in default.

    Returns (success, elapsed_s, bytes_read, reason).  success is True only when
    the client exits 0 AND the full file came back (byte-exact length)."""
    argv = [servers.XRDFS, url, "cat", file_path]
    env = servers.gsi_env()
    if client_max_stall_ms is not None:
        env["XRDC_MAX_STALL_MS"] = str(client_max_stall_ms)
    stderr_buf = []
    start = time.monotonic()
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env)
    out_fd, err_fd = proc.stdout.fileno(), proc.stderr.fileno()
    os.set_blocking(out_fd, False)
    os.set_blocking(err_fd, False)
    n = 0
    deadline = start + timeout
    # Drain both pipes until each hits EOF (closed when the client exits); a
    # passed deadline kills the client and the transfer is recorded as a timeout.
    open_fds = {out_fd, err_fd}
    while open_fds:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            proc.kill()
            proc.wait()
            return (False, time.monotonic() - start, n, "timeout")
        ready, _, _ = select.select(list(open_fds), [], [], min(remaining, 1.0))
        for fd in ready:
            buf = os.read(fd, 1 << 20)
            if not buf:          # EOF on this pipe
                open_fds.discard(fd)
                continue
            if fd == out_fd:
                n += len(buf)
            else:
                stderr_buf.append(buf)
    rc = proc.wait()
    elapsed = time.monotonic() - start
    if rc == 0 and n == expected_bytes:
        return (True, elapsed, n, "ok")
    if rc == 0 and n != expected_bytes:
        return (False, elapsed, n, "short")
    err = b"".join(stderr_buf).decode(errors="replace").strip().replace("\n", " ")
    return (False, elapsed, n, f"rc={rc}:{err[-120:]}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--losses", default="0,1,5,10,12,15",
                    help="comma-separated loss percentages")
    ap.add_argument("--reps", type=int, default=5, help="reps per (server,loss) cell")
    ap.add_argument("--size-mib", type=int, default=256, help="test file size (MiB)")
    ap.add_argument("--timeout", type=int, default=240, help="per-transfer timeout (s)")
    ap.add_argument("--client-max-stall", type=int, default=None,
                    help="XRDC_MAX_STALL_MS for the client: resilience window in ms "
                         "(0=fail fast; omit for the client default). Higher loss "
                         "needs a wider window since each recovery re-handshakes.")
    ap.add_argument("--file-path", default="/loss/big.bin", help="server-side path")
    ap.add_argument("--out", default=os.path.join(servers.PREFIX, "loss_sweep_results.csv"))
    args = ap.parse_args()

    losses = [int(x) for x in args.losses.split(",") if x.strip() != ""]
    size_bytes = args.size_mib * 1024 * 1024

    print(f"[setup] prefix={servers.PREFIX}  losses={losses}  reps={args.reps}  "
          f"size={args.size_mib}MiB  timeout={args.timeout}s")
    servers.ensure_pki()

    rows = []
    with servers.NginxGsi() as nginx, servers.XrootdGsi() as xrootd:
        print(f"[up] nginx GSI :{nginx.port}   xrootd GSI :{xrootd.port}")
        # Seed identical content into both data roots.
        local_src = os.path.join(servers.PREFIX, "src_big.bin")
        servers.seed_file(os.path.dirname(local_src), os.path.basename(local_src), size_bytes)
        servers.seed_file(nginx.data, args.file_path, size_bytes, src=local_src)
        servers.seed_file(xrootd.data, args.file_path, size_bytes, src=local_src)
        print(f"[seed] {args.size_mib}MiB into both data roots")

        targets = [("nginx", nginx.port), ("xrootd", xrootd.port)]
        # 0% sanity (direct, no proxy) for each server before the sweep.
        for name, port in targets:
            ok, el, nb, why = measure(f"root://127.0.0.1:{port}/", args.file_path,
                                      size_bytes, args.timeout,
                                      client_max_stall_ms=args.client_max_stall)
            print(f"[sanity] {name:7s} direct 0%: success={ok} {el:6.2f}s {nb}B ({why})")
            if not ok:
                raise RuntimeError(f"{name} failed clean 0% baseline: {why}")

        for name, port in targets:
            for loss in losses:
                for rep in range(1, args.reps + 1):
                    with servers.FaultProxy(port) as fp:
                        fp.set_loss(loss)
                        ok, el, nb, why = measure(fp.url(), args.file_path,
                                                  size_bytes, args.timeout,
                                                  client_max_stall_ms=args.client_max_stall)
                    rows.append(dict(server=name, loss_pct=loss, rep=rep,
                                     success=ok, elapsed_s=round(el, 3),
                                     bytes=nb, reason=why))
                    print(f"  {name:7s} loss={loss:2d}% rep {rep}/{args.reps}: "
                          f"{'OK ' if ok else 'FAIL'} {el:7.2f}s  ({why})")

    # Persist per-rep rows.
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["server", "loss_pct", "rep", "success",
                                           "elapsed_s", "bytes", "reason"])
        w.writeheader()
        w.writerows(rows)

    print_summary(rows, losses, args.reps)
    print(f"\n[done] per-rep CSV: {args.out}")


def print_summary(rows, losses, reps):
    """Per-cell summary: success count and timing of successful transfers."""
    print("\n=== SUMMARY (success-rate and timing of SUCCESSFUL transfers) ===")
    header = f"{'server':8s} {'loss%':>5s} {'ok/N':>6s} {'min s':>8s} {'med s':>8s} {'max s':>8s}"
    print(header)
    print("-" * len(header))
    for name in ("nginx", "xrootd"):
        for loss in losses:
            cell = [r for r in rows if r["server"] == name and r["loss_pct"] == loss]
            good = [r["elapsed_s"] for r in cell if r["success"]]
            okn = len(good)
            if good:
                mn, md, mx = min(good), statistics.median(good), max(good)
                print(f"{name:8s} {loss:5d} {okn:3d}/{reps:<2d} "
                      f"{mn:8.2f} {md:8.2f} {mx:8.2f}")
            else:
                print(f"{name:8s} {loss:5d} {okn:3d}/{reps:<2d} "
                      f"{'-':>8s} {'-':>8s} {'-':>8s}")


if __name__ == "__main__":
    main()
