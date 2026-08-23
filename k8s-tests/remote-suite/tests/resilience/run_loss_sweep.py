#!/usr/bin/env python3
"""
run_loss_sweep.py — wire-fault sweep for the native xrdfs client over root://+GSI.

WHAT: for each server (this repo's nginx module, and the official xrootd daemon)
      x each fault level x N reps, run `xrdfs ... cat <file>` through the in-repo
      fault proxy with the selected fault engaged, and record how long the transfer
      took and whether it completed byte-exact.

      The fault is one of (`--fault`):
        loss   — `lossy <level>`: sever the stream with <level>% probability per
                 chunk (application-visible wire loss; the default).
        jitter — `jitter <level>`: delay each chunk by a uniform-random 0..<level>
                 milliseconds. This is the faithful application-layer signature of
                 out-of-order PACKET delivery on a TCP stream (TCP reassembles in
                 order below us, so real reordering only ever shows up to the app as
                 variable latency — see tests/c/fault_proxy.c NOTE). Use this to
                 measure how the client fares under reordering/jitter conditions.
        both   — apply loss AND jitter at the level (a lossy, reordering link).

WHY:  re-runs the resilience comparison with the *current* client against both
      backends, on dedicated ports isolated from the main test suite.

HOW:  client -> fault_proxy(<fault> level) -> {nginx|xrootd}.  Both servers are
      brought up self-contained by tests/resilience/servers.py.  Results are
      written as per-rep CSV and printed as a per-cell summary table.

Run (from repo root):
  PYTHONPATH=tests python3 tests/resilience/run_loss_sweep.py
  # out-of-order / jitter sweep at 0,1,5,10,12,15,20 (ms):
  PYTHONPATH=tests python3 tests/resilience/run_loss_sweep.py --fault jitter
  PYTHONPATH=tests python3 tests/resilience/run_loss_sweep.py \
      --fault both --levels 0,1,5,10,12,15,20 --reps 5 --size-mib 256 --timeout 240
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


def _drain_ready(ready, out_fd, open_fds, stderr_buf):
    byte_count = 0
    for descriptor in ready:
        chunk = os.read(descriptor, 1 << 20)
        if not chunk:
            open_fds.discard(descriptor)
        elif descriptor == out_fd:
            byte_count += len(chunk)
        else:
            stderr_buf.append(chunk)
    return byte_count


def _measurement_result(returncode, byte_count, expected, elapsed, stderr_buf):
    if returncode == 0 and byte_count == expected:
        return True, elapsed, byte_count, "ok"
    if returncode == 0:
        return False, elapsed, byte_count, "short"
    error = b"".join(stderr_buf).decode(errors="replace").strip().replace("\n", " ")
    return False, elapsed, byte_count, f"rc={returncode}:{error[-120:]}"


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
        n += _drain_ready(ready, out_fd, open_fds, stderr_buf)
    rc = proc.wait()
    elapsed = time.monotonic() - start
    return _measurement_result(rc, n, expected_bytes, elapsed, stderr_buf)


def _argument_parser():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fault", choices=["loss", "jitter", "both"], default="loss",
                    help="fault to sweep: loss (sever %%/chunk), jitter (random "
                         "0..level ms/chunk = faithful out-of-order signature), or "
                         "both")
    ap.add_argument("--levels", "--losses", dest="levels", default="0,1,5,10,12,15,20",
                    help="comma-separated fault levels (loss%% and/or jitter-ms, per "
                         "--fault)")
    ap.add_argument("--reps", type=int, default=5, help="reps per (server,level) cell")
    ap.add_argument("--size-mib", type=int, default=256, help="test file size (MiB)")
    ap.add_argument("--timeout", type=int, default=240, help="per-transfer timeout (s)")
    ap.add_argument("--client-max-stall", type=int, default=None,
                    help="XRDC_MAX_STALL_MS for the client: resilience window in ms "
                         "(0=fail fast; omit for the client default). Higher loss "
                         "needs a wider window since each recovery re-handshakes.")
    ap.add_argument("--file-path", default="/loss/big.bin", help="server-side path")
    ap.add_argument("--out", default=os.path.join(servers.PREFIX, "loss_sweep_results.csv"))
    return ap


def _seed_targets(nginx, xrootd, args, size_bytes):
    local_src = os.path.join(servers.PREFIX, "src_big.bin")
    servers.seed_file(os.path.dirname(local_src), os.path.basename(local_src), size_bytes)
    servers.seed_file(nginx.data, args.file_path, size_bytes, src=local_src)
    servers.seed_file(xrootd.data, args.file_path, size_bytes, src=local_src)


def _sanity_targets(targets, host, args, size_bytes):
    for name, port in targets:
        result = measure(
            f"root://{host}:{port}/", args.file_path, size_bytes, args.timeout,
            client_max_stall_ms=args.client_max_stall,
        )
        ok, elapsed, byte_count, reason = result
        print(f"[sanity] {name:7s} direct 0%: success={ok} "
              f"{elapsed:6.2f}s {byte_count}B ({reason})")
        if not ok:
            raise RuntimeError(f"{name} failed clean 0% baseline: {reason}")


def _sweep_rep(name, port, fault, level, rep, args, size_bytes, unit):
    with servers.FaultProxy(port) as proxy:
        apply_fault(proxy, fault, level)
        result = measure(
            proxy.url(), args.file_path, size_bytes, args.timeout,
            client_max_stall_ms=args.client_max_stall,
        )
    ok, elapsed, byte_count, reason = result
    print(f"  {name:7s} {fault}={level:2d}{unit} rep {rep}/{args.reps}: "
          f"{'OK ' if ok else 'FAIL'} {elapsed:7.2f}s  ({reason})")
    return dict(server=name, fault=fault, level=level, rep=rep, success=ok,
                elapsed_s=round(elapsed, 3), bytes=byte_count, reason=reason)


def _sweep_targets(targets, levels, args, size_bytes):
    unit = "ms" if args.fault == "jitter" else "%"
    return [
        _sweep_rep(name, port, args.fault, level, rep, args, size_bytes, unit)
        for name, port in targets
        for level in levels
        for rep in range(1, args.reps + 1)
    ]


def _write_rows(path, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["server", "fault", "level", "rep", "success",
                        "elapsed_s", "bytes", "reason"],
        )
        writer.writeheader()
        writer.writerows(rows)


def main():
    args = _argument_parser().parse_args()

    levels = [int(x) for x in args.levels.split(",") if x.strip() != ""]
    size_bytes = args.size_mib * 1024 * 1024

    print(f"[setup] prefix={servers.PREFIX}  fault={args.fault}  levels={levels}  "
          f"reps={args.reps}  size={args.size_mib}MiB  timeout={args.timeout}s")
    servers.ensure_pki()

    rows = []
    with servers.NginxGsi() as nginx, servers.XrootdGsi() as xrootd:
        print(f"[up] nginx GSI :{nginx.port}   xrootd GSI :{xrootd.port}")
        _seed_targets(nginx, xrootd, args, size_bytes)
        print(f"[seed] {args.size_mib}MiB into both data roots")

        targets = [("nginx", nginx.port), ("xrootd", xrootd.port)]
        _sanity_targets(targets, "127.0.0.1", args, size_bytes)
        rows = _sweep_targets(targets, levels, args, size_bytes)

    # Persist per-rep rows.
    _write_rows(args.out, rows)

    print_summary(rows, args.fault, levels, args.reps)
    print(f"\n[done] per-rep CSV: {args.out}")


def apply_fault(fp, fault, level):
    """Engage the selected fault on the proxy at `level` (loss% and/or jitter-ms)."""
    if fault == "loss":
        fp.set_loss(level)
    elif fault == "jitter":
        fp.set_jitter(level)
    else:  # both — set loss first, then jitter (set_jitter at level>0 won't clear it)
        fp.set_loss(level)
        fp.set_jitter(level)


def _successful_times(rows, name, level):
    cell = [row for row in rows if row["server"] == name and row["level"] == level]
    return [row["elapsed_s"] for row in cell if row["success"]]


def _print_summary_cell(name, level, reps, successful):
    count = len(successful)
    prefix = f"{name:8s} {level:7d} {count:3d}/{reps:<2d} "
    if not successful:
        print(prefix + f"{'-':>8s} {'-':>8s} {'-':>8s}")
        return
    minimum = min(successful)
    median = statistics.median(successful)
    maximum = max(successful)
    print(prefix + f"{minimum:8.2f} {median:8.2f} {maximum:8.2f}")


def print_summary(rows, fault, levels, reps):
    """Print per-cell success counts and successful-transfer timing."""
    print("\n=== SUMMARY (success-rate and timing of SUCCESSFUL transfers) ===")
    unit = "ms" if fault == "jitter" else "%"
    header = f"{'server':8s} {fault + unit:>7s} {'ok/N':>6s} {'min s':>8s} {'med s':>8s} {'max s':>8s}"
    print(header)
    print("-" * len(header))
    for name in ("nginx", "xrootd"):
        for level in levels:
            _print_summary_cell(name, level, reps, _successful_times(rows, name, level))


if __name__ == "__main__":
    main()
