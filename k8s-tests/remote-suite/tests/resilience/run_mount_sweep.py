#!/usr/bin/env python3
"""
run_mount_sweep.py — xrootdfs FUSE mount under wire faults (loss / reorder / jitter).

WHAT: mount the native xrootdfs FUSE driver through the in-repo fault proxy and,
      for each fault level, run a WRITE round-trip and a READ round-trip, recording
      byte-exactness (md5, through the mount AND on the server's disk) plus
      wall-clock time / effective throughput.

      `--fault` selects what the proxy injects at each `--levels` value:
        loss    — `lossy <pct>`: sever the TCP stream with <pct>% probability per
                  forwarded chunk. An application-visible reset — the faithful,
                  harsher proxy for packet loss (real packet loss lives below TCP,
                  where it would be retransmitted; a sever forces the driver's full
                  reconnect + reopen + resume path). THE DEFAULT.
        reorder — `reorder <pct> <ms>`: hold <pct>% of chunks back by <ms> ms
                  (app-layer analog of `tc netem reorder` — out-of-order delivery).
        jitter  — `jitter <ms>`: uniform-random 0..<ms> delay on every chunk.

WHY:  measures how the resilient FUSE driver copes with each condition. Under loss
      a correct driver still returns every byte (reconnecting transparently),
      bounded by its --max-stall window — so the headline numbers are the success
      rate (does it recover at all?) and the time cost of recovery as loss climbs.

HOW:  client (FUSE) -> fault_proxy(<fault>) -> nginx (root://), on dedicated ports
      under /tmp/xrd-resilience, isolated from the main suite. The mount comes up
      on a CLEAN link, then the fault is engaged for the I/O (mirrors
      tests/test_xrootdfs_resilience.py), then cleared and unmounted. Each op runs
      under a watchdog: if the driver gives up and wedges, the mount is lazily
      unmounted so the sweep continues instead of hanging.

Run (from repo root):
  # packet-loss sweep (default), 0/1/5/10/12/15/20 %:
  PYTHONPATH=tests python3 tests/resilience/run_mount_sweep.py
  # out-of-order sweep:
  PYTHONPATH=tests python3 tests/resilience/run_mount_sweep.py --fault reorder --levels 0,1,2,3
"""
import argparse
import hashlib
import os
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import servers  # noqa: E402

XROOTDFS = os.path.join(servers.CLIENT_BIN, "xrootdfs")
HOST = "127.0.0.1"


def _md5(b):
    h = hashlib.md5()
    h.update(b)
    return h.hexdigest()


def _md5_file(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def with_timeout(fn, timeout_s):
    """Run fn() in a daemon thread; return (done, value). If it does not finish
    within timeout_s, return (False, None) — the thread is left to unwind once the
    caller unblocks it (lazy unmount)."""
    box = {}

    def run():
        box["v"] = fn()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout_s)
    if t.is_alive():
        return (False, None)
    return (True, box.get("v"))


def mount(url, max_stall_ms, env):
    """Mount xrootdfs at a fresh temp dir through `url`; return (mountpoint, proc)
    once the kernel reports it mounted, or (None, None) if it never came up."""
    mnt = subprocess.check_output(
        ["mktemp", "-d", os.path.join(os.environ.get("TMPDIR", "/tmp"),
                                      "xrdfssw.XXXXXX")]).decode().strip()
    argv = [XROOTDFS, "--max-stall", str(max_stall_ms), "--keepalive", "3000",
            url, mnt, "-f"]
    proc = subprocess.Popen(argv, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(80):
        if os.path.ismount(mnt):
            return mnt, proc
        if proc.poll() is not None:
            break
        time.sleep(0.1)
    if proc.poll() is None:
        proc.kill()
    subprocess.run(["fusermount3", "-uz", mnt], capture_output=True)
    try:
        os.rmdir(mnt)
    except OSError:
        pass
    return None, None


def unmount(mnt, proc, lazy=False):
    subprocess.run(["fusermount3", "-uz" if lazy else "-u", mnt],
                   capture_output=True)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    try:
        os.rmdir(mnt)
    except OSError:
        pass


def write_roundtrip(mnt, data_root, payload):
    """Write payload through the mount, read it back, and confirm both the mount
    readback AND the bytes on the server's disk match. Returns (ok, secs, reason)."""
    name = f"_sw_w_{os.getpid()}_{int(time.time()*1000)}.bin"
    mpath = os.path.join(mnt, name)
    disk = os.path.join(data_root, name)
    want = _md5(payload)
    try:
        t0 = time.monotonic()
        with open(mpath, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        secs = time.monotonic() - t0
        with open(mpath, "rb") as fh:
            if _md5(fh.read()) != want:
                return (False, secs, "mount-readback-mismatch")
        if not os.path.isfile(disk) or _md5_file(disk) != want:
            return (False, secs, "on-disk-mismatch")
        return (True, secs, "ok")
    except OSError as e:
        return (False, 0.0, f"errno:{e.errno}")
    finally:
        try:
            os.unlink(disk)
        except OSError:
            pass


def read_roundtrip(mnt, name, want_md5, expect_bytes):
    """Stream a pre-seeded file through the mount; confirm byte-exact. Returns
    (ok, secs, reason)."""
    mpath = os.path.join(mnt, name.lstrip("/"))
    h = hashlib.md5()
    n = 0
    try:
        t0 = time.monotonic()
        with open(mpath, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 16), b""):
                h.update(chunk)
                n += len(chunk)
        secs = time.monotonic() - t0
        if n != expect_bytes:
            return (False, secs, f"short:{n}/{expect_bytes}")
        if h.hexdigest() != want_md5:
            return (False, secs, "read-mismatch")
        return (True, secs, "ok")
    except OSError as e:
        return (False, 0.0, f"errno:{e.errno}")


def apply_fault(fp, fault, level, reorder_ms):
    if fault == "loss":
        fp.set_loss(level)            # may be fractional (sub-percent)
    elif fault == "jitter":
        fp.set_jitter(int(level))
    else:
        fp.set_reorder(int(level), reorder_ms)


def _parser():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fault", choices=["loss", "reorder", "jitter"], default="loss",
                    help="wire fault to sweep (default: loss)")
    ap.add_argument("--levels", default="0,1,5,10,12,15,20",
                    help="comma-separated fault levels (loss/reorder %% or jitter ms). "
                         "loss accepts fractional percents down to 0.0001")
    ap.add_argument("--reorder-ms", type=int, default=50,
                    help="hold-back delay for the reorder fault (ms)")
    ap.add_argument("--read-mib", type=int, default=32, help="read-test file size")
    ap.add_argument("--write-mib", type=int, default=8, help="write-test payload size")
    ap.add_argument("--reps", type=int, default=3, help="reps per level")
    ap.add_argument("--max-stall", type=int, default=30000,
                    help="XRDFS resilience window for the mount (ms)")
    ap.add_argument("--op-timeout", type=int, default=0,
                    help="per-op watchdog seconds (0=auto: 3x max-stall, min 90)")
    ap.add_argument("--gsi", action="store_true",
                    help="use the GSI nginx + X509 proxy env (default: anonymous)")
    return ap


def _check_binaries():
    if not os.path.isfile(XROOTDFS):
        sys.exit(f"xrootdfs not built: {XROOTDFS}  (make -C client xrootdfs)")
    if not os.path.isfile(servers.FAULT_PROXY):
        sys.exit(f"fault_proxy not built: {servers.FAULT_PROXY}")
    if not os.path.isfile(servers.NGINX_BIN):
        sys.exit(f"nginx not built: {servers.NGINX_BIN}")


def _run_settings(args):
    levels = [float(x) for x in args.levels.split(",") if x.strip() != ""]
    read_bytes = args.read_mib * 1024 * 1024
    write_payload = os.urandom(args.write_mib * 1024 * 1024)
    op_timeout = args.op_timeout or max(90, 3 * args.max_stall // 1000)
    unit = "ms" if args.fault == "jitter" else "%"
    return levels, read_bytes, write_payload, op_timeout, unit


def _server_context(args):
    if args.gsi:
        servers.ensure_pki()
        return servers.NginxGsi(), servers.gsi_env()
    mount_env = dict(os.environ)
    mount_env.pop("X509_USER_PROXY", None)
    mount_env.pop("LD_LIBRARY_PATH", None)
    return servers.NginxAnon(), mount_env


def _print_setup(args, levels, op_timeout, unit):
    auth = "GSI" if args.gsi else "anon"
    print(f"[setup] auth={auth}  fault={args.fault}  levels={levels}{unit}  "
          f"read={args.read_mib}MiB write={args.write_mib}MiB reps={args.reps}  "
          f"max-stall={args.max_stall}ms op-timeout={op_timeout}s")
    return auth


def _run_sweep(server_cm, args, settings, mount_env, auth):
    levels, read_bytes, write_payload, op_timeout, unit = settings
    rows = []
    with server_cm as nginx:
        print(f"[up] nginx {auth} :{nginx.port}")
        read_name = "/sw/read.bin"
        seeded = servers.seed_file(nginx.data, read_name, read_bytes)
        read_md5 = _md5_file(seeded)
        print(f"[seed] {args.read_mib}MiB read file (md5={read_md5[:12]}…)\n")

        for level in levels:
            for rep in range(1, args.reps + 1):
                rows.extend(run_one(nginx, args, level, rep, mount_env,
                                    write_payload, read_name, read_md5, read_bytes,
                                    op_timeout, unit))
    return rows


def main():
    args = _parser().parse_args()
    _check_binaries()
    settings = _run_settings(args)
    levels, _, _, op_timeout, unit = settings
    auth = _print_setup(args, levels, op_timeout, unit)
    server_cm, mount_env = _server_context(args)
    rows = _run_sweep(server_cm, args, settings, mount_env, auth)
    print_summary(rows, levels, args, unit)


def run_one(nginx, args, level, rep, mount_env, write_payload, read_name,
            read_md5, read_bytes, op_timeout, unit):
    """One (level, rep): clean mount → engage fault → write op → read op, each
    under a watchdog. Returns the write+read result rows."""
    tag = f"  {args.fault}={level:>7g}{unit} rep{rep}"
    with servers.FaultProxy(nginx.port) as fp:
        url = f"root://{HOST}:{fp.listen}/"
        mnt, proc = mount(url, args.max_stall, mount_env)
        if mnt is None:
            print(f"{tag}: MOUNT FAILED")
            return _mount_failure_rows(level, rep)

        apply_fault(fp, args.fault, level, args.reorder_ms)
        write, read, done = _run_mount_operations(
            mnt, nginx.data, write_payload, read_name, read_md5, read_bytes, op_timeout
        )
        fp.set_loss(0)  # clear before unmount
        unmount(mnt, proc, lazy=not all(done))

    _print_run_result(tag, write_payload, read_bytes, write, read)
    return _operation_rows(level, rep, write, read)


def _mount_failure_rows(level, rep):
    return [dict(level=level, rep=rep, op=op, ok=False, secs=0.0,
                 reason="mount-failed") for op in ("write", "read")]


def _timed_result(done, result, timeout):
    return result if done and result else (False, timeout, "watchdog-timeout")


def _run_mount_operations(mnt, data, payload, name, digest, size, timeout):
    w_done, w = with_timeout(lambda: write_roundtrip(mnt, data, payload), timeout)
    write = _timed_result(w_done, w, timeout)
    if not w_done:
        return write, (False, 0.0, "skipped-after-write-hang"), (w_done, True)
    r_done, r = with_timeout(lambda: read_roundtrip(mnt, name, digest, size), timeout)
    return write, _timed_result(r_done, r, timeout), (w_done, r_done)


def _throughput(byte_count, result):
    ok, seconds, _ = result
    return byte_count / seconds / 1e6 if ok and seconds > 0 else 0


def _print_run_result(tag, write_payload, read_bytes, write, read):
    w_ok, w_s, w_why = write
    r_ok, r_s, r_why = read
    w_mbps = _throughput(len(write_payload), write)
    r_mbps = _throughput(read_bytes, read)

    print(f"{tag}: "
          f"WRITE {'OK ' if w_ok else 'FAIL'} {w_s:7.2f}s {w_mbps:6.1f}MB/s ({w_why})  "
          f"READ {'OK ' if r_ok else 'FAIL'} {r_s:7.2f}s {r_mbps:6.1f}MB/s ({r_why})")


def _operation_rows(level, rep, write, read):
    return [_operation_row(level, rep, "write", write),
            _operation_row(level, rep, "read", read)]


def _operation_row(level, rep, operation, result):
    ok, seconds, reason = result
    return dict(level=level, rep=rep, op=operation, ok=ok,
                secs=round(seconds, 3), reason=reason)


def print_summary(rows, levels, args, unit):
    print(f"\n=== SUMMARY ({args.fault} sweep — byte-exact ok/N + median time/"
          f"throughput of SUCCESSFUL ops) ===")
    lvl_hdr = f"{args.fault}{unit}"
    hdr = f"{lvl_hdr:>9s} {'op':>5s} {'ok/N':>6s} {'med s':>8s} {'MB/s':>8s}"
    print(hdr)
    print("-" * len(hdr))
    sizes = {"write": args.write_mib * 1024 * 1024, "read": args.read_mib * 1024 * 1024}
    for level in levels:
        for op in ("write", "read"):
            _print_summary_cell(rows, level, op, sizes[op])


def _print_summary_cell(rows, level, operation, size):
    cell = list(filter(lambda row: _matches_cell(row, level, operation), rows))
    good = sorted(map(lambda row: row["secs"], filter(lambda row: row["ok"], cell)))
    if not good:
        print(f"{level:>9g} {operation:>5s} {0:3d}/{len(cell):<2d} {'-':>8s} {'-':>8s}")
        return
    median = good[len(good) // 2]
    speed = size / median / 1e6 if median > 0 else 0
    print(f"{level:>9g} {operation:>5s} {len(good):3d}/{len(cell):<2d} "
          f"{median:8.2f} {speed:8.1f}")


def _matches_cell(row, level, operation):
    return row["level"] == level and row["op"] == operation


if __name__ == "__main__":
    main()
