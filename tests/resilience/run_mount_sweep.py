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

HOW:  client (FUSE) -> brix-fault-proxy(<fault>) -> nginx (root://), on dedicated ports
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


def main():
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
    args = ap.parse_args()

    if not os.path.isfile(XROOTDFS):
        sys.exit(f"xrootdfs not built: {XROOTDFS}  (make -C client xrootdfs)")
    if not os.path.isfile(servers.FAULT_PROXY):
        sys.exit(f"brix-fault-proxy not built: {servers.FAULT_PROXY}")
    if not os.path.isfile(servers.NGINX_BIN):
        sys.exit(f"nginx not built: {servers.NGINX_BIN}")

    levels = [float(x) for x in args.levels.split(",") if x.strip() != ""]
    read_bytes = args.read_mib * 1024 * 1024
    write_payload = os.urandom(args.write_mib * 1024 * 1024)
    read_name = "/sw/read.bin"
    op_timeout = args.op_timeout or max(90, 3 * args.max_stall // 1000)
    unit = "ms" if args.fault == "jitter" else "%"

    auth = "GSI" if args.gsi else "anon"
    print(f"[setup] auth={auth}  fault={args.fault}  levels={levels}{unit}  "
          f"read={args.read_mib}MiB write={args.write_mib}MiB reps={args.reps}  "
          f"max-stall={args.max_stall}ms op-timeout={op_timeout}s")

    if args.gsi:
        servers.ensure_pki()
        server_cm = servers.NginxGsi()
        mount_env = servers.gsi_env()
    else:
        server_cm = servers.NginxAnon()
        mount_env = dict(os.environ)
        mount_env.pop("X509_USER_PROXY", None)
        mount_env.pop("LD_LIBRARY_PATH", None)

    rows = []
    with server_cm as nginx:
        print(f"[up] nginx {auth} :{nginx.port}")
        seeded = servers.seed_file(nginx.data, read_name, read_bytes)
        read_md5 = _md5_file(seeded)
        print(f"[seed] {args.read_mib}MiB read file (md5={read_md5[:12]}…)\n")

        for level in levels:
            for rep in range(1, args.reps + 1):
                rows.extend(run_one(nginx, args, level, rep, mount_env,
                                    write_payload, read_name, read_md5, read_bytes,
                                    op_timeout, unit))

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
            return [dict(level=level, rep=rep, op=op, ok=False, secs=0.0,
                         reason="mount-failed") for op in ("write", "read")]

        apply_fault(fp, args.fault, level, args.reorder_ms)

        w_done, w = with_timeout(
            lambda: write_roundtrip(mnt, nginx.data, write_payload), op_timeout)
        w_ok, w_s, w_why = w if (w_done and w) else (False, op_timeout, "watchdog-timeout")

        if w_done:
            r_done, r = with_timeout(
                lambda: read_roundtrip(mnt, read_name, read_md5, read_bytes),
                op_timeout)
            r_ok, r_s, r_why = r if (r_done and r) else (False, op_timeout, "watchdog-timeout")
        else:
            r_ok, r_s, r_why = (False, 0.0, "skipped-after-write-hang")
            r_done = True

        fp.set_loss(0)  # clear before unmount
        unmount(mnt, proc, lazy=not (w_done and r_done))

    w_mbps = (len(write_payload) / w_s / 1e6) if w_ok and w_s > 0 else 0
    r_mbps = (read_bytes / r_s / 1e6) if r_ok and r_s > 0 else 0
    print(f"{tag}: "
          f"WRITE {'OK ' if w_ok else 'FAIL'} {w_s:7.2f}s {w_mbps:6.1f}MB/s ({w_why})  "
          f"READ {'OK ' if r_ok else 'FAIL'} {r_s:7.2f}s {r_mbps:6.1f}MB/s ({r_why})")
    return [dict(level=level, rep=rep, op="write", ok=w_ok, secs=round(w_s, 3),
                 reason=w_why),
            dict(level=level, rep=rep, op="read", ok=r_ok, secs=round(r_s, 3),
                 reason=r_why)]


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
            cell = [r for r in rows if r["level"] == level and r["op"] == op]
            good = sorted(r["secs"] for r in cell if r["ok"])
            okn = len(good)
            if good:
                med = good[len(good) // 2]
                mbps = sizes[op] / med / 1e6 if med > 0 else 0
                print(f"{level:>9g} {op:>5s} {okn:3d}/{len(cell):<2d} {med:8.2f} {mbps:8.1f}")
            else:
                print(f"{level:>9g} {op:>5s} {okn:3d}/{len(cell):<2d} {'-':>8s} {'-':>8s}")


if __name__ == "__main__":
    main()
