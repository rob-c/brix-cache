#!/usr/bin/env python3
"""
tools/diag/storm_ab_bench.py — interleaved A/B storm benchmark: BriX vs the
official XRootD daemon, on identical payloads, at ultra-parallel widths.

WHY interleaved: the ultra-parallel storm suite showed run-to-run swings
larger than the effects worth optimizing (one 16k rung had BriX 15% behind,
the next had it 40% ahead — same tree, same host).  A ladder that runs all
of A then all of B attributes host noise to the server.  This rig alternates
A/B/A/B... within one process, one round at a time, and reports the MEDIAN
over rounds, so drift and background load hit both servers equally.

Workload: the FTS-DoS shape the storm tests use — n clients released on one
barrier, 1 in `--transfer-every` running a full transfer (connect, handshake,
login, stat, open, read, close), the rest r/o metadata loops.

Usage (from the repo root):
  python3 tools/diag/storm_ab_bench.py --width 4096 --rounds 5
  python3 tools/diag/storm_ab_bench.py --width 16384 --rounds 3 --meta-only
  python3 tools/diag/storm_ab_bench.py --width 1024 --rounds 7 --json out.json

Both servers are started and torn down by this script on free ports.  The
BriX subject mirrors tests/configs/nginx_lc_ultra_parallel.conf.
"""

import argparse
import json
import os
import pathlib
import random
import resource
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests"))

HOST = "127.0.0.1"
NGINX_BIN = os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
XROOTD = shutil.which("xrootd")

kXR_close, kXR_login = 3003, 3007
kXR_open, kXR_read, kXR_stat = 3010, 3013, 3017
kXR_ok, kXR_oksofar, kXR_wait = 0, 4000, 4005

OP_TIMEOUT = 20.0
STACK = 512 * 1024


# --------------------------------------------------------------------------- #
# Wire                                                                         #
# --------------------------------------------------------------------------- #

class Failed(Exception):
    pass


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise Failed("closed mid-frame")
        buf += chunk
    return buf


def _send(s, streamid, reqid, body=b"", payload=b""):
    hdr = streamid + struct.pack("!H", reqid)
    hdr += body.ljust(16, b"\x00") + struct.pack("!I", len(payload))
    s.sendall(hdr + payload)


def _resp(s):
    hdr = _recv_exact(s, 8)
    status = struct.unpack("!H", hdr[2:4])[0]
    dlen = struct.unpack("!I", hdr[4:8])[0]
    body = _recv_exact(s, dlen) if dlen else b""
    if status == kXR_wait:
        raise Failed("kXR_wait")
    return status, body


def _ok(s, what):
    status, body = _resp(s)
    if status not in (kXR_ok, kXR_oksofar):
        raise Failed(f"{what}: status {status}")
    return status, body


def _login(port, src):
    s = socket.create_connection((HOST, port), timeout=OP_TIMEOUT,
                                 source_address=(src, 0) if src else None)
    s.settimeout(OP_TIMEOUT)
    s.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    _ok(s, "handshake")
    _send(s, b"\x00\x01", kXR_login, body=b"\x00" * 13 + b"\x04\x00\x00",
          payload=b"anonymous\x00")
    _ok(s, "login")
    return s


def _stat(s, path):
    _send(s, b"\x00\x04", kXR_stat, body=b"\x00" * 16,
          payload=path.encode() + b"\x00")
    _ok(s, "stat")


def _read_file(s, path, size):
    _send(s, b"\x00\x01", kXR_open,
          body=struct.pack("!HH", 0, 0) + b"\x00" * 12,
          payload=path.encode() + b"\x00")
    _st, body = _ok(s, "open")
    fh = body[:4]
    _send(s, b"\x00\x02", kXR_read, body=fh + struct.pack("!qi", 0, size))
    got = 0
    while True:
        status, chunk = _ok(s, "read")
        got += len(chunk)
        if status == kXR_ok:
            break
    if got != size:
        raise Failed(f"short read {got}/{size}")
    _send(s, b"\x00\x03", kXR_close, body=fh)
    _ok(s, "close")


def _job(port, idx, cfg):
    src = f"127.0.0.{2 + idx % 8}" if cfg["spread"] else None
    s = _login(port, src)
    try:
        if not cfg["meta_only"] and idx % cfg["transfer_every"] == 0:
            _stat(s, "/bench.bin")
            _read_file(s, "/bench.bin", cfg["size"])
        else:
            for _ in range(cfg["meta_ops"]):
                _stat(s, "/bench.bin")
                _stat(s, "/")
    finally:
        s.close()


# --------------------------------------------------------------------------- #
# One storm round                                                              #
# --------------------------------------------------------------------------- #

def _worker(port, barrier, out, slot, ident, cfg):
    """`slot` indexes this shard's result array; `ident` is the client's
    GLOBAL identity (it selects the source address and the job shape), so a
    sharded storm keeps the same mix as an unsharded one."""
    try:
        barrier.wait(timeout=300)
    except threading.BrokenBarrierError:
        pass
    started = time.perf_counter()
    try:
        _job(port, ident, cfg)
        out[slot] = time.perf_counter() - started
    except (Failed, OSError) as exc:
        out[slot] = f"ERR {type(exc).__name__}: {exc}"


def _is_latency(value):
    return isinstance(value, float)


def _is_error(value):
    return isinstance(value, str)


def _thread_round(port, width, cfg, base=0):
    """One barrier-released storm inside THIS process."""
    out = [None] * width
    barrier = threading.Barrier(width)
    old = threading.stack_size(STACK)
    threads = []
    try:
        for i in range(width):
            t = threading.Thread(target=_worker, daemon=True,
                                 args=(port, barrier, out, i, base + i, cfg))
            t.start()
            threads.append(t)
    finally:
        threading.stack_size(old)
    started = time.perf_counter()
    for t in threads:
        t.join(timeout=OP_TIMEOUT * 3 + 300)
    wall = time.perf_counter() - started
    lat = list(filter(_is_latency, out))
    err = list(filter(_is_error, out))
    return wall, lat, err


def _proc_entry(port, width, cfg, base, gate, conn):
    """Child-process storm shard: wait on the cross-process gate, then run."""
    try:
        gate.wait(timeout=300)
    except Exception:                                  # noqa: BLE001 - broken
        pass                                           # gate; storm anyway
    wall, lat, err = _thread_round(port, width, cfg, base)
    conn.send((wall, lat, err))
    conn.close()


def _process_shard_width(width, procs, index):
    count = width // procs
    if index == procs - 1:
        count += width % procs
    return count


def _start_process_shard(port, width, cfg, procs, index, ctx, gate):
    count = _process_shard_width(width, procs, index)
    base = index * (width // procs)
    parent_conn, child_conn = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=_proc_entry,
                       args=(port, count, cfg, base, gate, child_conn))
    proc.start()
    child_conn.close()
    return proc, parent_conn


def _start_process_shards(port, width, cfg, procs, ctx):
    gate = ctx.Barrier(procs)
    started = [_start_process_shard(port, width, cfg, procs, index, ctx, gate)
               for index in range(procs)]
    children = [item[0] for item in started]
    pipes = [item[1] for item in started]
    return children, pipes


def _receive_process_shard(conn, proc, walls, latencies, errors):
    try:
        wall, shard_latencies, shard_errors = conn.recv()
        walls.append(wall)
        latencies.extend(shard_latencies)
        errors.extend(shard_errors)
    except EOFError:
        errors.append("ERR child died")
    proc.join(timeout=OP_TIMEOUT * 3 + 300)


def _collect_process_shards(children, pipes):
    walls, latencies, errors = [], [], []
    for conn, proc in zip(pipes, children):
        _receive_process_shard(conn, proc, walls, latencies, errors)
    return latencies, errors


def _round(port, width, cfg, procs=1):
    """One barrier-released storm; returns (wall, latencies, errors).

    With procs>1 the storm is sharded over child PROCESSES (each running its
    own thread fan-out behind a shared cross-process gate) — a single CPython
    process saturates its GIL around ~220 jobs/s, which is below both
    servers' capacity, so a single-process client measures the client."""
    if procs <= 1:
        return _thread_round(port, width, cfg)

    import multiprocessing as mp

    ctx = mp.get_context("fork")
    children, pipes = _start_process_shards(port, width, cfg, procs, ctx)
    started = time.perf_counter()
    latencies, errors = _collect_process_shards(children, pipes)
    return time.perf_counter() - started, latencies, errors


def _pct(vals, q):
    if not vals:
        return 0.0
    ordered = sorted(vals)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))]


# --------------------------------------------------------------------------- #
# Subjects                                                                     #
# --------------------------------------------------------------------------- #

def _proc_tree_cpu(root_pid):
    """utime+stime in seconds for a pid and its children, from /proc.  This is
    the load-INDEPENDENT metric: wall-clock rates on a contended host measure
    the host, but CPU-seconds-per-job measures the server's own code."""
    total, ticks = 0.0, os.sysconf("SC_CLK_TCK")
    pids = [root_pid]
    seen = set()
    while pids:
        pid = pids.pop()
        if pid in seen:
            continue
        seen.add(pid)
        try:
            fields = pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(
                ") ", 1)[1].split()
            total += (int(fields[11]) + int(fields[12])) / ticks
            children = pathlib.Path(
                f"/proc/{pid}/task/{pid}/children").read_text().split()
            pids.extend(int(c) for c in children)
        except (OSError, IndexError, ValueError):
            continue
    return total


def _server_pid(handle):
    if handle[0] == "brix":
        _kind, root, _conf = handle
        try:
            return int((root / "logs" / "nginx.pid").read_text().strip())
        except (OSError, ValueError):
            return None
    return handle[1].pid


def _free_port():
    s = socket.socket()
    s.bind((HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _seed(root, size):
    data = root / "data"
    data.mkdir(parents=True, exist_ok=True)
    (data / "bench.bin").write_bytes(random.Random(0xF75).randbytes(size))
    return data


def _start_brix(root, size, workers=2, reuseport=True, attempts=5,
                session_slots=0):
    """`session_slots` overrides brix_session_slots (0 = compiled default,
    1024).  The registry is scanned linearly under one cross-worker mutex on
    every login AND every disconnect, so its capacity relative to the storm
    width is a first-order term in admission cost — the knob exists to
    measure that, not to hide it."""
    data = _seed(root, size)
    logs = root / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    slots = f"    brix_session_slots {session_slots};\n" if session_slots else ""
    for attempt in range(attempts):
        port = _free_port()
        conf = root / "nginx.conf"
        conf.write_text(
            f"worker_processes {workers};\n"
            "worker_rlimit_nofile 65536;\n"
            "daemon on;\n"
            f"error_log {logs}/error.log error;\n"
            f"pid {logs}/nginx.pid;\n"
            "events { worker_connections 16384; multi_accept on; }\n"
            "stream {\n"
            "  server {\n"
            f"    listen {HOST}:{port}"
            f"{' reuseport' if reuseport else ''} backlog=16384;\n"
            "    brix_root on;\n"
            f"    brix_storage_backend posix:{data};\n"
            "    brix_auth none;\n"
            f"{slots}"
            "  }\n"
            "}\n")
        res = subprocess.run([NGINX_BIN, "-p", str(root), "-c", str(conf)],
                             capture_output=True, text=True)
        if res.returncode == 0 and _await(port, timeout=15):
            return port, ("brix", root, conf)
        _stop(("brix", root, conf))
        print(f"  [brix port {port} unusable, retry {attempt + 1}]",
              flush=True)
    raise SystemExit(f"nginx would not bind in {attempts} attempts")


def _start_stock(root, size, attempts=5):
    """Start the official daemon, retrying the port: _free_port() only proves
    a port was free a moment ago, and on a busy host something else can claim
    it before xrootd binds."""
    data = _seed(root, size)
    admin = root / "admin"
    admin.mkdir(exist_ok=True)
    for attempt in range(attempts):
        port = _free_port()
        cfg = root / "xrootd.cfg"
        cfg.write_text(f"xrd.port {port}\nall.adminpath {admin}\n"
                       f"all.pidpath {admin}\noss.localroot {data}\n"
                       f"all.export /\nxrd.network nodnr\n")
        log = root / "xrootd.log"
        proc = subprocess.Popen([XROOTD, "-c", str(cfg), "-l", str(log)],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        if _await(port, timeout=15):
            return port, ("stock", proc)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        print(f"  [stock port {port} unusable, retry {attempt + 1}]",
              flush=True)
    raise SystemExit(f"official xrootd would not bind in {attempts} attempts")


def _stop(handle):
    if handle[0] == "brix":
        _kind, root, conf = handle
        subprocess.run([NGINX_BIN, "-p", str(root), "-c", str(conf),
                        "-s", "quit"], capture_output=True)
    else:
        proc = handle[1]
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _await(port, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _login(port, None).close()
            return True
        except OSError:
            time.sleep(0.2)
        except Failed:
            time.sleep(0.2)
    return False


# --------------------------------------------------------------------------- #
# Driver                                                                       #
# --------------------------------------------------------------------------- #

def _round_values(rounds, key):
    return [round_result[key] for round_result in rounds]


def _report(name, rounds):
    walls = _round_values(rounds, "wall")
    p50s = _round_values(rounds, "p50")
    p99s = _round_values(rounds, "p99")
    errors = sum(_round_values(rounds, "errors"))
    width = rounds[0]["width"]
    rates = [width / wall for wall in walls]
    cpu_costs = _round_values(rounds, "cpu_ms_per_job")
    rate = statistics.median(rates)
    return {"name": name, "rate": rate, "wall": statistics.median(walls),
            "p50": statistics.median(p50s) * 1000,
            "p99": statistics.median(p99s) * 1000,
            "cpu_ms_per_job": statistics.median(cpu_costs),
            "errors": errors, "walls": walls}


def _parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--width", type=int, default=4096)
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--size", type=int, default=64 << 10)
    ap.add_argument("--transfer-every", type=int, default=4)
    ap.add_argument("--meta-ops", type=int, default=3)
    ap.add_argument("--meta-only", action="store_true")
    ap.add_argument("--client-procs", type=int, default=1,
                    help="shard the storm over N client PROCESSES; 1 keeps "
                         "the single-process (GIL-bound ~220 jobs/s) client")
    ap.add_argument("--workers", default="2",
                    help="nginx worker_processes (int or 'auto'); the "
                         "official daemon threads across every core, so a "
                         "fair whole-box comparison wants 'auto'")
    ap.add_argument("--no-spread", action="store_true")
    ap.add_argument("--no-reuseport", action="store_true",
                    help="drop `reuseport` from the BriX listener: the "
                         "kernel then wakes workers by demand instead of "
                         "hashing each connection to a worker at SYN time")
    ap.add_argument("--session-slots", type=int, default=0,
                    help="brix_session_slots for the BriX subject; 0 keeps "
                         "the compiled default of 1024.  Below the storm "
                         "width the registry saturates and every login pays "
                         "a full failing scan under the cross-worker mutex")
    ap.add_argument("--json")
    return ap.parse_args()


def _cpu_delta(pid, before):
    if pid is None:
        return 0.0
    return _proc_tree_cpu(pid) - before


def _round_result(args, cfg, port, pid):
    cpu_before = _proc_tree_cpu(pid) if pid is not None else 0.0
    wall, latencies, errors = _round(
        port, args.width, cfg, args.client_procs)
    cpu = _cpu_delta(pid, cpu_before)
    return {
        "width": args.width,
        "wall": wall,
        "p50": _pct(latencies, 0.5),
        "p99": _pct(latencies, 0.99),
        "errors": len(errors),
        "sample_err": errors[:2],
        "cpu_ms_per_job": cpu * 1000 / args.width,
    }


def _print_round(round_number, width, row):
    print(f"{round_number:>5} {width / row['brix']['wall']:>9.1f} "
          f"{row['brix']['p99'] * 1000:>9.1f} "
          f"{row['brix']['cpu_ms_per_job']:>9.3f} "
          f"{width / row['stock']['wall']:>10.1f} "
          f"{row['stock']['p99'] * 1000:>10.1f} "
          f"{row['stock']['cpu_ms_per_job']:>10.3f}", flush=True)


def _run_rounds(args, cfg, subjects):
    per_side = {"brix": [], "stock": []}
    pids = {name: _server_pid(handle) for name, _port, handle in subjects}
    for round_number in range(args.rounds):
        row = {}
        for name, port, _handle in subjects:
            row[name] = _round_result(args, cfg, port, pids[name])
            per_side[name].append(row[name])
            time.sleep(1.0)
        _print_round(round_number, args.width, row)
    return per_side


def _print_header(args):
    shape = ("metadata-only" if args.meta_only
             else f"mixed 1-in-{args.transfer_every} transfers "
                  f"({args.size >> 10}KiB)")
    print(f"interleaved A/B: width={args.width} rounds={args.rounds} "
          f"{shape} brix_workers={args.workers} "
          f"client_procs={args.client_procs}", flush=True)
    print(f"{'round':>5} {'brix j/s':>9} {'brix p99':>9} "
          f"{'brixCPU':>9} {'stock j/s':>10} {'stock p99':>10} "
          f"{'stockCPU':>10}   (CPU = server ms/job)", flush=True)


def _summary_reports(per_side):
    return {name: _report(name, per_side[name])
            for name in ("brix", "stock")}


def _print_report_table(result):
    print(f"\n{'':<8}{'jobs/s':>9}{'p50 ms':>9}{'p99 ms':>9}"
          f"{'CPU ms/job':>12}{'errors':>8}   (median of rounds)")
    for name in ("brix", "stock"):
        report = result[name]
        print(f"{name:<8}{report['rate']:>9.1f}{report['p50']:>9.1f}"
              f"{report['p99']:>9.1f}{report['cpu_ms_per_job']:>12.3f}"
              f"{report['errors']:>8}")


def _print_throughput_ratio(result):
    speedup = result["brix"]["rate"] / result["stock"]["rate"]
    leader = "BriX ahead" if speedup > 1 else "official ahead"
    print(f"\nBriX / official throughput ratio: {speedup:.3f}x ({leader})")


def _print_cpu_ratio(result):
    brix_cpu = result["brix"]["cpu_ms_per_job"]
    stock_cpu = result["stock"]["cpu_ms_per_job"]
    if not brix_cpu or not stock_cpu:
        return
    efficiency = stock_cpu / brix_cpu
    leader = "BriX cheaper" if efficiency > 1 else "official cheaper"
    print(f"BriX / official CPU efficiency:   {efficiency:.3f}x "
          f"({leader}) — load-independent")


def _write_summary_json(args, result, per_side):
    if not args.json:
        return
    payload = {"args": vars(args), "result": result, "rounds": per_side}
    pathlib.Path(args.json).write_text(json.dumps(payload, indent=2))
    print(f"wrote {args.json}")


def _print_summary(args, per_side):
    result = _summary_reports(per_side)
    _print_report_table(result)
    _print_throughput_ratio(result)
    _print_cpu_ratio(result)
    _write_summary_json(args, result, per_side)


def main():
    args = _parse_args()

    if XROOTD is None:
        raise SystemExit("official `xrootd` not installed")
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE,
                       (min(max(args.width + 4096, soft), hard), hard))

    cfg = {"transfer_every": args.transfer_every, "meta_ops": args.meta_ops,
           "meta_only": args.meta_only, "size": args.size,
           "spread": not args.no_spread}

    tmp = pathlib.Path(tempfile.mkdtemp(prefix="storm-ab-"))
    brix_port, brix_h = _start_brix(tmp / "brix", args.size, args.workers,
                                    not args.no_reuseport,
                                    session_slots=args.session_slots)
    stock_port, stock_h = _start_stock(tmp / "stock", args.size)
    subjects = (("brix", brix_port, brix_h),
                ("stock", stock_port, stock_h))
    try:
        _print_header(args)
        per_side = _run_rounds(args, cfg, subjects)
    finally:
        _stop(brix_h)
        _stop(stock_h)
    _print_summary(args, per_side)


if __name__ == "__main__":
    main()
