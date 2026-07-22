#!/usr/bin/env python3
"""
asan_tls_read_harness.py — drive the userspace-TLS (roots://) memory read path
under (optionally ASAN-instrumented) nginx, concurrently and through the fault
proxy's reorder lever, and fail if the bytes diverge OR AddressSanitizer reports
anything.

This is the verification rig for the read-pipelining work (#1 TLS single-chunk,
#4 produce-ahead, #2 multi-chunk/readv).  A roots:// read of a regular file takes
the memory-backed builder (brix_build_single_memory_chain / _chunked_chain) —
the path being made pipelinable — because sendfile is gated off for userspace TLS.

Usage:
  PYTHONPATH=tests python3 tests/resilience/asan_tls_read_harness.py \
      [--nginx /tmp/nginx-asan/objs/nginx] [--depth 8] [--size-mib 8] \
      [--concurrency 16] [--rounds 4] [--reorder 1.0] [--reorder-ms 50]
"""
import argparse
import concurrent.futures as cf
import hashlib
import os
import socket
import subprocess
import sys
import tempfile
import time

from config_templates import render_config

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import servers  # noqa: E402
from settings import BIND_HOST, HOST

XRDCP = os.path.join(servers.CLIENT_BIN, "xrdcp")
ASAN_MARKERS = ("AddressSanitizer", "runtime error:", "heap-use-after-free",
                "heap-buffer-overflow", "SUMMARY: AddressSanitizer", "LeakSanitizer")


def md5_file(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def free_port():
    s = socket.socket()
    s.bind((BIND_HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def tls_read(port, name, want, env, timeout=60, tls_flags=False):
    dst = tempfile.mktemp(suffix=".bin")
    if tls_flags:
        url = f"root://{HOST}:{port}/{name}"
        argv = [XRDCP, "--tls", "--noverifyhost", "-f", "-s", url, dst]
    else:
        url = f"roots://{HOST}:{port}/{name}"
        argv = [XRDCP, "-f", "-s", url, dst]
    try:
        r = subprocess.run(argv, env=env, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout)
        ok = (r.returncode == 0 and os.path.exists(dst)
              and md5_file(dst) == want)
        return ok, (r.stderr.decode(errors="replace")[-160:] if not ok else "")
    finally:
        try:
            os.unlink(dst)
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--nginx", default="/tmp/nginx-asan/objs/nginx")
    ap.add_argument("--depth", type=int, default=8)
    ap.add_argument("--size-mib", type=int, default=8)
    ap.add_argument("--concurrency", type=int, default=16)
    ap.add_argument("--rounds", type=int, default=4)
    ap.add_argument("--reorder", type=float, default=1.0,
                    help="reorder %% through the fault proxy (0 = direct, no proxy)")
    ap.add_argument("--reorder-ms", type=int, default=50)
    args = ap.parse_args()

    if not os.path.isfile(args.nginx):
        sys.exit(f"nginx not found: {args.nginx}")
    servers.ensure_pki()

    prefix = os.path.join(servers.PREFIX, "asan_tls")
    logs = os.path.join(prefix, "logs")
    data = os.path.join(prefix, "data")
    for d in (logs, data):
        os.makedirs(d, exist_ok=True)
    errlog = os.path.join(logs, "error.log")
    open(errlog, "w").close()                      # truncate

    port = free_port()
    conf = os.path.join(prefix, "nginx.conf")
    with open(conf, "w") as fh:
        fh.write(render_config(
            "nginx_resilience_asan_tls_read.conf",
            ERROR_LOG=errlog,
            LOG_DIR=logs,
            PORT=port,
            DATA_DIR=data,
            CERT_FILE=servers.SERVER_CERT,
            KEY_FILE=servers.SERVER_KEY,
            PIPELINE_DEPTH=args.depth,
        ))

    name = "/r.bin"
    src = os.path.join(data, "r.bin")
    subprocess.run(["dd", "if=/dev/urandom", f"of={src}", "bs=1M",
                    f"count={args.size_mib}"], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)
    want = md5_file(src)

    env = dict(os.environ)
    env.pop("LD_LIBRARY_PATH", None)
    env.pop("X509_USER_PROXY", None)
    env["X509_CERT_DIR"] = servers.CA_DIR

    nginx_env = dict(os.environ)
    nginx_env.pop("LD_LIBRARY_PATH", None)
    nginx_env["ASAN_OPTIONS"] = ("detect_leaks=0:abort_on_error=0:halt_on_error=0:"
                                 "print_stats=0:log_path=stderr")
    stderr_fh = open(os.path.join(logs, "nginx_stderr.log"), "w")
    proc = subprocess.Popen([args.nginx, "-p", prefix, "-c", "nginx.conf"],
                            stdout=stderr_fh, stderr=stderr_fh, env=nginx_env)
    for _ in range(80):
        try:
            socket.create_connection((HOST, port), timeout=0.3).close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        proc.kill()
        sys.exit("nginx (TLS) failed to come up")

    asan = "ASAN" if "address" in subprocess.run(
        [args.nginx, "-V"], capture_output=True).stderr.decode() else "release"
    print(f"[up] nginx({asan}) TLS :{port}  depth={args.depth}  "
          f"{args.size_mib}MiB  conc={args.concurrency} rounds={args.rounds}  "
          f"reorder={args.reorder}%/{args.reorder_ms}ms")

    fp = None
    target_port = port
    if args.reorder > 0:
        fp = servers.FaultProxy(port)
        fp.__enter__()
        fp.set_reorder(args.reorder, args.reorder_ms)
        target_port = fp.listen

    fails = 0
    total = 0
    t0 = time.monotonic()
    try:
        for rnd in range(1, args.rounds + 1):
            with cf.ThreadPoolExecutor(args.concurrency) as ex:
                futs = [ex.submit(tls_read, target_port, name, want, env)
                        for _ in range(args.concurrency)]
                for f in futs:
                    ok, err = f.result()
                    total += 1
                    if not ok:
                        fails += 1
                        if fails <= 3:
                            print(f"  [rnd {rnd}] READ FAIL: {err}")
            print(f"  round {rnd}/{args.rounds}: {args.concurrency} concurrent "
                  f"TLS reads done ({fails} fails so far)")
    finally:
        if fp is not None:
            fp.set_reorder(0)
            fp.__exit__(None, None, None)
        # Graceful stop so the worker flushes any ASAN report.
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        stderr_fh.close()

    elapsed = time.monotonic() - t0
    # Scan BOTH nginx logs for ASAN reports.
    san_hits = []
    for lf in (os.path.join(logs, "nginx_stderr.log"), errlog):
        try:
            with open(lf, errors="replace") as fh:
                for line in fh:
                    if any(m in line for m in ASAN_MARKERS):
                        san_hits.append(line.rstrip())
        except OSError:
            pass

    print(f"\n=== {total} TLS reads in {elapsed:.1f}s — byte-exact fails={fails}  "
          f"ASAN reports={len(san_hits)} ===")
    for h in san_hits[:12]:
        print("  SAN:", h)
    if fails == 0 and not san_hits:
        print("RESULT: PASS (byte-exact, zero ASAN reports)")
        sys.exit(0)
    print("RESULT: FAIL")
    sys.exit(1)


if __name__ == "__main__":
    main()
