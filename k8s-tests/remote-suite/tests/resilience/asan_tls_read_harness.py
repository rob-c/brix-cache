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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import servers  # noqa: E402

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
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def tls_read(port, name, want, env, timeout=60, tls_flags=False):
    dst = tempfile.mktemp(suffix=".bin")
    if tls_flags:
        url = f"root://127.0.0.1:{port}/{name}"
        argv = [XRDCP, "--tls", "--noverifyhost", "-f", "-s", url, dst]
    else:
        url = f"roots://127.0.0.1:{port}/{name}"
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
    args = _parse_args()
    if not os.path.isfile(args.nginx):
        sys.exit(f"nginx not found: {args.nginx}")
    servers.ensure_pki()
    prefix, logs, data, errlog = _prepare_run_paths()
    port = free_port()
    _write_nginx_config(args, prefix, logs, data, errlog, port)
    want = _create_source(args, data)
    env = _client_environment()
    proc, stderr_fh = _start_nginx(args, prefix, logs)
    _wait_for_nginx(proc, port)
    _print_run_header(args, port)
    proxy, target_port = _start_proxy(args, port)
    try:
        fails, total, elapsed = _run_reads(args, target_port, want, env)
    finally:
        _stop_run(proxy, proc, stderr_fh)
    san_hits = _sanitizer_hits(logs, errlog)
    sys.exit(_report(total, elapsed, fails, san_hits))


def _parse_args():
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
    return ap.parse_args()


def _prepare_run_paths():
    prefix = os.path.join(servers.PREFIX, "asan_tls")
    logs = os.path.join(prefix, "logs")
    data = os.path.join(prefix, "data")
    for d in (logs, data):
        os.makedirs(d, exist_ok=True)
    errlog = os.path.join(logs, "error.log")
    open(errlog, "w").close()                      # truncate
    return prefix, logs, data, errlog


def _write_nginx_config(args, prefix, logs, data, errlog, port):
    conf = os.path.join(prefix, "nginx.conf")
    with open(conf, "w") as fh:
        fh.write(f"""worker_processes 1; daemon off;
error_log {errlog} info; pid {logs}/nginx.pid;
events {{ worker_connections 2048; }}
stream {{ server {{ listen 127.0.0.1:{port}; brix_root on; brix_storage_backend posix:{data};
  brix_auth none; brix_allow_write on;
  brix_tls on; brix_certificate {servers.SERVER_CERT};
  brix_certificate_key {servers.SERVER_KEY};
  brix_pipeline_depth {args.depth}; }} }}""")


def _create_source(args, data):
    src = os.path.join(data, "r.bin")
    subprocess.run(["dd", "if=/dev/urandom", f"of={src}", "bs=1M",
                    f"count={args.size_mib}"], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)
    return md5_file(src)


def _client_environment():
    env = dict(os.environ)
    env.pop("LD_LIBRARY_PATH", None)
    env.pop("X509_USER_PROXY", None)
    env["X509_CERT_DIR"] = servers.CA_DIR
    return env


def _start_nginx(args, prefix, logs):
    nginx_env = dict(os.environ)
    nginx_env.pop("LD_LIBRARY_PATH", None)
    nginx_env["ASAN_OPTIONS"] = ("detect_leaks=0:abort_on_error=0:halt_on_error=0:"
                                 "print_stats=0:log_path=stderr")
    stderr_fh = open(os.path.join(logs, "nginx_stderr.log"), "w")
    proc = subprocess.Popen([args.nginx, "-p", prefix, "-c", "nginx.conf"],
                            stdout=stderr_fh, stderr=stderr_fh, env=nginx_env)
    return proc, stderr_fh


def _wait_for_nginx(proc, port):
    for _ in range(80):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        proc.kill()
        sys.exit("nginx (TLS) failed to come up")


def _print_run_header(args, port):
    asan = "ASAN" if "address" in subprocess.run(
        [args.nginx, "-V"], capture_output=True).stderr.decode() else "release"
    print(f"[up] nginx({asan}) TLS :{port}  depth={args.depth}  "
          f"{args.size_mib}MiB  conc={args.concurrency} rounds={args.rounds}  "
          f"reorder={args.reorder}%/{args.reorder_ms}ms")


def _start_proxy(args, port):
    if args.reorder > 0:
        proxy = servers.FaultProxy(port)
        proxy.__enter__()
        proxy.set_reorder(args.reorder, args.reorder_ms)
        return proxy, proxy.listen
    return None, port


def _run_reads(args, target_port, want, env):
    fails = 0
    total = 0
    t0 = time.monotonic()
    for rnd in range(1, args.rounds + 1):
        round_fails = _run_read_round(args, target_port, want, env, rnd)
        fails += round_fails
        total += args.concurrency
        print(f"  round {rnd}/{args.rounds}: {args.concurrency} concurrent "
              f"TLS reads done ({fails} fails so far)")
    return fails, total, time.monotonic() - t0


def _run_read_round(args, target_port, want, env, round_number):
    with cf.ThreadPoolExecutor(args.concurrency) as executor:
        futures = [executor.submit(tls_read, target_port, "/r.bin", want, env)
                   for _ in range(args.concurrency)]
        failures = _read_failures(futures)
    for error in failures[:3]:
        print(f"  [rnd {round_number}] READ FAIL: {error}")
    return len(failures)


def _read_failures(futures):
    return [error for ok, error in (future.result() for future in futures)
            if not ok]


def _stop_run(proxy, proc, stderr_fh):
    if proxy is not None:
        proxy.set_reorder(0)
        proxy.__exit__(None, None, None)
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    stderr_fh.close()


def _sanitizer_hits(logs, errlog):
    hits = []
    for lf in (os.path.join(logs, "nginx_stderr.log"), errlog):
        hits.extend(_sanitizer_hits_in(lf))
    return hits


def _sanitizer_hits_in(path):
    hits = []
    try:
        with open(path, errors="replace") as fh:
            for line in fh:
                if any(marker in line for marker in ASAN_MARKERS):
                    hits.append(line.rstrip())
    except OSError:
        pass
    return hits


def _report(total, elapsed, fails, san_hits):
    print(f"\n=== {total} TLS reads in {elapsed:.1f}s — byte-exact fails={fails}  "
          f"ASAN reports={len(san_hits)} ===")
    for hit in san_hits[:12]:
        print("  SAN:", hit)
    if fails == 0 and not san_hits:
        print("RESULT: PASS (byte-exact, zero ASAN reports)")
        return 0
    print("RESULT: FAIL")
    return 1


if __name__ == "__main__":
    main()
