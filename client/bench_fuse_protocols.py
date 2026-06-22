#!/usr/bin/env python3
"""
bench_fuse_protocols.py — compare xrootdfs read throughput: root:// vs http(s).

WHAT: Mounts the SAME file over each transport the async FUSE driver speaks
      (root://, http/WebDAV, https/XrdHttp) and measures sequential read
      throughput, reporting median/min/max MB/s per protocol plus an md5 check so a
      fast-but-wrong run can never look good.
WHY:  Answers "how does FUSE-over-root compare with FUSE-over-https?" for the same
      server and data — against this nginx module or an official XRootD endpoint.
HOW:  Each iteration mounts a FRESH mountpoint (so the FUSE/page cache is cold),
      times a full streamed read of the file, then unmounts. Throughput = size /
      wall-time. Nothing is written; mounts are always torn down.

Examples:
  # nginx module — both transports, same data dir
  ./bench_fuse_protocols.py med.bin \\
      --root  root://127.0.0.1:11294/ \\
      --http  http://127.0.0.1:18080/

  # official XRootD — root vs XrdHttp (self-signed → verify off by default)
  ./bench_fuse_protocols.py med.bin \\
      --root  root://127.0.0.1:12095/data \\
      --https https://127.0.0.1:12096/data \\
      --iters 5
"""
import argparse
import hashlib
import os
import statistics
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
XROOTDFS = os.path.join(HERE, "bin", "xrootdfs")
READ_CHUNK = 4 * 1024 * 1024


def _mount(url, extra):
    """Mount url at a fresh dir; return (proc, mountpoint) or raise on failure."""
    mnt = tempfile.mkdtemp(prefix="xrdbench.")
    argv = [XROOTDFS] + list(extra) + [url, mnt, "-f"]
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(100):
        if os.path.ismount(mnt):
            return proc, mnt
        if proc.poll() is not None:
            break
        time.sleep(0.05)
    err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
    proc.kill()
    try:
        os.rmdir(mnt)
    except OSError:
        pass
    raise RuntimeError(f"mount failed for {url}: {err.strip()}")


def _umount(proc, mnt):
    subprocess.run(["fusermount3", "-u", "-z", mnt], capture_output=True)
    try:
        proc.wait(timeout=10)
    except Exception:
        proc.kill()
    try:
        os.rmdir(mnt)
    except OSError:
        pass


def _timed_read(path):
    """Stream-read path; return (bytes, seconds, md5hex)."""
    h = hashlib.md5()
    total = 0
    t0 = time.perf_counter()
    with open(path, "rb", buffering=0) as f:
        while True:
            b = f.read(READ_CHUNK)
            if not b:
                break
            h.update(b)
            total += len(b)
    return total, time.perf_counter() - t0, h.hexdigest()


def bench_endpoint(name, url, extra, fname, iters):
    """Run `iters` cold-mount reads of fname; return a result dict (or None)."""
    rates, size, md5 = [], None, None
    for i in range(iters):
        try:
            proc, mnt = _mount(url, extra)
        except RuntimeError as e:
            print(f"  [{name}] {e}", file=sys.stderr)
            return None
        try:
            n, secs, digest = _timed_read(os.path.join(mnt, fname))
        except OSError as e:
            print(f"  [{name}] read error: {e}", file=sys.stderr)
            _umount(proc, mnt)
            return None
        finally:
            _umount(proc, mnt)
        if size is None:
            size, md5 = n, digest
        elif digest != md5:
            print(f"  [{name}] md5 MISMATCH across iterations!", file=sys.stderr)
            return None
        mbps = (n / (1024 * 1024)) / secs if secs > 0 else 0.0
        rates.append(mbps)
        print(f"  [{name}] iter {i + 1}/{iters}: {mbps:8.1f} MB/s "
              f"({n} bytes in {secs:.3f}s)")
    return {"name": name, "size": size, "md5": md5, "rates": rates}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", help="file path RELATIVE to the mount root, e.g. med.bin")
    ap.add_argument("--root", help="root:// endpoint URL")
    ap.add_argument("--http", help="http/WebDAV endpoint URL")
    ap.add_argument("--https", help="https/XrdHttp endpoint URL")
    ap.add_argument("--iters", type=int, default=3, help="iterations (default 3)")
    ap.add_argument("--verify", action="store_true",
                    help="verify the https server cert (default: off — test beds "
                         "use self-signed certs)")
    ap.add_argument("--token", help="bearer token for http(s)")
    ap.add_argument("--readahead", help="--readahead bytes passed to the driver")
    args = ap.parse_args()

    if not os.path.exists(XROOTDFS):
        sys.exit(f"missing {XROOTDFS} (run `make -C {HERE} xrootdfs`)")

    common = []
    if args.readahead:
        common += ["--readahead", args.readahead]
    web_extra = list(common)
    if args.token:
        web_extra += ["--token", args.token]
    https_extra = list(web_extra)
    if not args.verify:
        https_extra += ["--noverifyhost"]

    plan = []
    if args.root:
        plan.append(("root", args.root, common))
    if args.http:
        plan.append(("http", args.http, web_extra))
    if args.https:
        plan.append(("https", args.https, https_extra))
    if not plan:
        sys.exit("specify at least one of --root / --http / --https")

    results = []
    for name, url, extra in plan:
        print(f"\n== {name}: {url} ==")
        r = bench_endpoint(name, url, extra, args.file, args.iters)
        if r:
            results.append(r)

    if not results:
        sys.exit("no endpoint produced a result")

    md5s = {r["md5"] for r in results}
    print("\n===== summary =====")
    print(f"file={args.file}  size={results[0]['size']} bytes  iters={args.iters}")
    print(f"cross-protocol bytes identical: {'YES' if len(md5s) == 1 else 'NO (!)'}")
    print(f"{'proto':<8}{'median':>10}{'min':>10}{'max':>10}   (MB/s)")
    for r in results:
        rr = r["rates"]
        print(f"{r['name']:<8}{statistics.median(rr):>10.1f}"
              f"{min(rr):>10.1f}{max(rr):>10.1f}")
    if len(results) >= 2:
        base = results[0]
        bmed = statistics.median(base["rates"])
        for r in results[1:]:
            rmed = statistics.median(r["rates"])
            if bmed > 0:
                print(f"{r['name']} vs {base['name']}: "
                      f"{rmed / bmed:.2f}× throughput")


if __name__ == "__main__":
    main()
