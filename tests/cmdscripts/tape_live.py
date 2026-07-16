"""Direct Python ports for the tape/nearline live shell scenarios.

Ports ``run_tape_recall_stream.sh``, ``run_tape_recall_async.sh``,
``run_tape_exec_adapter.sh``, and ``run_s3_tape_residency.sh``.  Each public
scenario keeps its shell test's own acceptance sequence and assertions; ports
are allocated dynamically instead of the scripts' fixed literals.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import stat as stat_mod
import sys
import time

from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT, random_file, sha256
from settings import free_ports

XRDFS = REPO_ROOT / "client/bin/xrdfs"

CLIENT_REQUIREMENTS = {
    "tape-recall-stream": (XRDFS,),
    "tape-recall-async": (),
    "tape-exec-adapter": (),
    "s3-tape-residency": (),
}

# The operator stagecmd: a real-MSS stand-in backed by a local tape dir.
# Same contract as the shell fixture ($BRIX_FRM_STAGECMD <verb> <key> <online>):
# exists -> residency probe, recall -> async submit (backgrounded copy after a
# latency), migrate -> synchronous copy online->tape.
_STAGECMD = """#!{python}
import os, shutil, subprocess, sys, time

TAPE = {tape!r}
DELAY_S = {delay!r}

verb = sys.argv[1] if len(sys.argv) > 1 else ""
key = sys.argv[2] if len(sys.argv) > 2 else ""
online = sys.argv[3] if len(sys.argv) > 3 else ""
src = os.path.join(TAPE, key.lstrip("/"))

if verb == "exists":
    sys.exit(0 if os.path.isfile(src) else 1)
if verb == "recall":
    subprocess.Popen([sys.executable, __file__, "recall-worker", key, online],
                     start_new_session=True)
    sys.exit(0)
if verb == "recall-worker":
    time.sleep(DELAY_S)
    os.makedirs(os.path.dirname(online) or ".", exist_ok=True)
    shutil.copyfile(src, online)
    sys.exit(0)
if verb == "migrate":
    os.makedirs(os.path.dirname(src) or ".", exist_ok=True)
    shutil.copyfile(online, src)
    sys.exit(0)
sys.exit(2)
"""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _checks(values: list[tuple[bool, str]]) -> int:
    for passed, text in values:
        print(f"  {'ok  ' if passed else 'FAIL'} {text}")
    return 0 if all(passed for passed, _ in values) else 1


def _tail_log(log: Path, pattern: str, count: int = 8) -> None:
    if not log.exists():
        return
    lines = [
        line
        for line in log.read_text(errors="replace").splitlines()
        if re.search(pattern, line, re.I) and "access_json" not in line
    ]
    for line in lines[-count:]:
        print(f"    {line}")


def _write_stagecmd(run: LiveRun, tape_dir: Path, *, delay_s: float) -> Path:
    script = run.write(
        run.root / "stagecmd.py",
        _STAGECMD.format(python=sys.executable, tape=str(tape_dir), delay=delay_s),
    )
    script.chmod(script.stat().st_mode | stat_mod.S_IXUSR | stat_mod.S_IXGRP | stat_mod.S_IXOTH)
    return script


def recall_stream(nginx: Path | None = None) -> int:
    """Async nearline recall over root://: a read-open of an OFFLINE tape
    object faults a recall and the server answers kXR_wait; the client
    retries until the recall brings the object online, then serves it."""
    if not XRDFS.exists():
        print(f"SKIP: native xrdfs not built ({XRDFS})")
        return 0
    (bport,) = free_ports(1)
    with LiveRun("tprs", nginx) as run:
        for name in ("tape", "cache", "export", "logs"):
            run.mkdir(name)
        config = run.write(run.root / "nginx.conf", f"""daemon on; error_log {run.root}/logs/e.log info; pid {run.root}/nginx.pid;
env BRIX_FRM_STUB_RECALL_DELAY_MS=1200;
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{ listen 127.0.0.1:{bport}; brix_root on; brix_export {run.root}/export; brix_auth none;
    brix_storage_backend tape://stub{run.root}/tape;
    brix_cache_store posix:{run.root}/cache; }} }}
""")
        digest = random_file(run.root / "tape/f.bin", 480000)
        run.start_nginx(run.root, config, bport)
        time.sleep(1)
        target = f"root://127.0.0.1:{bport}"

        stat_out = run.call([XRDFS, target, "stat", "/f.bin"], check=False).stdout
        offline = "Offline" in stat_out
        if not offline:
            for line in stat_out.splitlines():
                if "flags" in line.lower():
                    print(f"    {line}")
        no_recall = not (run.root / "cache/f.bin").exists()

        started = time.monotonic()
        cold = run.call([XRDFS, target, "cat", "/f.bin"], input=b"", check=False)
        elapsed = int(time.monotonic() - started)
        cold_ok = sha256_bytes(cold.stdout) == digest
        if not cold_ok:
            print(f"    {cold.stderr.decode(errors='replace') if isinstance(cold.stderr, bytes) else cold.stderr}")
            _tail_log(run.root / "logs/e.log", r"recall|wait|frm|cache|error")
        log = (run.root / "logs/e.log").read_text(errors="replace")
        # Informational in the shell (`|| true`).
        if re.search(r"recall-wait|kXR_wait|recall in progress", log):
            print("  ok   server logged the recall kXR_wait park")

        warm = run.call([XRDFS, target, "cat", "/f.bin"], input=b"", check=False)
        return _checks([
            (offline, "kXR_stat reports Offline for a tape:// nearline object (phase-64 backend residency)"),
            (no_recall, "STAT did not fault a recall (residency probe only)"),
            (cold_ok, f"xrdfs cat byte-exact after {elapsed}s (recall via kXR_wait/retry, worker never blocked)"),
            (sha256_bytes(warm.stdout) == digest, "warm read byte-exact (cache hit, no wait)"),
        ])


def recall_async(nginx: Path | None = None) -> int:
    """Async nearline recall over HTTP: a GET of an OFFLINE tape object parks
    the open (202 staging), the client polls, and once the recall completes
    the cache tier fills from tape and serves 200."""
    (bport,) = free_ports(1)
    with LiveRun("tprec", nginx) as run:
        for name in ("tape", "cache", "export", "tmp", "logs"):
            run.mkdir(name)
        config = run.write(run.root / "nginx.conf", f"""daemon on; error_log {run.root}/logs/e.log info; pid {run.root}/nginx.pid;
env BRIX_FRM_STUB_RECALL_DELAY_MS=2500;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{ client_body_temp_path {run.root}/tmp; server {{ listen 127.0.0.1:{bport};
  location / {{ brix_webdav on; brix_export {run.root}/export; brix_webdav_auth none;
    brix_storage_backend tape://stub{run.root}/tape;
    brix_cache_store posix:{run.root}/cache; }} }} }}
""")
        # Seed an OFFLINE object: on "tape" (<base>/<key>) with NO online buffer.
        digest = random_file(run.root / "tape/f.bin", 500000)
        run.start_nginx(run.root, config, bport)
        time.sleep(1)
        url = f"http://127.0.0.1:{bport}/f.bin"

        first = run.curl_status(url)
        if first != 202:
            _tail_log(run.root / "logs/e.log", r"recall|frm|nearline|cache|error", 6)
        marker = (run.root / "tape/.recalling").is_dir()

        polled = run.root / "polled.bin"
        landed, last = None, first
        for second in range(1, 16):
            time.sleep(1)
            last = int(run.call(["curl", "-sS", "--max-time", "25", "-o", polled, "-w", "%{http_code}", url], check=False).stdout.strip() or 0)
            if last == 200:
                landed = second
                break
        recalled = landed is not None and sha256(polled) == digest
        if not recalled:
            _tail_log(run.root / "logs/e.log", r"recall|frm|cache|error")

        warm = run.root / "warm.bin"
        warm_status = int(run.call(["curl", "-sS", "--max-time", "25", "-o", warm, "-w", "%{http_code}", url], check=False).stdout.strip() or 0)
        return _checks([
            (first == 202, f"202 Accepted (staging) — worker NOT blocked for the recall (got {first})"),
            (marker, "recall marker in flight (async MSS simulated)"),
            (recalled, f"recall completed after ~{landed}s -> 200 byte-exact (filled tape->cache, served); last={last}"),
            (warm_status == 200 and sha256(warm) == digest, f"warm cache hit byte-exact (got {warm_status})"),
        ])


def exec_adapter(nginx: Path | None = None) -> int:
    """The exec MSS adapter: sd_frm shells out to $BRIX_FRM_STAGECMD for
    residency, async recall, and migrate; the open parks (202), a poll turns
    200 once the operator stagecmd's recall completes."""
    (bport,) = free_ports(1)
    with LiveRun("tpexec", nginx) as run:
        for name in ("realtape", "online", "cache", "export", "tmp", "logs"):
            run.mkdir(name)
        stagecmd = _write_stagecmd(run, run.root / "realtape", delay_s=2.0)
        config = run.write(run.root / "nginx.conf", f"""daemon on; error_log {run.root}/logs/e.log info; pid {run.root}/nginx.pid;
env BRIX_FRM_STAGECMD={stagecmd};
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{ client_body_temp_path {run.root}/tmp; server {{ listen 127.0.0.1:{bport};
  location / {{ brix_webdav on; brix_export {run.root}/export; brix_webdav_auth none;
    brix_storage_backend tape://exec{run.root}/online;
    brix_cache_store posix:{run.root}/cache; }} }} }}
""")
        # Seed an offline object on the REAL tape (the stagecmd's domain).
        digest = random_file(run.root / "realtape/f.bin", 480000)
        run.start_nginx(run.root, config, bport)
        time.sleep(1)
        url = f"http://127.0.0.1:{bport}/f.bin"

        propfind = run.call([
            "curl", "-sS", "-X", "PROPFIND", "-H", "Depth: 0",
            "--data", '<D:propfind xmlns:D="DAV:" xmlns:xrd="http://brix.org/2010/ns/dav"><D:prop><xrd:locality/></D:prop></D:propfind>',
            url,
        ], check=False).stdout
        nearline = "<xrd:locality>NEARLINE</xrd:locality>" in propfind
        if not nearline:
            match = re.search(r"<xrd:locality>[^<]*</xrd:locality>", propfind)
            if match:
                print(f"    {match.group(0)}")
        propfind_no_recall = not (run.root / "online/f.bin").exists()

        first = run.curl_status(url)
        if first != 202:
            _tail_log(run.root / "logs/e.log", r"frm|exec|recall|cache|error")

        polled = run.root / "polled.bin"
        landed, last = None, first
        for second in range(1, 16):
            time.sleep(1)
            last = int(run.call(["curl", "-sS", "--max-time", "25", "-o", polled, "-w", "%{http_code}", url], check=False).stdout.strip() or 0)
            if last == 200:
                landed = second
                break
        recalled = landed is not None and sha256(polled) == digest
        if not recalled:
            _tail_log(run.root / "logs/e.log", r"frm|exec|recall|cache|error")
        return _checks([
            (nearline, "PROPFIND locality NEARLINE (from the tape backend via the VFS seam, no FRM xattr)"),
            (propfind_no_recall, "PROPFIND did not trigger a recall (residency probe only)"),
            (first == 202, f"202 staging (exec stagecmd submitted the recall, non-blocking) — got {first}"),
            (recalled, f"recalled via exec stagecmd after ~{landed}s -> 200 byte-exact; last={last}"),
        ])


def s3_tape_residency(nginx: Path | None = None) -> int:
    """The VFS residency seam on an S3 export over a tape:// backend: HEAD of
    a nearline object advertises GLACIER, GET answers 403 InvalidObjectState
    without faulting a recall; a plain posix S3 export is unaffected."""
    port, pport = free_ports(2)
    with LiveRun("s3tres", nginx) as run:
        tape_node, plain_node = run.mkdir("t"), run.mkdir("p")
        for name in ("realtape", "online", "s3root", "cache", "logs"):
            (tape_node / name).mkdir(exist_ok=True)
        for name in ("plain", "logs"):
            (plain_node / name).mkdir(exist_ok=True)
        stagecmd = _write_stagecmd(run, tape_node / "realtape", delay_s=1.0)
        tape_conf = run.write(tape_node / "nginx.conf", f"""daemon on; error_log {tape_node}/logs/e.log info; pid {tape_node}/nginx.pid;
env BRIX_FRM_STAGECMD={stagecmd};
events {{ worker_connections 64; }}
http {{ server {{ listen 127.0.0.1:{port};
  location / {{ brix_s3 on; brix_export {tape_node}/s3root; brix_s3_bucket xrdtape;
    brix_storage_backend tape://exec{tape_node}/online;
    brix_cache_store posix:{tape_node}/cache; }} }} }}
""")
        # A plain POSIX s3 export — the non-regression control: NO nearline
        # tier, must classify ONLINE and serve normally.
        plain_conf = run.write(plain_node / "nginx.conf", f"""daemon on; error_log {plain_node}/logs/p.log info; pid {plain_node}/nginx.pid;
events {{ worker_connections 64; }}
http {{ server {{ listen 127.0.0.1:{pport};
  location / {{ brix_s3 on; brix_export {plain_node}/plain; brix_s3_bucket xrdplain; }} }} }}
""")
        # f.bin: offline (on tape only). h.bin: normal object on the plain export.
        random_file(tape_node / "realtape/f.bin", 320000)
        plain_digest = random_file(plain_node / "plain/h.bin", 256000)
        run.start_nginx(tape_node, tape_conf, port)
        run.start_nginx(plain_node, plain_conf, pport)
        time.sleep(1)
        tape_url = f"http://127.0.0.1:{port}/xrdtape/f.bin"
        plain_url = f"http://127.0.0.1:{pport}/xrdplain/h.bin"

        head = run.call(["curl", "-sS", "--max-time", "25", "-I", tape_url], check=False).stdout
        head_code = (head.splitlines()[0].split() + ["", ""])[1] if head else ""
        glacier = re.search(r"x-amz-storage-class:.*GLACIER", head, re.I) is not None
        if not glacier:
            for line in head.splitlines()[:8]:
                print(f"    {line}")
            _tail_log(tape_node / "logs/e.log", r"frm|exec|residency|error", 6)

        body = run.root / "get.body"
        get_code = int(run.call(["curl", "-sS", "--max-time", "25", "-o", body, "-w", "%{http_code}", tape_url], check=False).stdout.strip() or 0)
        invalid_state = get_code == 403 and "InvalidObjectState" in body.read_text(errors="replace")
        if not invalid_state:
            print(f"    {body.read_text(errors='replace')[:240]}")
        no_recall = not (tape_node / "online/f.bin").exists()

        got = run.root / "h.got"
        plain_code = int(run.call(["curl", "-sS", "--max-time", "25", "-o", got, "-w", "%{http_code}", plain_url], check=False).stdout.strip() or 0)
        plain_ok = plain_code == 200 and sha256(got) == plain_digest
        if not plain_ok:
            _tail_log(plain_node / "logs/p.log", r"error|InvalidObjectState", 6)
        plain_head = run.call(["curl", "-sS", "--max-time", "25", "-I", plain_url], check=False).stdout
        plain_glacier = re.search(r"x-amz-storage-class:.*GLACIER", plain_head, re.I) is not None

        for log in (tape_node / "logs/e.log", plain_node / "logs/p.log"):
            if log.exists():
                errors = len(re.findall(r"\[(error|crit|alert)\]", log.read_text(errors="replace")))
                print(f"  info error-lines {log.name}: {errors}")
        return _checks([
            (glacier, f"HEAD {head_code} advertised GLACIER (residency from the tape backend, no xattr)"),
            (invalid_state, f"GET 403 InvalidObjectState (no stage faulted — S3/Glacier semantics); got {get_code}"),
            (no_recall, "GET did not trigger a recall (online buffer untouched)"),
            (plain_ok, f"GET 200 byte-exact (non-tape export unaffected — no false InvalidObjectState); got {plain_code}"),
            (not plain_glacier, "plain HEAD did NOT advertise GLACIER (no nearline tier => ONLINE)"),
        ])


SCENARIOS = {
    "tape-recall-stream": recall_stream,
    "tape-recall-async": recall_async,
    "tape-exec-adapter": exec_adapter,
    "s3-tape-residency": s3_tape_residency,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return SCENARIOS[ns.scenario](ns.nginx)
    except LiveFailure as exc:
        print(f"tape scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
