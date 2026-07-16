"""Direct Python ports for the tier/stage live shell scenarios.

Ports ``run_tier_instance_lifetime.sh``, ``run_stage_async_remote_flush.sh``,
``run_root_stage_writeback.sh``, and ``run_root_slice_fill.sh``.  Each public
scenario keeps its shell test's own acceptance sequence and assertions; ports
are allocated dynamically instead of the scripts' fixed literals.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import signal
import sys
import time

from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT, random_file, sha256
from settings import free_ports

XRDCP = REPO_ROOT / "client/bin/xrdcp"
XRDFS = REPO_ROOT / "client/bin/xrdfs"

CLIENT_REQUIREMENTS = {
    "tier-instance-lifetime": (XRDCP, XRDFS),
    "stage-async-remote-flush": (),
    "root-stage-writeback": (XRDCP, XRDFS),
    "root-slice-fill": (XRDFS,),
}


def _checks(values: list[tuple[bool, str]]) -> int:
    for passed, text in values:
        print(f"  {'ok  ' if passed else 'FAIL'} {text}")
    return 0 if all(passed for passed, _ in values) else 1


def _origin_config(run: LiveRun, root: Path, port: int, *, writable: bool = True, level: str = "info") -> Path:
    write = " brix_allow_write on;" if writable else ""
    return run.write(root / "nginx.conf", f"""daemon on; error_log {root}/logs/e.log {level}; pid {root}/nginx.pid;
events {{ worker_connections 64; }}
stream {{ server {{ listen 127.0.0.1:{port}; brix_root on; brix_export {root}/root; brix_auth none;{write} }} }}
""")


def _wait_flush(origin_file: Path, reference: Path, *, tries: int = 30, delay: float = 0.5) -> bool:
    for _ in range(tries):
        if origin_file.exists() and sha256(origin_file) == sha256(reference):
            return True
        time.sleep(delay)
    return False


def instance_lifetime(nginx: Path | None = None) -> int:
    """Storage-driver instance lifetime through a composed tier stack.

    Regression for the xrd1 crash-loop: tier composition during config parse
    must not allocate SD instances from the transient init-cycle pool.  Runs
    the stack in production shape (master + 2 workers), exercises every tier
    surface, reloads, exercises again, and requires zero worker deaths.
    """
    oport, bport = free_ports(2)
    with LiveRun("tier_life", nginx) as run:
        origin, node = run.mkdir("o"), run.mkdir("b")
        for directory, names in ((origin, ("root", "logs")), (node, ("export", "cache", "stage", "logs"))):
            for name in names:
                (directory / name).mkdir(exist_ok=True)
        run.start_nginx(origin, _origin_config(run, origin, oport), oport)
        node_conf = run.write(node / "nginx.conf", f"""daemon on; master_process on; worker_processes 2;
error_log {node}/logs/e.log info; pid {node}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{
    listen 127.0.0.1:{bport}; brix_root on; brix_export {node}/export;
    brix_auth none; brix_allow_write on;
    brix_storage_backend root://127.0.0.1:{oport};
    brix_cache_store posix:{node}/cache; brix_cache_export /;
    brix_stage on; brix_stage_store posix:{node}/stage; brix_stage_flush async;
}} }}
""")
        run.start_nginx(node, node_conf, bport)
        time.sleep(1)

        small, big = run.root / "small.bin", run.root / "big.bin"
        random_file(small, 300000)
        random_file(big, 2600000)
        pre = origin / "root/pre.bin"
        random_file(pre, 500000)
        target = f"root://127.0.0.1:{bport}"
        checks: list[tuple[bool, str]] = []

        small_put = run.call([XRDCP, "-f", small, f"{target}//small.bin"], check=False).returncode == 0
        checks.append((small_put, "small write accepted outright"))
        checks.append((_wait_flush(origin / "root/small.bin", small), "small staged write flushed byte-exact"))
        big_put = run.call([XRDCP, "-f", big, f"{target}//big.bin"], check=False).returncode == 0
        checks.append((big_put, "multi-chunk write accepted outright"))
        checks.append((_wait_flush(origin / "root/big.bin", big), "multi-chunk staged write flushed byte-exact"))

        cold = run.call([XRDFS, target, "cat", "/pre.bin"], input=b"", check=False).stdout
        checks.append((cold == pre.read_bytes(), f"cold read (cache fill) byte-exact (got={len(cold)})"))
        warm = run.call([XRDFS, target, "cat", "/pre.bin"], input=b"", check=False).stdout
        checks.append((warm == pre.read_bytes(), "warm read (cache hit) byte-exact"))

        os.kill(int((node / "nginx.pid").read_text().strip()), signal.SIGHUP)
        time.sleep(1.5)
        post_put = run.call([XRDCP, "-f", small, f"{target}//post-reload.bin"], check=False).returncode == 0
        checks.append((post_put, "post-reload write accepted outright"))
        checks.append((_wait_flush(origin / "root/post-reload.bin", small), "post-reload staged write flushed byte-exact"))
        post = run.call([XRDFS, target, "cat", "/pre.bin"], input=b"", check=False).stdout
        checks.append((post == pre.read_bytes(), "post-reload read byte-exact"))

        log = (node / "logs/e.log").read_text(errors="replace")
        deaths = re.findall(r"exited on signal|exited with fatal", log)
        if deaths:
            for line in [l for l in log.splitlines() if re.search(r"exited on signal|exited with fatal", l)][:3]:
                print(f"    {line}")
        checks.append((not deaths, "zero worker deaths across writes, fills, hits, and a reload"))
        return _checks(checks)


def stage_async_remote_flush(nginx: Path | None = None) -> int:
    """Async stage-flush mover runs on the thread pool so a flush to a REMOTE
    root:// backend works; the stage copy is dropped on completion."""
    oport, bport = free_ports(2)
    with LiveRun("saf", nginx) as run:
        origin, node = run.mkdir("o"), run.mkdir("b")
        for directory, names in ((origin, ("root", "logs")), (node, ("export", "stage", "tmp", "logs"))):
            for name in names:
                (directory / name).mkdir(exist_ok=True)
        run.start_nginx(origin, _origin_config(run, origin, oport, level="error"), oport)
        node_conf = run.write(node / "nginx.conf", f"""daemon on; error_log {node}/logs/e.log info; pid {node}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{ client_body_temp_path {node}/tmp; server {{ listen 127.0.0.1:{bport};
  location / {{ dav_methods PUT DELETE;
    brix_webdav on; brix_export {node}/export; brix_webdav_auth none; brix_allow_write on;
    brix_storage_backend root://127.0.0.1:{oport};
    brix_stage on; brix_stage_store posix:{node}/stage; brix_stage_flush async; }} }} }}
""")
        run.start_nginx(node, node_conf, bport)
        time.sleep(1)

        source = run.root / "src.bin"
        digest = random_file(source, 420000)
        status = run.curl_status(f"http://127.0.0.1:{bport}/o.bin", "-T", str(source))
        # Informational in the shell (`|| true`): the async flush may already
        # have raced the stage copy away by the time we look.
        if (node / "stage/o.bin").exists():
            print("  ok   object staged on the local posix store")

        landed = None
        remote = origin / "root/o.bin"
        for second in range(1, 13):
            time.sleep(1)
            if remote.exists():
                landed = second
                break
        flushed = landed is not None and sha256(remote) == digest
        # The drop of the stage copy trails the flush by a moment; give it the
        # same slack the shell's 1s poll granularity implicitly provided.
        dropped = False
        for _ in range(30):
            if not (node / "stage/o.bin").exists():
                dropped = True
                break
            time.sleep(0.1)
        if not flushed:
            log = (node / "logs/e.log").read_text(errors="replace")
            for line in [l for l in log.splitlines() if re.search(r"stage|flush|move|xroot|error", l, re.I) and "access_json" not in l][-8:]:
                print(f"    {line}")
        return _checks([
            (status == 201, f"PUT 201 (staged locally, flush deferred) — got {status}"),
            (flushed, f"async flush reached the REMOTE backend after ~{landed}s, byte-exact (mover ran off-loop)"),
            (dropped, "stage copy dropped after the flush completed"),
        ])


def root_stage_writeback(nginx: Path | None = None) -> int:
    """root:// kXR_write routed through the sd_stage write-back object: a
    root:// upload buffers on the stage store and flushes to the origin on
    close, byte-exact."""
    oport, bport = free_ports(2)
    with LiveRun("root_wb", nginx) as run:
        origin, node = run.mkdir("o"), run.mkdir("b")
        for directory, names in ((origin, ("root", "logs")), (node, ("export", "stage", "logs"))):
            for name in names:
                (directory / name).mkdir(exist_ok=True)
        run.start_nginx(origin, _origin_config(run, origin, oport), oport)
        node_conf = run.write(node / "nginx.conf", f"""daemon on; error_log {node}/logs/e.log info; pid {node}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{
    listen 127.0.0.1:{bport}; brix_root on; brix_export {node}/export;
    brix_auth none; brix_allow_write on; brix_upload_resume off;
    brix_storage_backend root://127.0.0.1:{oport};
    brix_stage on;
    brix_stage_store posix:{node}/stage;
    brix_stage_flush sync;
}} }}
""")
        run.start_nginx(node, node_conf, bport)
        time.sleep(1)

        source = run.root / "src.bin"
        random_file(source, 2621440)  # 2.5 MiB, multi-write
        uploaded = run.call([XRDCP, "-f", source, f"root://127.0.0.1:{bport}//m.bin"], check=False).returncode == 0
        if not uploaded:
            log = (node / "logs/e.log").read_text(errors="replace")
            for line in [l for l in log.splitlines() if re.search(r"stage|flush|origin|error|write", l, re.I)][-10:]:
                print(f"    {line}")
        flushed = origin / "root/m.bin"
        got = run.call([XRDFS, f"root://127.0.0.1:{bport}", "cat", "/m.bin"], input=b"", check=False).stdout
        return _checks([
            (uploaded, "upload accepted"),
            (flushed.exists() and sha256(flushed) == sha256(source),
             f"flushed object byte-exact on the backend O (got={flushed.stat().st_size if flushed.exists() else 'missing'})"),
            (got == source.read_bytes(), "read-back byte-exact"),
        ])


def root_slice_fill(nginx: Path | None = None) -> int:
    """Legacy-config slice cache fills per-slice from a root:// origin and
    serves byte-exact over root:// (cold fill, warm hit, multi-slice)."""
    oport, cport = free_ports(2)
    with LiveRun("root_slice", nginx) as run:
        origin, cache = run.mkdir("o"), run.mkdir("c")
        for directory, names in ((origin, ("root", "logs")), (cache, ("export", "cache", "logs"))):
            for name in names:
                (directory / name).mkdir(exist_ok=True)
        run.start_nginx(origin, _origin_config(run, origin, oport, writable=False, level="error"), oport)
        cache_conf = run.write(cache / "nginx.conf", f"""daemon on; error_log {cache}/logs/e.log info; pid {cache}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen 127.0.0.1:{cport};
        brix_root on;
        brix_export {cache}/export;
        brix_auth none;
        brix_storage_backend root://127.0.0.1:{oport};
        brix_cache_store posix:{cache}/cache; brix_cache_export /;
        brix_cache_slice_size 1m;
    }}
}}
""")
        run.start_nginx(cache, cache_conf, cport)
        time.sleep(1)

        small, big = origin / "root/small.bin", origin / "root/big.bin"
        random_file(small, 900000)   # < 1 slice
        random_file(big, 4194304)    # 4 slices
        target = f"root://127.0.0.1:{cport}"

        cold_small = run.call([XRDFS, target, "cat", "/small.bin"], input=b"", check=False).stdout
        cold_ok = cold_small == small.read_bytes()
        if not cold_ok:
            log = (cache / "logs/e.log").read_text(errors="replace")
            for line in [l for l in log.splitlines() if re.search(r"slice|cache|origin|xroot|fill|error", l, re.I)][-8:]:
                print(f"    {line}")
        warm_small = run.call([XRDFS, target, "cat", "/small.bin"], input=b"", check=False).stdout
        cold_big = run.call([XRDFS, target, "cat", "/big.bin"], input=b"", check=False).stdout
        warm_big = run.call([XRDFS, target, "cat", "/big.bin"], input=b"", check=False).stdout
        return _checks([
            (cold_ok, "cold slice read byte-exact"),
            ((cache / "cache/small.bin").exists(), "object cached under cache_root"),
            (warm_small == small.read_bytes(), "warm slice hit byte-exact"),
            (cold_big == big.read_bytes(), f"multi-slice read byte-exact (got={len(cold_big)})"),
            (warm_big == big.read_bytes(), "warm multi-slice byte-exact"),
        ])


SCENARIOS = {
    "tier-instance-lifetime": instance_lifetime,
    "stage-async-remote-flush": stage_async_remote_flush,
    "root-stage-writeback": root_stage_writeback,
    "root-slice-fill": root_slice_fill,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return SCENARIOS[ns.scenario](ns.nginx)
    except LiveFailure as exc:
        print(f"tier/stage scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
