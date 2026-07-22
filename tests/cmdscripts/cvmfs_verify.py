"""Direct Python port of ``tests/run_cvmfs_verify.sh``."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT
from settings import BIND_HOST, HOST


MOCK_PORT = 12841
CACHE_PORT = 12842


def config(run: LiveRun, verify: str | None) -> Path:
    directive = f"        brix_cache_verify {verify};\n" if verify else ""
    return run.write(
        run.root / "nginx.conf",
        f"""daemon on; error_log {run.root}/logs/e.log info; pid {run.root}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 128; }}
http {{ access_log off; server {{
    listen {BIND_HOST}:{CACHE_PORT};
    location /metrics {{ brix_metrics on; }}
    location /cvmfs/ {{
        brix_storage_backend http://{HOST}:{MOCK_PORT};
        brix_cache_store posix:{run.root}/cache;
{directive}        brix_cvmfs on;
        brix_cvmfs_quarantine_dir {run.root}/quarantine;
    }}
}} }}
""",
    )


def set_fault(run: LiveRun, mode: str, count: int) -> None:
    run.call(
        ["curl", "-sS", "-o", "/dev/null", "-X", "POST", "-d", json.dumps({"mode": mode, "count": count}), f"http://{HOST}:{MOCK_PORT}/ctl/fault"]
    )


def run_port(nginx: Path | None = None) -> int:
    failures: list[str] = []
    with LiveRun("cvmfs_verify", nginx) as run:
        run.mkdir("cache")
        quarantine = run.mkdir("quarantine")
        run.mkdir("logs")
        mock = run.spawn([sys.executable, REPO_ROOT / "tests/cvmfs/mock_stratum1.py", "--port", str(MOCK_PORT), "--objects", "4", "--seed", "3"])
        if mock.poll() is not None:
            raise LiveFailure("mock_stratum1 did not start")
        time.sleep(0.2)
        objects = json.loads(run.call(["curl", "-sS", f"http://{HOST}:{MOCK_PORT}/ctl/objects"]).stdout)
        obj = objects[1]

        def check(condition: bool, message: str) -> None:
            print(f"  {'ok  ' if condition else 'FAIL'} {message}")
            if not condition:
                failures.append(message)

        run.start_nginx(run.root, config(run, "cvmfs-cas"), CACHE_PORT)
        set_fault(run, "corrupt", 8)
        check(run.curl_status(f"http://{HOST}:{CACHE_PORT}{obj}") == 502, "corrupt fill -> 502, not admitted")
        set_fault(run, "none", 0)
        check(any(quarantine.iterdir()), "corrupt part quarantined")
        metrics = run.call(["curl", "-sS", f"http://{HOST}:{CACHE_PORT}/metrics"]).stdout
        count = next((line.split()[-1] for line in metrics.splitlines() if line.startswith("brix_cvmfs_verify_failures_total ")), "0")
        check(float(count) >= 1, "verify failure metric incremented")
        got = run.curl_bytes(f"http://{HOST}:{CACHE_PORT}{obj}")
        origin = run.curl_bytes(f"http://{HOST}:{MOCK_PORT}{obj}")
        check(got == origin, "clean retry byte-exact")

        run.stop_nginx(run.root)
        shutil_rmtree(run.root / "cache")
        run.mkdir("cache")
        run.start_nginx(run.root, config(run, "off"), CACHE_PORT)
        set_fault(run, "corrupt", 1)
        poison_one = run.curl_bytes(f"http://{HOST}:{CACHE_PORT}{obj}")
        poison_two = run.curl_bytes(f"http://{HOST}:{CACHE_PORT}{obj}")
        check(poison_one != origin, "verify=off admits corruption (documented gap)")
        check(poison_one == poison_two, "poisoned cache re-serves it")

        run.stop_nginx(run.root)
        shutil_rmtree(run.root / "cache")
        shutil_rmtree(quarantine)
        run.mkdir("cache")
        quarantine.mkdir()
        set_fault(run, "none", 0)
        run.start_nginx(run.root, config(run, None), CACHE_PORT)
        set_fault(run, "corrupt", 8)
        check(run.curl_status(f"http://{HOST}:{CACHE_PORT}{obj}") == 502, "default rejects corrupt fill")
        set_fault(run, "none", 0)
        check(any(quarantine.iterdir()), "default quarantines corrupt part")
    return 1 if failures else 0


def shutil_rmtree(path: Path) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return run_port(ns.nginx)
    except LiveFailure as exc:
        print(f"run_cvmfs_verify: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
