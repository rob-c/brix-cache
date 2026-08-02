"""phase-92 HTTP cache-fill remote passthrough (store-then-evict) live checks.

The read cache admits an object only when the admission policy allows it
(prefix/size).  `brix_cache_passthrough on;` extends that: a REMOTE object the
policy DECLINES purely on size — but that still fits `brix_cache_passthrough_max`
(the spool cap) — is filled into the store anyway, served through the normal
cache-hit reenter, then EVICTED once every coalesced waiter has opened its serve
fd.  The object is delivered byte-exact without being retained; an object over
the spool cap is refused (no unbounded spool), and with passthrough OFF a
declined object is never served (fail-closed opt-in).

Passthrough is HTTP-plane-only (WebDAV GET / S3 GetObject) — it rides the
off-loop cache-fill worker, which the root:// stream plane never uses.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
import time

from cmdscripts.live_common import LiveFailure, LiveRun, random_file, sha256
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, HOST

_PORTS = cmdscript_ports("cache_passthrough")

CLIENT_REQUIREMENTS = {
    "serve-evict": (),
    "disabled-declines": (),
}

# admission caps for the node: cache anything <=256k; passthrough-spool up to 2m.
_MAX_OBJECT = "256k"
_PT_MAX = "2m"
_SMALL = 120_000     # <= max_object          -> admitted + RETAINED
_MID = 900_000       # > max_object, <= pt_max -> passthrough served + EVICTED
_HUGE = 3_000_000    # > pt_max                -> refused (no unbounded spool)


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


def _origin_conf(origin: Path, oport: int) -> str:
    return f"""daemon on; error_log {origin}/logs/e.log info; pid {origin}/nginx.pid;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:{oport}; brix_root on; brix_export {origin}/root; brix_auth none; }} }}
"""


def _node_conf(node: Path, bport: int, oport: int, *, passthrough: bool) -> str:
    return f"""daemon on; error_log {node}/logs/e.log info; pid {node}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    client_body_temp_path {node}/tmp;
    server {{
        listen {BIND_HOST}:{bport};
        location / {{
            brix_webdav on;
            brix_export {node}/export;
            brix_webdav_auth none;
            brix_storage_backend root://{HOST}:{oport};
            brix_cache_store posix:{node}/cache;
            brix_cache_max_object {_MAX_OBJECT};
            brix_cache_passthrough {'on' if passthrough else 'off'};
            brix_cache_passthrough_max {_PT_MAX};
        }}
    }}
}}
"""


def _seed(run: LiveRun, oport: int) -> tuple[Path, dict[str, str]]:
    origin = run.mkdir("o")
    for name in ("root", "logs"):
        (origin / name).mkdir(exist_ok=True)
    digests = {
        "small.bin": random_file(origin / "root/small.bin", _SMALL),
        "mid.bin": random_file(origin / "root/mid.bin", _MID),
        "huge.bin": random_file(origin / "root/huge.bin", _HUGE),
    }
    run.write(origin / "nginx.conf", _origin_conf(origin, oport))
    run.start_nginx(origin, origin / "nginx.conf", oport)
    return origin, digests


def _get(run: LiveRun, url: str, dest: Path) -> int:
    return int(run.call(
        ["curl", "-sS", "--max-time", "25", "-o", dest, "-w", "%{http_code}", url],
        check=False,
    ).stdout.strip() or 0)


def serve_evict(nginx: Path | None = None) -> int:
    """passthrough ON: a small object is cached+retained; a mid object over the
    caching cap but within the spool cap is served byte-exact then EVICTED
    (store-then-evict); an object over the spool cap is refused."""
    oport, bport = _PORTS[0:2]
    with LiveRun("cpte", nginx) as run:
        node = run.mkdir("b")
        for name in ("export", "cache", "tmp", "logs"):
            (node / name).mkdir(exist_ok=True)
        origin, digests = _seed(run, oport)
        run.write(node / "nginx.conf", _node_conf(node, bport, oport, passthrough=True))
        run.start_nginx(node, node / "nginx.conf", bport)
        time.sleep(1)
        url = f"http://{HOST}:{bport}"

        # 1) small <= max_object -> normal admission, RETAINED in the store.
        small = run.root / "small.got"
        small_status = _get(run, f"{url}/small.bin", small)
        small_ok = small_status == 200 and small.exists() and sha256(small) == digests["small.bin"]

        # 2) mid > max_object, <= pt_max -> passthrough serves byte-exact + EVICTS.
        mid = run.root / "mid.got"
        mid_status = _get(run, f"{url}/mid.bin", mid)
        mid_ok = mid_status == 200 and mid.exists() and sha256(mid) == digests["mid.bin"]
        time.sleep(0.7)  # let brix_http_cache_fill_done run the post-serve evict
        log = (node / "logs/e.log").read_text(errors="replace")
        if not (mid_ok and not (node / "cache/mid.bin").exists()):
            _tail_log(node / "logs/e.log", r"passthrough|cache|fill|error")

        # 3) huge > pt_max -> refused (no unbounded spool).
        huge = run.root / "huge.got"
        huge_status = _get(run, f"{url}/huge.bin", huge)

        return _checks([
            (small_ok, f"small GET 200 byte-exact (got {small_status})"),
            ((node / "cache/small.bin").exists(),
             "small object RETAINED in the cache store (normal admission)"),
            (mid_ok, f"mid GET 200 byte-exact via passthrough (got {mid_status})"),
            (not (node / "cache/mid.bin").exists(),
             "mid object NOT retained — store-then-evict after serve"),
            ("event=passthrough-evict" in log and "mid.bin" in log,
             "passthrough-evict logged for the served mid object"),
            (huge_status != 200,
             f"huge object OVER the spool cap refused (got {huge_status}, want !=200)"),
            (not (node / "cache/huge.bin").exists(),
             "huge object never spooled beyond the passthrough cap"),
        ])


def disabled_declines(nginx: Path | None = None) -> int:
    """security-neg: with passthrough OFF a size-declined REMOTE object is never
    served and never lands in the store — passthrough is fail-closed opt-in."""
    oport, bport = _PORTS[0:2]
    with LiveRun("cptd", nginx) as run:
        node = run.mkdir("b")
        for name in ("export", "cache", "tmp", "logs"):
            (node / name).mkdir(exist_ok=True)
        origin, digests = _seed(run, oport)
        run.write(node / "nginx.conf", _node_conf(node, bport, oport, passthrough=False))
        run.start_nginx(node, node / "nginx.conf", bport)
        time.sleep(1)
        url = f"http://{HOST}:{bport}"

        # small still caches normally (control: OFF only changes declined objects).
        small = run.root / "small.got"
        small_status = _get(run, f"{url}/small.bin", small)
        small_ok = small_status == 200 and small.exists() and sha256(small) == digests["small.bin"]

        # mid > max_object with passthrough OFF -> DECLINED, not served.
        mid = run.root / "mid.got"
        mid_status = _get(run, f"{url}/mid.bin", mid)
        time.sleep(0.5)
        if mid_status == 200:
            _tail_log(node / "logs/e.log", r"passthrough|cache|fill|declin|error")

        return _checks([
            (small_ok, f"small GET still cached+served with passthrough off (got {small_status})"),
            (mid_status != 200,
             f"declined mid object NOT served with passthrough off (got {mid_status}, want !=200)"),
            (not (node / "cache/mid.bin").exists(),
             "declined mid object never spooled with passthrough off"),
        ])


SCENARIOS = {
    "serve-evict": serve_evict,
    "disabled-declines": disabled_declines,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return SCENARIOS[ns.scenario](ns.nginx)
    except LiveFailure as exc:
        print(f"cache_passthrough scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
