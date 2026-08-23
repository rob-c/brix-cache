"""Direct Python ports for the remote-tier live shell scenarios.

Ports ``run_tier_remote_stage.sh``, ``run_tier_remote_evict.sh``,
``run_tier_remote_store.sh``, ``run_tier_sidecar_meta.sh``, and
``run_tier_slice_fill.sh``.  The shared topology code only eliminates repeated
nginx/process plumbing; each public scenario below contains the shell test's
own acceptance sequence and assertions.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import time

from cmdscripts.live_common import LiveFailure, LiveRun, random_file, sha256
from settings import BIND_HOST, HOST


def _expression_1(response):
    return (
        int(response.stdout.strip() or 0)
    )

def _expression_2(size, cache):
    return (
        cache.stat().st_blocks * 512 if cache.exists() else size
    )

def _expression_3(status, expected, allocated, full_status, got, cache, size, first, block, full, source):
    return (
        _result([
                    (status in (200, 206), f"middle range accepted ({status})"),
                    (got.read_bytes() == expected, "middle range byte-exact"),
                    (cache.exists() and allocated < size // 4, "first range created a sparse cache object"),
                    (first.read_bytes() == source.read_bytes()[:block], "second range byte-exact"),
                    (full_status == 200 and sha256(full) == sha256(source), "full GET completes byte-exact object"),
                ])
    )

def _expression_4(sidecar):
    return (
        (11742, 11743, 8527) if sidecar else (11682, 11683, 8497)
    )

def _expression_5(sidecar):
    return (
        "tier_sidecar" if sidecar else "tier_rstore"
    )

def _expression_6(sidecar):
    return (
        "brix_cache_meta sidecar;" if sidecar else ""
    )

def _expression_7(source, sidecar):
    return (
        random_file(source, 400000 if sidecar else 500000)
    )

def _expression_8(cold, digest, cached, first):
    return (
        [(cold == 200 and sha256(first) == digest, "cold GET byte-exact"), (cached.exists(), "object bytes stored remotely")]
    )

def _expression_9(cached):
    return (
        subprocess.run(["getfattr", "-d", "-m", ".", str(cached)], capture_output=True, text=True) if shutil.which("getfattr") else None
    )

def _expression_10(checks, warm_status, digest, warm):
    return (
        checks.append((warm_status == 200 and sha256(warm) == digest, "warm hit survives cache-node restart with origin down"))
    )


def _guard_remote_store_1(xattr, checks):
    if xattr is not None:
        checks.append(("cinfo" in xattr.stdout.lower(), "cinfo xattr stored remotely"))


class TierTopology:
    def __init__(self, run: LiveRun, origin_port: int, store_port: int, client_port: int) -> None:
        self.run = run
        self.origin_port, self.store_port, self.client_port = origin_port, store_port, client_port
        self.origin = run.mkdir("o")
        self.store = run.mkdir("s")
        self.client = run.mkdir("b")
        for root, names in ((self.origin, ("root", "logs")), (self.store, ("root", "logs")), (self.client, ("export", "tmp", "cache", "logs"))):
            for name in names:
                (root / name).mkdir()

    def stream(self, directory: Path, port: int, writable: bool, *, store: bool = False) -> Path:
        write = " brix_allow_write on;" if writable else ""
        # A cache node writes "<key>.cinfo" beside the object in sidecar meta
        # mode, and a reserved name is answered kXR_NotFound on every ordinary
        # export.  brix_cache_store_endpoint declares this server the trusted
        # store surface where those names are legitimate targets.
        store_surface = " brix_cache_store_endpoint on;" if store else ""
        return self.run.write(
            directory / "nginx.conf",
            f"""daemon on; error_log {directory}/logs/e.log info; pid {directory}/nginx.pid;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:{port}; brix_root on; brix_export {directory}/root; brix_auth none;{write}{store_surface} }} }}
""",
        )

    def cache(self, directives: str, *, writable: bool = False) -> Path:
        write = "dav_methods PUT DELETE; brix_allow_write on;" if writable else ""
        return self.run.write(
            self.client / "nginx.conf",
            f"""daemon on; error_log {self.client}/logs/e.log info; pid {self.client}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{ client_body_temp_path {self.client}/tmp; server {{ listen {BIND_HOST}:{self.client_port};
  location / {{ {write} brix_webdav on; brix_export {self.client}/export; brix_webdav_auth none;
    brix_storage_backend root://{HOST}:{self.origin_port};
    {directives}
  }} }} }}
""",
        )

    def start(
        self,
        directives: str,
        *,
        origin_writable: bool = False,
        cache_writable: bool = False,
        include_store: bool = True,
    ) -> None:
        self.run.start_nginx(self.origin, self.stream(self.origin, self.origin_port, origin_writable), self.origin_port)
        if include_store:
            self.run.start_nginx(self.store, self.stream(self.store, self.store_port, True, store=True), self.store_port)
        self.run.start_nginx(self.client, self.cache(directives, writable=cache_writable), self.client_port)

    @property
    def url(self) -> str:
        return f"http://{HOST}:{self.client_port}"

    def download(self, path: str, output: Path) -> int:
        result = self.run.call(["curl", "-sS", "-o", output, "-w", "%{http_code}", f"{self.url}/{path}"], check=False)
        return int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0

    def delete(self, path: str) -> int:
        return self.run.curl_status(f"{self.url}/{path}", "-X", "DELETE")

    def upload(self, source: Path, path: str) -> int:
        return self.run.curl_status(f"{self.url}/{path}", "-T", str(source))

    def restart_client(self, directives: str, *, writable: bool = False) -> None:
        self.run.stop_nginx(self.client)
        time.sleep(0.2)
        self.run.start_nginx(self.client, self.cache(directives, writable=writable), self.client_port)


def _result(checks: list[tuple[bool, str]]) -> int:
    for passed, message in checks:
        print(f"  {'ok  ' if passed else 'FAIL'} {message}")
    return 0 if all(passed for passed, _ in checks) else 1


def remote_stage(nginx: Path | None = None) -> int:
    with LiveRun("tier_rstage", nginx) as run:
        topology = TierTopology(run, 11702, 11703, 8503)
        stage = f"brix_stage on; brix_stage_store root://{HOST}:{topology.store_port}; brix_stage_flush sync;"
        topology.start(stage, origin_writable=True, cache_writable=True)
        source = run.root / "src.bin"
        digest = random_file(source, 420000)
        status = topology.upload(source, "o.bin")
        leftovers = list(topology.client.joinpath("export").glob("*.part")) + list(topology.client.joinpath("export").glob("*.stage"))
        return _result([
            (status in (200, 201), f"PUT accepted ({status})"),
            (topology.origin.joinpath("root/o.bin").exists() and sha256(topology.origin / "root/o.bin") == digest, "flushed object byte-exact on backend O"),
            (not topology.store.joinpath("root/o.bin").exists(), "staged copy reclaimed from remote store S"),
            (not leftovers, "no local stage temporary leaked on B"),
        ])


def remote_store(nginx: Path | None = None, *, sidecar: bool = False) -> int:
    ports = _expression_4(sidecar)
    label = _expression_5(sidecar)
    with LiveRun(label, nginx) as run:
        topology = TierTopology(run, *ports)
        metadata = _expression_6(sidecar)
        directives = f"brix_cache_store root://{HOST}:{topology.store_port}; {metadata}"
        source = topology.origin / "root/s.bin"
        digest = _expression_7(source, sidecar)
        source.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        topology.start(directives)
        first = run.root / "cold.bin"
        cold = topology.download("s.bin", first)
        cached = topology.store / "root/s.bin"
        # ".cinfo", not ".xrdcinfo": BRIX_XMETA_SIDECAR_SUFFIX in
        # src/fs/meta/xmeta_carrier.h — the stock-compatible prefix is what
        # makes the sidecar readable as an XrdPfc cinfo file, the suffix is not.
        sidecar_file = topology.store / "root/s.bin.cinfo"
        checks = _expression_8(cold, digest, cached, first)
        if sidecar:
            checks.append((sidecar_file.exists(), "sidecar cinfo object stored remotely"))
        else:
            xattr = _expression_9(cached)
            _guard_remote_store_1(xattr, checks)
        topology.run.stop_nginx(topology.origin)
        topology.restart_client(directives)
        warm = run.root / "warm.bin"
        warm_status = topology.download("s.bin", warm)
        _expression_10(checks, warm_status, digest, warm)
        return _result(checks)


def remote_evict(nginx: Path | None = None) -> int:
    with LiveRun("tier_revict", nginx) as run:
        topology = TierTopology(run, 11732, 11733, 8525)
        topology.start(f"brix_cache_store root://{HOST}:{topology.store_port};", origin_writable=True, cache_writable=True)
        original = topology.origin / "root/e.bin"
        digest = random_file(original, 300000)
        first = run.root / "first.bin"
        cold = topology.download("e.bin", first)
        cached = topology.store / "root/e.bin"
        # Snapshot every existence check AT the step it describes: the checks
        # below are evaluated after the refill has re-created both the origin
        # object and its cached copy, so a late .exists() would report the
        # refilled state and the eviction assertion would be vacuous.
        cold_cached = cached.exists()
        deleted = topology.delete("e.bin")
        time.sleep(0.2)
        evicted = not cached.exists() and not original.exists()
        refilled_digest = random_file(original, 300000)
        refill = run.root / "refill.bin"
        refill_status = topology.download("e.bin", refill)
        replacement = run.root / "replacement.bin"
        replacement_digest = random_file(replacement, 250000)
        overwrite = topology.upload(replacement, "e.bin")
        time.sleep(0.2)
        latest = run.root / "latest.bin"
        latest_status = topology.download("e.bin", latest)
        return _result([
            (cold == 200 and sha256(first) == digest and cold_cached, "cold GET filled remote cache"),
            (deleted in (200, 204), f"DELETE accepted ({deleted})"),
            (evicted, "DELETE evicted remote cache and origin"),
            (refill_status == 200 and sha256(refill) == refilled_digest, "fresh GET re-fills after eviction"),
            (overwrite in (200, 201, 204), f"overwrite accepted ({overwrite})"),
            (latest_status == 200 and sha256(latest) == replacement_digest, "post-overwrite GET serves new bytes"),
        ])


def slice_fill(nginx: Path | None = None) -> int:
    block, size = 65536, 4194304
    with LiveRun("tier_slice", nginx) as run:
        topology = TierTopology(run, 11712, 11713, 8507)
        directives = f"brix_cache_store posix:{topology.client}/cache; brix_cache_slice_size {block};"
        source = topology.origin / "root/big.bin"
        random_file(source, size)
        source.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        topology.start(directives, include_store=False)
        middle = size // 2
        got = run.root / "middle.bin"
        response = run.call(["curl", "-sS", "-o", got, "-w", "%{http_code}", "-r", f"{middle}-{middle + block - 1}", f"{topology.url}/big.bin"], check=False)
        status = _expression_1(response)
        expected = source.read_bytes()[middle:middle + block]
        cache = topology.client / "cache/big.bin"
        allocated = _expression_2(size, cache)
        first = run.root / "first.bin"
        response = run.call(["curl", "-sS", "-o", first, "-w", "%{http_code}", "-r", f"0-{block - 1}", f"{topology.url}/big.bin"], check=False)
        full = run.root / "full.bin"
        full_status = topology.download("big.bin", full)
        return _expression_3(status, expected, allocated, full_status, got, cache, size, first, block, full, source)


SCENARIOS = {"remote-stage": remote_stage, "remote-evict": remote_evict, "remote-store": remote_store, "sidecar-meta": lambda nginx: remote_store(nginx, sidecar=True), "slice-fill": slice_fill}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return SCENARIOS[ns.scenario](ns.nginx)
    except LiveFailure as exc:
        print(f"tier scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
