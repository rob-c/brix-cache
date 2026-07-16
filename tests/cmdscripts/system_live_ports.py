"""Direct Python ports for compact live shell scenarios.

This module covers:
* tests/run_cache_af_family.sh
* tests/run_io_uring_backend.sh
* tests/run_ktls.sh
* tests/run_proxy_metadata_phase.sh
"""

from __future__ import annotations

import argparse
from pathlib import Path
import os
import re
import shutil
import signal
import subprocess
import sys
import time

from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT, random_file, sha256


def _checks(items: list[tuple[bool, str]]) -> int:
    for ok, message in items:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in items) else 1


def _stream_config(run: LiveRun, root: Path, pid_name: str, port: int, body: str) -> Path:
    return run.write(root / "nginx.conf", f"""daemon on; error_log {root}/logs/e.log info; pid {root}/{pid_name};
thread_pool default threads=4;
events {{ worker_connections 64; }}
stream {{ server {{ listen 127.0.0.1:{port}; {body} }} }}
""")


def cache_af_family(nginx: Path | None = None) -> int:
    xrdfs = REPO_ROOT / "client/bin/xrdfs"
    if not xrdfs.exists():
        print(f"SKIP: no xrdfs client available at {xrdfs}")
        return 0
    with LiveRun("cache_af", nginx) as run:
        origin, node = run.mkdir("o"), run.mkdir("n")
        for directory in (origin, node):
            (directory / "logs").mkdir(exist_ok=True)
        (origin / "root").mkdir()
        (node / "cache").mkdir()
        origin_conf = _stream_config(
            run,
            origin,
            "nginx.pid",
            11940,
            f"brix_root on; brix_export {origin}/root; brix_auth none;",
        )
        run.start_nginx(origin, origin_conf, 11940)
        random_file(origin / "root/f.bin", 600000)

        def start_node(family: str) -> None:
            conf = _stream_config(
                run,
                node,
                "nginx.pid",
                11941,
                f"""brix_root on; brix_auth none;
    brix_storage_backend root://127.0.0.1:11940;
    brix_cache_store posix:{node}/cache; brix_cache_export /;
    brix_cache_origin_family {family};""",
            )
            run.start_nginx(node, conf, 11941)

        def stop_node() -> None:
            run.stop_nginx(node)
            shutil.rmtree(node / "cache", ignore_errors=True)
            (node / "cache").mkdir(exist_ok=True)

        def cat_bytes() -> subprocess.CompletedProcess:
            try:
                return subprocess.run(
                    [str(xrdfs), "root://127.0.0.1:11941", "cat", "/f.bin"],
                    capture_output=True, timeout=60,
                )
            except subprocess.TimeoutExpired:
                return subprocess.CompletedProcess([], 124, stdout=b"", stderr=b"timed out")

        got4, got6, gota = run.root / "4.got", run.root / "6.got", run.root / "a.got"
        start_node("inet")
        inet = cat_bytes()
        got4.write_bytes(inet.stdout)
        stop_node()
        start_node("inet6")
        before = time.monotonic()
        inet6 = cat_bytes()
        elapsed = time.monotonic() - before
        got6.write_bytes(inet6.stdout)
        stop_node()
        start_node("auto")
        auto = cat_bytes()
        gota.write_bytes(auto.stdout)
        return _checks([
            (inet.returncode == 0 and got4.read_bytes() == (origin / "root/f.bin").read_bytes(), "inet: IPv4 origin fill byte-exact"),
            (inet6.returncode != 0 or got6.read_bytes() != (origin / "root/f.bin").read_bytes(), "inet6: fill fails without IPv4 fallback"),
            (elapsed < 30, f"inet6: failed fast ({elapsed:.1f}s < 30s)"),
            (auto.returncode == 0 and gota.read_bytes() == (origin / "root/f.bin").read_bytes(), "auto: fill byte-exact"),
        ])


def proxy_metadata_phase(nginx: Path | None = None) -> int:
    xrdfs, xrdcp = REPO_ROOT / "client/bin/xrdfs", REPO_ROOT / "client/bin/xrdcp"
    if not xrdfs.exists() or not xrdcp.exists():
        print("SKIP: no xrd command-line clients available")
        return 0
    with LiveRun("proxy_meta", nginx) as run:
        origin, proxy = run.mkdir("o"), run.mkdir("p")
        for directory in (origin, proxy):
            (directory / "logs").mkdir(exist_ok=True)
        (origin / "root").mkdir()
        origin_conf = _stream_config(
            run,
            origin,
            "nginx.pid",
            11644,
            f"brix_root on; brix_storage_backend posix:{origin}/root; brix_auth none; brix_allow_write on; brix_upload_resume off;",
        )
        proxy_conf = _stream_config(
            run,
            proxy,
            "nginx.pid",
            11645,
            "brix_root on; brix_auth none; brix_tap_proxy on; brix_tap_proxy_upstream 127.0.0.1:11644; brix_tap_proxy_auth anonymous;",
        )
        run.start_nginx(origin, origin_conf, 11644)
        run.start_nginx(proxy, proxy_conf, 11645)
        endpoint = "root://127.0.0.1:11645"
        source = run.root / "w.bin"
        random_file(source, 4096)
        mkdir = run.call([xrdfs, endpoint, "mkdir", "/d"], check=False).returncode == 0
        put = run.call([xrdcp, "-f", source, f"{endpoint}//d/f.bin"], check=False).returncode == 0
        put_landed = (origin / "root/d/f.bin").exists()
        listing = run.call([xrdfs, endpoint, "ls", "/d"], check=False).stdout
        stat = run.call([xrdfs, endpoint, "stat", "/d/f.bin"], check=False).stdout
        chmod = run.call([xrdfs, endpoint, "chmod", "/d/f.bin", "740"], check=False).returncode == 0
        mode = oct((origin / "root/d/f.bin").stat().st_mode & 0o777) if (origin / "root/d/f.bin").exists() else ""
        xset = run.call([xrdfs, endpoint, "xattr", "set", "/d/f.bin", "user.test", "hello"], check=False)
        xget = run.call([xrdfs, endpoint, "xattr", "get", "/d/f.bin", "user.test"], check=False).stdout
        xlist = run.call([xrdfs, endpoint, "xattr", "ls", "/d/f.bin"], check=False).stdout
        moved = run.call([xrdfs, endpoint, "mv", "/d/f.bin", "/d/g.bin"], check=False).returncode == 0
        mv_landed = (origin / "root/d/g.bin").exists()
        removed = run.call([xrdfs, endpoint, "rm", "/d/g.bin"], check=False).returncode == 0
        return _checks([
            (mkdir and (origin / "root/d").is_dir(), "mkdir forwarded to origin"),
            (put and put_landed, "put forwarded to origin"),
            ("f.bin" in listing, "ls lists child through proxy"),
            ("4096" in stat, "stat reports correct size through proxy"),
            (chmod and mode != "", f"chmod reached origin ({mode})"),
            (xset.returncode == 0 and "hello" in xget, "xattr set/get round-trips"),
            ("user.test" in xlist, "xattr ls lists name through proxy"),
            (moved and mv_landed, "mv forwarded to origin"),
            (removed and not (origin / "root/d/g.bin").exists(), "rm forwarded to origin"),
        ])


def io_uring_backend(nginx: Path | None = None) -> int:
    xrdcp = Path(shutil.which("xrdcp") or REPO_ROOT / "client/bin/xrdcp")
    if not xrdcp.exists():
        print("SKIP: no xrdcp client available")
        return 0
    with LiveRun("uring_be", nginx) as run:
        local, origin, backend = run.mkdir("l"), run.mkdir("o"), run.mkdir("b")
        for directory, subdir in ((local, "export"), (origin, "root"), (backend, "export")):
            (directory / subdir).mkdir()
            (directory / "logs").mkdir(exist_ok=True)
        local_conf = _stream_config(
            run,
            local,
            "nginx.pid",
            11780,
            f"brix_root on; brix_export {local}/export; brix_auth none; brix_allow_write on; brix_io_uring on;",
        )
        probe = run.call([run.nginx, "-p", local, "-c", local_conf], check=False)
        if probe.returncode:
            print(f"SKIP: io_uring unavailable for this binary/kernel: {probe.stderr.strip()}")
            return 0
        run.pidfiles.append(local / "nginx.pid")
        time.sleep(1)
        log = (local / "logs/e.log").read_text(errors="replace")
        if "io_uring disk-I/O backend active" not in log:
            print("SKIP: io_uring did not activate")
            return 0
        big = run.root / "big.bin"
        big_digest = random_file(big, 33554432)
        local_put = run.call([xrdcp, "-f", big, "root://127.0.0.1:11780//big.bin"], check=False)
        origin_conf = _stream_config(
            run,
            origin,
            "nginx.pid",
            11778,
            f"brix_root on; brix_export {origin}/root; brix_auth none; brix_allow_write on; brix_upload_resume off;",
        )
        backend_conf = _stream_config(
            run,
            backend,
            "nginx.pid",
            11779,
            f"""brix_root on; brix_export {backend}/export; brix_auth none; brix_allow_write on; brix_upload_resume off;
    brix_io_uring on; brix_storage_backend root://127.0.0.1:11778;""",
        )
        run.start_nginx(origin, origin_conf, 11778)
        run.start_nginx(backend, backend_conf, 11779)
        remote = run.root / "remote.bin"
        remote_digest = random_file(remote, 2600000)
        remote_put = run.call([xrdcp, "-f", remote, "root://127.0.0.1:11779//remote.bin"], check=False)
        killed = subprocess.Popen([str(xrdcp), "-f", "--xrate", "8m", str(big), "root://127.0.0.1:11780//killed.bin"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        if killed.poll() is None:
            killed.kill()
        time.sleep(3)
        crash_log = (local / "logs/e.log").read_text(errors="replace")
        probe_file = run.root / "probe.bin"
        probe_digest = random_file(probe_file, 500000)
        probe_put = run.call([xrdcp, "-f", probe_file, "root://127.0.0.1:11780//probe.bin"], check=False)
        return _checks([
            (local_put.returncode == 0 and sha256(local / "export/big.bin") == big_digest, "32 MiB local write completed"),
            (remote_put.returncode == 0 and sha256(origin / "root/remote.bin") == remote_digest, "remote write-through byte-exact on origin"),
            ("exited on signal" not in crash_log, "no worker death after mid-write client kill"),
            (probe_put.returncode == 0 and sha256(local / "export/probe.bin") == probe_digest, "server still serving after abrupt disconnect"),
        ])


def ktls(nginx: Path | None = None) -> int:
    nginx_bin = nginx or Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    generated = Path("/tmp/xrd-perf-test/nginx.gen.conf")
    data = Path("/tmp/xrd-load/data")
    if not generated.exists():
        print(f"SKIP: {generated} missing; run the load-test setup first")
        return 0
    data.mkdir(parents=True, exist_ok=True)
    source = data / "ktls_t.bin"
    random_file(source, 4194304)

    def mkconf(value: str) -> Path:
        text = generated.read_text()
        patched = re.sub(r"(brix_webdav\s+on;)", rf"\1\n        brix_ktls {value};", text, count=1)
        path = Path(f"/tmp/ktls_t_{value}.conf")
        path.write_text(patched)
        return path

    def tls_tx_sw() -> int:
        stat = Path("/proc/net/tls_stat")
        if not stat.exists():
            return 0
        for line in stat.read_text(errors="ignore").splitlines():
            if line.startswith("TlsTxSw"):
                parts = line.split()
                return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        return 0

    def start(config: Path) -> bool:
        subprocess.run(["pkill", "-9", "-f", "objs/nginx.*xrd-perf-test"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proc = subprocess.Popen([str(nginx_bin), "-c", str(config), "-p", "/tmp/xrd-perf-test"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        proc.communicate()
        if proc.returncode:
            return False
        from lib_py.util import wait_tcp
        return wait_tcp("127.0.0.1", 12792, 15)

    try:
        invalid = subprocess.run([str(nginx_bin), "-t", "-c", str(mkconf("maybe")), "-p", "/tmp/xrd-perf-test"], capture_output=True, text=True)
        invalid_ok = invalid.returncode != 0 and 'must be "on" or "off"' in (invalid.stderr + invalid.stdout)
        checks = [(invalid_ok, "invalid brix_ktls value rejected by nginx -t")]
        for value, label in (("on", "brix_ktls on"), ("off", "brix_ktls off")):
            out = Path(f"/tmp/ktls_t_{value}_dl.bin")
            started = start(mkconf(value))
            before = tls_tx_sw()
            curl = subprocess.run(["curl", "-s", "-o", str(out), "-k", "--tls13-ciphers", "TLS_AES_128_GCM_SHA256", "https://localhost:12792/ktls_t.bin"], capture_output=True)
            after = tls_tx_sw()
            checks.append((started and curl.returncode == 0 and out.exists() and out.read_bytes() == source.read_bytes(), f"{label}: HTTPS GET byte-identical"))
            if value == "on":
                print(f"  info kTLS TX sessions this GET: {after - before}")
        return _checks(checks)
    finally:
        subprocess.run(["pkill", "-9", "-f", "objs/nginx.*xrd-perf-test"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        source.unlink(missing_ok=True)
        Path("/tmp/ktls_t_on_dl.bin").unlink(missing_ok=True)
        Path("/tmp/ktls_t_off_dl.bin").unlink(missing_ok=True)


SCENARIOS = {
    "cache-af-family": cache_af_family,
    "io-uring-backend": io_uring_backend,
    "ktls": ktls,
    "proxy-metadata-phase": proxy_metadata_phase,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return SCENARIOS[ns.scenario](ns.nginx)
    except LiveFailure as exc:
        print(f"{ns.scenario} failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
