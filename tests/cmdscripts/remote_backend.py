"""Direct Python ports for the remote-root backend shell scenarios."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import sys
import time

from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT, random_file, sha256
from settings import BIND_HOST, HOST


def _stream_config(run: LiveRun, root: Path, port: int, *, backend: int | None = None, writable: bool = False) -> Path:
    backend_line = f" brix_storage_backend root://{HOST}:{backend};" if backend else ""
    write_line = " brix_allow_write on; brix_upload_resume off;" if writable else ""
    return run.write(root / "nginx.conf", f"""daemon on; error_log {root}/logs/e.log info; pid {root}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{ listen {BIND_HOST}:{port}; brix_root on; brix_export {root}/export; brix_auth none;{write_line}{backend_line} }} }}
""")


def _dav_config(run: LiveRun, root: Path, port: int, origin: int, *, writable: bool = False, staging: bool = False) -> Path:
    write_line = "dav_methods PUT DELETE; brix_allow_write on;" if writable else ""
    staging_line = "brix_webdav_storage_staging on;" if staging else ""
    return run.write(root / "nginx.conf", f"""daemon on; error_log {root}/logs/e.log info; pid {root}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{ client_body_temp_path {root}/tmp; client_max_body_size 50m; server {{ listen {BIND_HOST}:{port};
  location / {{ {write_line} brix_webdav on; brix_export {root}/export; brix_webdav_auth none;
    brix_storage_backend root://{HOST}:{origin}; {staging_line} }} }} }}
""")


def _make_nodes(run: LiveRun, origin_port: int, node_port: int, *, webdav: bool, writable: bool, staging: bool = False) -> tuple[Path, Path]:
    origin, node = run.mkdir("o"), run.mkdir("n")
    for directory in (origin, node):
        for name in ("export", "logs", "tmp"):
            (directory / name).mkdir()
    run.start_nginx(origin, _stream_config(run, origin, origin_port, writable=True), origin_port)
    config = _dav_config(run, node, node_port, origin_port, writable=writable, staging=staging) if webdav else _stream_config(run, node, node_port, backend=origin_port, writable=writable)
    run.start_nginx(node, config, node_port)
    return origin, node


def _checks(values: list[tuple[bool, str]]) -> int:
    for passed, text in values:
        print(f"  {'ok  ' if passed else 'FAIL'} {text}")
    return 0 if all(passed for passed, _ in values) else 1


def serve_offload(nginx: Path | None = None) -> int:
    with LiveRun("rbserve", nginx) as run:
        origin, node = _make_nodes(run, 11722, 8531, webdav=True, writable=False)
        small, big = origin / "export/small.bin", origin / "export/big.bin"
        random_file(small, 500000)
        random_file(big, 2600000)
        url = f"http://{HOST}:8531"
        got = run.root / "small.got"
        status = run.call(["curl", "-sS", "-o", got, "-w", "%{http_code}", f"{url}/small.bin"], check=False).stdout.strip()
        ranged = run.curl_bytes(f"{url}/big.bin", "-r", "1000-1010")
        big_got = run.root / "big.got"
        big_status = run.call(["curl", "-sS", "-o", big_got, "-w", "%{http_code}", f"{url}/big.bin"], check=False).stdout.strip()
        log = (node / "logs/e.log").read_text(errors="replace")
        return _checks([
            (status == "200" and sha256(got) == sha256(small), "remote backend GET byte-exact"),
            ("serve offload: materialising remote" in log, "serve used the thread-pool offload path"),
            (ranged == big.read_bytes()[1000:1011], "range GET byte-exact"),
            (big_status == "200" and sha256(big_got) == sha256(big), "multi-chunk GET byte-exact"),
        ])


def webdav_write(nginx: Path | None = None, *, staging: bool = False) -> int:
    label, origin_port, port = ("remote_stg", 11657, 8476) if staging else ("remote_dav", 11650, 8470)
    with LiveRun(label, nginx) as run:
        origin, node = _make_nodes(run, origin_port, port, webdav=True, writable=True, staging=staging)
        one, two = run.root / "a.bin", run.root / "b.bin"
        first_digest, second_digest = random_file(one, 700000 if staging else 250000), random_file(two, 1800000)
        status_one = run.curl_status(f"http://{HOST}:{port}/a.bin", "-T", str(one))
        got = run.root / "a.got"
        got.write_bytes(run.curl_bytes(f"http://{HOST}:{port}/a.bin"))
        status_two = run.curl_status(f"http://{HOST}:{port}/b.bin", "-T", str(two))
        export_empty = not any((node / "export").iterdir())
        return _checks([
            (status_one in (200, 201, 204), f"first PUT accepted ({status_one})"),
            ((origin / "export/a.bin").exists() and sha256(origin / "export/a.bin") == first_digest, "first object landed byte-exact on origin"),
            (export_empty, "no local data copy remains after remote commit"),
            (sha256(got) == first_digest, "GET reads back byte-exact"),
            (status_two in (200, 201, 204) and (origin / "export/b.bin").exists() and sha256(origin / "export/b.bin") == second_digest, "multi-chunk PUT landed byte-exact"),
        ])


def stream_write(nginx: Path | None = None) -> int:
    xrdcp, xrdfs = REPO_ROOT / "client/bin/xrdcp", REPO_ROOT / "client/bin/xrdfs"
    with LiveRun("remote_bw", nginx) as run:
        origin, node = _make_nodes(run, 11650, 11651, webdav=False, writable=True)
        small, big = run.root / "small.bin", run.root / "big.bin"
        small_digest, big_digest = random_file(small, 300000), random_file(big, 2600000)
        target = f"root://{HOST}:11651"
        small_put = run.call([xrdcp, "-f", small, f"{target}//small.bin"], check=False).returncode
        output = run.call([xrdfs, target, "cat", "/small.bin"], check=False).stdout.encode()
        stat_out = run.call([xrdfs, target, "stat", "/small.bin"], check=False).stdout
        big_put = run.call([xrdcp, "-f", big, f"{target}//big.bin"], check=False).returncode
        return _checks([
            (small_put == 0 and (origin / "export/small.bin").exists() and sha256(origin / "export/small.bin") == small_digest, "stream write landed byte-exact on origin"),
            (not (node / "export/small.bin").exists(), "stream node kept no local copy"),
            (output == small.read_bytes(), "stream read-back byte-exact"),
            ("300000" in stat_out, "stat reports origin object size"),
            (big_put == 0 and (origin / "export/big.bin").exists() and sha256(origin / "export/big.bin") == big_digest, "multi-chunk stream write byte-exact"),
        ])


def metadata(nginx: Path | None = None) -> int:
    xrdcp, xrdfs = REPO_ROOT / "client/bin/xrdcp", REPO_ROOT / "client/bin/xrdfs"
    origin_port, stream_port, dav_port = 11658, 11659, 8477
    with LiveRun("remote_meta", nginx) as run:
        origin, stream, dav = run.mkdir("o"), run.mkdir("b"), run.mkdir("w")
        for directory in (origin, stream, dav):
            for name in ("export", "logs", "tmp"):
                (directory / name).mkdir()
        run.start_nginx(origin, _stream_config(run, origin, origin_port, writable=True), origin_port)
        run.start_nginx(stream, _stream_config(run, stream, stream_port, backend=origin_port, writable=True), stream_port)
        run.start_nginx(dav, _dav_config(run, dav, dav_port, origin_port, writable=True), dav_port)
        source = run.root / "a.bin"
        random_file(source, 4096)
        target = f"root://{HOST}:{stream_port}"
        copied = run.call([xrdcp, "-f", source, f"{target}//f.bin"], check=False).returncode == 0
        xset = run.call([xrdfs, target, "xattr", "set", "/f.bin", "user.color", "blue"], check=False).returncode == 0
        get = run.call([xrdfs, target, "xattr", "get", "/f.bin", "user.color"], check=False).stdout
        origin_get = run.call([xrdfs, f"root://{HOST}:{origin_port}", "xattr", "get", "/f.bin", "user.color"], check=False).stdout
        listing = run.call([xrdfs, target, "xattr", "ls", "/f.bin"], check=False).stdout
        renamed = run.call([xrdfs, target, "mv", "/f.bin", "/g.bin"], check=False).returncode == 0
        copy_status = run.curl_status(
            f"http://{HOST}:{dav_port}/g.bin",
            "-X", "COPY", "-H", f"Destination: http://{HOST}:{dav_port}/copy.bin",
        )
        origin_file, copied_file = origin / "export/g.bin", origin / "export/copy.bin"
        return _checks([
            (copied, "xrdcp upload reached remote origin"),
            (xset and "blue" in get and "blue" in origin_get, "xattr set/get forwards to origin"),
            ("user.color" in listing, "xattr list forwards to origin"),
            (renamed and origin_file.exists() and not (origin / "export/f.bin").exists(), "rename forwards to origin"),
            (copy_status in (200, 201, 204) and copied_file.exists() and sha256(copied_file) == sha256(origin_file), "WebDAV COPY forwards byte-exact origin copy"),
        ])


def stage_reconcile(nginx: Path | None = None) -> int:
    port = 8581
    with LiveRun("strec", nginx) as run:
        for name in ("backend", "stage", "journal", "tmp", "logs"):
            run.mkdir(name)
        config = run.write(run.root / "nginx.conf", f"""daemon on; error_log {run.root}/logs/e.log info; pid {run.root}/nginx.pid;
env BRIX_STAGE_JOURNAL_DIR={run.root}/journal;
worker_processes 1; thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{ client_body_temp_path {run.root}/tmp; server {{ listen {BIND_HOST}:{port}; location / {{
  dav_methods PUT DELETE; brix_webdav on; brix_export {run.root}/backend; brix_webdav_auth none; brix_allow_write on;
  brix_stage on; brix_stage_store posix:{run.root}/stage; brix_stage_flush async; }} }} }}
""")
        run.start_nginx(run.root, config, port)
        source = run.root / "src.bin"
        digest = random_file(source, 350000)
        status = run.curl_status(f"http://{HOST}:{port}/o.bin", "-T", str(source))
        pid = int((run.root / "nginx.pid").read_text())
        os.kill(pid, signal.SIGKILL)
        time.sleep(0.2)
        backend = run.root / "backend/o.bin"
        journal = list((run.root / "journal").glob("*.req"))
        staged = run.root / "stage/o.bin"
        if not backend.exists():
            run.start_nginx(run.root, config, port)
            time.sleep(1.5)
        got = run.root / "got.bin"
        get_status = run.call(["curl", "-sS", "-o", got, "-w", "%{http_code}", f"http://{HOST}:{port}/o.bin"], check=False).stdout.strip()
        return _checks([
            (status == 201, "async staged PUT accepted"),
            (backend.exists() or (journal and staged.exists()), "backend commit raced crash or durable stage journal survived"),
            (backend.exists() and sha256(backend) == digest, "reconcile preserved byte-exact backend object"),
            (get_status == "200" and sha256(got) == digest, "recovered object serves byte-exact"),
        ])


SCENARIOS = {"serve-offload": serve_offload, "meta": metadata, "stream-write": stream_write, "staging": lambda nginx: webdav_write(nginx, staging=True), "webdav": webdav_write, "stage-reconcile": stage_reconcile}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return SCENARIOS[ns.scenario](ns.nginx)  # type: ignore[misc]
    except LiveFailure as exc:
        print(f"remote backend scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
