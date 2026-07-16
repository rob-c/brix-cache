"""Direct Python ports for metadata/reaper/audit live shell scenarios."""

from __future__ import annotations

import argparse
from pathlib import Path
import os
import shutil
import subprocess
import sys
import time

from cmdscripts.compile_run import REPO_ROOT
from cmdscripts.live_common import LiveFailure, LiveRun, random_file, sha256


def _checks(items: list[tuple[bool, str]]) -> int:
    for ok, message in items:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in items) else 1


def xmeta() -> int:
    binary = Path("/tmp/xmeta_ut")
    sample = Path("/tmp/xmeta_sample.cinfo")
    build = subprocess.run(
        [
            "gcc",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(REPO_ROOT / "src"),
            "-o",
            str(binary),
            str(REPO_ROOT / "src/fs/meta/xmeta_unittest.c"),
            str(REPO_ROOT / "src/fs/meta/xmeta.c"),
            str(REPO_ROOT / "src/fs/meta/xmeta_encode.c"),
            str(REPO_ROOT / "src/fs/meta/xmeta_decode.c"),
            str(REPO_ROOT / "src/core/compat/crc32c.c"),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if build.returncode:
        print(build.stderr or build.stdout, file=sys.stderr)
        return 1
    unit = subprocess.run([str(binary), str(sample)], capture_output=True, text=True)
    checks = [(unit.returncode == 0, "codec unit tests")]
    xrdpfc = shutil.which("xrdpfc_print")
    if xrdpfc is None:
        print("  SKIP xrdpfc_print not installed")
        binary.unlink(missing_ok=True)
        sample.unlink(missing_ok=True)
        return _checks(checks)
    stock = subprocess.run([xrdpfc, "-v", str(sample)], capture_output=True, text=True)
    output = stock.stdout + stock.stderr
    checks.extend(
        [
            ("version 4" in output, "stock reads version 4"),
            ("file_size 2560 kB" in output, "stock reads file_size"),
            ("buffer_size 1024 kB" in output, "stock reads buffer_size"),
            ("n_blocks 3" in output, "stock reads n_blocks"),
            ("n_downloaded 2" in output, "stock reads bitmap"),
            ("0 x.x" in output, "stock bit order matches"),
            ("N_acc_total=3" in output, "stock reads access count"),
        ]
    )
    binary.unlink(missing_ok=True)
    sample.unlink(missing_ok=True)
    return _checks(checks)


def nonstaged_reap(nginx: Path | None = None) -> int:
    with LiveRun("nsreap", nginx) as run:
        export = run.mkdir("export")
        (export / "sub").mkdir()
        for name in ("tmp", "logs"):
            run.mkdir(name)
        config = run.write(
            run.root / "nginx.conf",
            f"""daemon on; error_log {run.root}/logs/e.log info; pid {run.root}/nginx.pid;
worker_processes 1;
events {{ worker_connections 64; }}
http {{ client_body_temp_path {run.root}/tmp; server {{ listen 127.0.0.1:8583;
  location / {{ dav_methods PUT DELETE;
    brix_webdav on; brix_storage_backend posix:{export}; brix_webdav_auth none; brix_allow_write on; }} }} }}
""",
        )
        dead = 999999
        (export / f"a.bin.xrd-tmp.{dead}.111").write_text("dead1")
        (export / "sub" / f"c.bin.xrd-tmp.{dead}.222").write_text("dead2")
        live_name = f"b.bin.xrd-tmp.{os.getpid()}.333"
        (export / live_name).write_text("live")
        (export / "keep.bin").write_text("real")
        run.start_nginx(run.root, config, 8583)
        time.sleep(1)
        source = run.root / "src.bin"
        digest = random_file(source, 200000)
        code = run.curl_status("http://127.0.0.1:8583/real.bin", "-T", str(source))
        log = (run.root / "logs/e.log").read_text(errors="replace")
        return _checks(
            [
                (not (export / f"a.bin.xrd-tmp.{dead}.111").exists(), "dead-owner temp reaped"),
                (not (export / "sub" / f"c.bin.xrd-tmp.{dead}.222").exists(), "nested dead-owner temp reaped"),
                ((export / live_name).exists(), "live-owner temp kept"),
                ((export / "keep.bin").exists(), "normal file untouched"),
                ("reaped" in log and "orphaned upload temp" in log, "reaper logged cleanup"),
                (code == 201 and sha256(export / "real.bin") == digest, "PUT 201 byte-exact"),
            ]
        )


def sd_s3_meta(nginx: Path | None = None) -> int:
    smoke = REPO_ROOT / "client/bin/sd_s3_meta_smoke"
    if not smoke.exists():
        built = subprocess.run(["make", "sd-s3-meta-smoke"], cwd=REPO_ROOT / "client", capture_output=True, text=True)
        if built.returncode:
            print("SKIP: sd_s3_meta_smoke harness is unavailable")
            return 0
    with LiveRun("sd_s3_meta", nginx) as run:
        s3root, logs = run.mkdir("s3root"), run.mkdir("logs")
        config = run.write(
            run.root / "nginx.conf",
            f"""daemon on; error_log {logs}/e.log info; pid {run.root}/nginx.pid;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{
    server {{
        listen 127.0.0.1:9012;
        location / {{
            brix_s3 on;
            brix_storage_backend posix:{s3root};
            brix_s3_bucket testbucket;
            brix_allow_write on;
        }}
    }}
}}
""",
        )
        run.start_nginx(run.root, config, 9012)
        seed = run.call(
            [
                "curl",
                "-sS",
                "-X",
                "PUT",
                "-H",
                "x-amz-meta-foo: bar",
                "--data-binary",
                "payload",
                "http://127.0.0.1:9012/testbucket/obj.txt",
            ],
            check=False,
        )
        smoke_run = run.call([smoke, "127.0.0.1", "9012", "/testbucket/obj.txt"], check=False)
        return _checks([(seed.returncode == 0, "seed object with user metadata"), (smoke_run.returncode == 0, "sd_s3 metadata smoke harness passed")])


def xfer_audit_sink(nginx: Path | None = None) -> int:
    xrdcp = REPO_ROOT / "client/bin/xrdcp"
    if not xrdcp.exists():
        print(f"SKIP: no xrdcp client at {xrdcp}")
        return 0
    with LiveRun("xfer_audit", nginx) as run:
        origin = run.mkdir("o")
        for name in ("root", "logs"):
            (origin / name).mkdir()
        origin_conf = run.write(
            origin / "nginx.conf",
            f"""daemon on; error_log {origin}/logs/e.log info; pid {origin}/nginx.pid;
events {{ worker_connections 64; }}
stream {{ server {{
    listen 127.0.0.1:11774; brix_root on; brix_export {origin}/root;
    brix_auth none; brix_allow_write on;
}} }}
""",
        )
        run.start_nginx(origin, origin_conf, 11774)

        def start_node(extra: str = "") -> Path:
            node = run.mkdir("b")
            shutil.rmtree(node, ignore_errors=True)
            for name in ("export", "stage", "elog"):
                (node / name).mkdir(parents=True, exist_ok=True)
            conf = run.write(
                node / "nginx.conf",
                f"""daemon on; error_log {node}/elog/e.log info; pid {node}/nginx.pid;
{extra}
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{
    listen 127.0.0.1:11775; brix_root on; brix_export {node}/export;
    brix_auth none; brix_allow_write on; brix_upload_resume off;
    brix_storage_backend root://127.0.0.1:11774;
    brix_stage on;
    brix_stage_store posix:{node}/stage;
    brix_stage_flush sync;
}} }}
""",
            )
            run.start_nginx(node, conf, 11775)
            return node

        def upload(name: str) -> bool:
            source = run.root / "src.bin"
            random_file(source, 65536)
            return run.call([xrdcp, "-f", source, f"root://127.0.0.1:11775//{name}"], check=False).returncode == 0

        node = start_node()
        first = upload("a.bin")
        fallback_log = node / "elog/xfer_audit.log"
        # start_node() wipes the node dir on restart — capture the audit
        # sink's state now, before the next lifecycle destroys it.
        fallback_audit = fallback_log.read_text(errors="replace") if fallback_log.exists() else ""
        fallback_notice = (node / "elog/e.log").read_text(errors="replace")
        run.stop_nginx(node)
        custom = run.mkdir("custom")
        node = start_node(f"env BRIX_XFER_AUDIT_LOG={custom}/audit.log;")
        explicit = upload("b.bin")
        run.stop_nginx(node)
        node = start_node(f"env BRIX_XFER_AUDIT_LOG={run.root}/no-such-dir/audit.log;")
        unwritable = upload("c.bin")
        explicit_error = (node / "elog/e.log").read_text(errors="replace")
        return _checks(
            [
                (first and 'path="/a.bin"' in fallback_audit, "fallback audit line beside error.log"),
                ("xfer: audit log at" in fallback_notice, "fallback announced with notice"),
                (explicit and (custom / "audit.log").exists() and 'path="/b.bin"' in (custom / "audit.log").read_text(errors="replace"), "explicit BRIX_XFER_AUDIT_LOG honored"),
                (unwritable, "transfer succeeds with unwritable explicit sink"),
                (not (node / "elog/xfer_audit.log").exists(), "explicit override does not fall back"),
                ("xfer: cannot open audit log" in explicit_error, "warn emitted for unwritable sink"),
            ]
        )


SCENARIOS = {
    "nonstaged-reap": nonstaged_reap,
    "sd-s3-meta": sd_s3_meta,
    "xfer-audit-sink": xfer_audit_sink,
    "xmeta": lambda _nginx=None: xmeta(),
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
