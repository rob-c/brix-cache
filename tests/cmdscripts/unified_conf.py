"""Python port of tests/run_unified_conf.sh."""

from __future__ import annotations

from pathlib import Path
import argparse
import os
import shutil
import subprocess
import sys
import tempfile


def _run_nginx_test(nginx: Path, prefix: Path, name: str, expect_fail: bool, body: str) -> tuple[bool, str]:
    config = prefix / "nginx.conf"
    config.write_text(
        f"""daemon off; pid {prefix}/nginx.pid; error_log {prefix}/logs/err.log warn;
thread_pool default threads=2;
events {{ worker_connections 64; }}
http {{ {body} }}
"""
    )
    proc = subprocess.Popen(
        [str(nginx), "-t", "-c", str(config), "-p", str(prefix)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = proc.communicate()
    ok = proc.returncode != 0 if expect_fail else proc.returncode == 0
    detail = name if ok else f"{name} (rc={proc.returncode}, expected {'failure' if expect_fail else 'success'}): {stderr or stdout}"
    return ok, detail


def run(nginx: Path | None = None) -> int:
    nginx_bin = nginx or Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    prefix = Path(tempfile.mkdtemp(prefix="unified-conf."))
    passed = 0
    failed: list[str] = []
    try:
        for name in ("logs", "data", "cache"):
            (prefix / name).mkdir(parents=True, exist_ok=True)
        cache = prefix / "cache"
        data = prefix / "data"
        cv = f"""brix_cvmfs on; brix_export {data};
    brix_storage_backend http://127.0.0.1:1;
    brix_cache_store posix:{cache};"""
        cases = [
            (
                "unified names parse in webdav location",
                False,
                f"""server {{ listen 127.0.0.1:18499;
  location /dav/ {{
    brix_webdav on;
    brix_webdav_auth none;
    brix_export {data};
    brix_cache_store posix:{cache};
    brix_cache_evict_at 85; brix_cache_evict_to 70;
  }} }}""",
            ),
            (
                "server-level brix_cache_store inherits",
                False,
                f"""server {{ listen 127.0.0.1:18499;
  brix_cache_store posix:{cache};
  brix_export {data};
  location /dav/ {{ brix_webdav on; brix_webdav_auth none; }} }}
server {{ listen 127.0.0.1:18498;
  brix_cache_store posix:{cache};
  brix_export {data};
  location /v/   {{ brix_s3 on; brix_s3_bucket b; }} }}""",
            ),
            (
                "brix_cache_evict_at rejects non-numeric",
                True,
                f"""server {{ listen 127.0.0.1:18499;
  location /dav/ {{ brix_webdav on; brix_webdav_auth none; brix_export {data};
    brix_cache_evict_at lots; }} }}""",
            ),
            (
                "two protocols in one location rejected",
                True,
                f"""server {{ listen 127.0.0.1:18499;
  location / {{ brix_webdav on; brix_webdav_auth none; brix_export {data};
               brix_s3 on; brix_s3_bucket b; }} }}""",
            ),
            (
                "two protocols on one port rejected",
                True,
                f"""server {{ listen 127.0.0.1:18499;
  location /dav/ {{ brix_webdav on; brix_webdav_auth none; brix_export {data}; }}
  location /v/   {{ brix_s3 on; brix_s3_bucket b; brix_export {data}; }} }}""",
            ),
            (
                "protocols on separate ports accepted",
                False,
                f"""server {{ listen 127.0.0.1:18499;
  location /dav/ {{ brix_webdav on; brix_webdav_auth none; brix_export {data}; }} }}
server {{ listen 127.0.0.1:18498;
  location /v/   {{ brix_s3 on; brix_s3_bucket b; brix_export {data}; }} }}""",
            ),
            (
                "brix_stage under cvmfs rejected",
                True,
                f"""server {{ listen 127.0.0.1:18499; location / {{ {cv}
  brix_stage on; brix_stage_store posix:{data}; }} }}""",
            ),
            (
                "brix_stage_store alone under cvmfs rejected",
                True,
                f"""server {{ listen 127.0.0.1:18499; location / {{ {cv}
  brix_stage_store posix:{data}; }} }}""",
            ),
            (
                "brix_cache_slice_size under cvmfs rejected",
                True,
                f"""server {{ listen 127.0.0.1:18499; location / {{ {cv} brix_cache_slice_size 1m; }} }}""",
            ),
            (
                "brix_allow_write under cvmfs rejected",
                True,
                f"""server {{ listen 127.0.0.1:18499; location / {{ {cv} brix_allow_write on; }} }}""",
            ),
            (
                "origin_select geo without brix_cvmfs_here rejected",
                True,
                f"""server {{ listen 127.0.0.1:18499; location / {{ {cv}
  brix_cvmfs_origin_select geo; }} }}""",
            ),
            (
                "cvmfs pure cache node without brix_export accepted",
                False,
                f"""server {{ listen 127.0.0.1:18499; location / {{
  brix_cvmfs on;
  brix_storage_backend http://127.0.0.1:1;
  brix_cache_store posix:{cache}; }} }}""",
            ),
        ]
        for name, expect_fail, body in cases:
            ok, detail = _run_nginx_test(nginx_bin, prefix, name, expect_fail, body)
            print(f"{'ok  -' if ok else 'FAIL-'} {detail}")
            if ok:
                passed += 1
            else:
                failed.append(detail)
        print(f"unified_conf: {passed} passed, {len(failed)} failed")
        return 0 if not failed else 1
    finally:
        shutil.rmtree(prefix, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    return run(ns.nginx)


if __name__ == "__main__":
    raise SystemExit(main())
