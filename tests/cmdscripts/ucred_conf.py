"""Parse-level checks for per-user credential directives."""

from __future__ import annotations

from pathlib import Path
import os

from cmdscripts.compile_run import result, run
from settings import BIND_HOST, NGINX_BIN


def write_config(prefix: Path, extra: str) -> Path:
    for name in ("logs", "export", "creds", "tmp", "proxy_temp", "fastcgi_temp", "uwsgi_temp", "scgi_temp"):
        (prefix / name).mkdir(parents=True, exist_ok=True)
    conf = prefix / "nginx.conf"
    conf.write_text(
        f"""daemon off; error_log {prefix / 'logs' / 'e.log'} info; pid {prefix / 'nginx.pid'};
events {{ worker_connections 16; }}
http {{
    access_log {prefix / 'logs' / 'access.log'};
    client_body_temp_path {prefix / 'tmp'};
    proxy_temp_path {prefix / 'proxy_temp'};
    fastcgi_temp_path {prefix / 'fastcgi_temp'};
    uwsgi_temp_path {prefix / 'uwsgi_temp'};
    scgi_temp_path {prefix / 'scgi_temp'};
    server {{ listen {BIND_HOST}:18443;
        location / {{ brix_webdav on; brix_webdav_auth none; brix_export {prefix / 'export'}; {extra} }}
    }}
}}
""",
        encoding="utf-8",
    )
    return conf


def nginx_test(prefix: Path, conf: Path, nginx_bin: str) -> bool:
    proc = run([nginx_bin, "-t", "-c", str(conf)], cwd=prefix)
    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode == 0:
        return True
    return "syntax is ok" in output and "Operation not permitted" in output


def run_checks(base: Path, nginx_bin: str = NGINX_BIN) -> list[tuple[bool, str]]:
    if not os.access(nginx_bin, os.X_OK):
        return [result(True, f"SKIP nginx binary not executable: {nginx_bin}")]
    results: list[tuple[bool, str]] = []
    conf = write_config(base, f"brix_storage_credential_dir {base / 'creds'}; brix_storage_credential_fallback deny;")
    results.append(result(nginx_test(base, conf, nginx_bin), "valid directives accepted"))
    conf = write_config(base, "brix_storage_credential_fallback sometimes;")
    results.append(result(not nginx_test(base, conf, nginx_bin), "bad fallback value rejected"))
    conf = write_config(base, "")
    results.append(result(nginx_test(base, conf, nginx_bin), "defaults (absent) parse"))
    return results


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="ucred_conf.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
