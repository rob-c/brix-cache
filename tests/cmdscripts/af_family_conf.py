"""Config grammar checks for brix_cache_origin_family."""

from __future__ import annotations

from pathlib import Path
import tempfile

from cmdscripts import run
from settings import NGINX_BIN, free_ports


VALID_TOKENS = ("auto", "inet", "inet6")
INVALID_TOKEN = "ipv4"


def write_config(prefix: Path, token: str, listen_port: int, upstream_port: int) -> Path:
    conf = prefix / "nginx.conf"
    cache = prefix / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    conf.write_text(
        f"""daemon off; error_log {prefix / 'e.log'} info; pid {prefix / 'pid'};
events {{ worker_connections 64; }}
stream {{ server {{
    listen 127.0.0.1:{listen_port}; brix_root on; brix_auth none;
    brix_storage_backend root://127.0.0.1:{upstream_port};
    brix_cache_store posix:{cache}; brix_cache_export /;
    brix_cache_origin_family {token};
}} }}
""",
        encoding="utf-8",
    )
    return conf


def check_token(nginx_bin: str, prefix: Path, token: str, expect_ok: bool) -> tuple[bool, str]:
    listen_port, upstream_port = free_ports(2)
    conf = write_config(prefix, token, listen_port, upstream_port)
    result = run([nginx_bin, "-t", "-c", str(conf)])
    ok = result.returncode == 0
    if ok == expect_ok:
        verb = "accepts" if expect_ok else "rejects"
        return True, f"{verb} brix_cache_origin_family {token}"
    detail = (result.stderr or result.stdout or "").strip().splitlines()
    tail = detail[-1] if detail else f"nginx -t rc={result.returncode}"
    return False, f"unexpected result for brix_cache_origin_family {token}: {tail}"


def run_checks(nginx_bin: str = NGINX_BIN, prefix: Path | None = None) -> list[tuple[bool, str]]:
    if prefix is None:
        prefix = Path(tempfile.mkdtemp(prefix="af_conf."))
    prefix.mkdir(parents=True, exist_ok=True)

    results = [check_token(nginx_bin, prefix, token, True) for token in VALID_TOKENS]
    results.append(check_token(nginx_bin, prefix, INVALID_TOKEN, False))

    return results


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    results = run_checks(nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
