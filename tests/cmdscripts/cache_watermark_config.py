"""Config validation for cache and staging watermark directives."""

from __future__ import annotations

from pathlib import Path

from cmdscripts import run
from settings import NGINX_BIN, free_port


def write_cache_config(base: Path, high: str, low: str = "", extra: str = "") -> Path:
    (base / "root").mkdir(parents=True, exist_ok=True)
    (base / "cache").mkdir(parents=True, exist_ok=True)
    (base / "logs").mkdir(parents=True, exist_ok=True)
    conf = base / "nginx.conf"
    conf.write_text(
        f"""daemon off; error_log {base / 'logs' / 'e.log'} info; pid {base / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{
    listen 127.0.0.1:{free_port()}; brix_root on; brix_auth none;
    brix_storage_backend root://127.0.0.1:1;
    brix_cache on; brix_cache_export {base / 'cache'}; {extra}
    {high} {low}
}} }}
""",
        encoding="utf-8",
    )
    return conf


def write_stage_config(base: Path, directives: str) -> Path:
    (base / "root").mkdir(parents=True, exist_ok=True)
    (base / "logs").mkdir(parents=True, exist_ok=True)
    conf = base / "nginx.conf"
    conf.write_text(
        f"""daemon off; error_log {base / 'logs' / 'e.log'} info; pid {base / 'nginx.pid'};
thread_pool default threads=2;
events {{ worker_connections 64; }}
stream {{ server {{
    listen 127.0.0.1:{free_port()}; brix_root on; brix_auth none;
    brix_storage_backend posix:{base / 'root'};
    brix_allow_write on; brix_write_through on; brix_wt_origin 127.0.0.1:1;
    {directives}
}} }}
""",
        encoding="utf-8",
    )
    return conf


def nginx_test(nginx_bin: str, conf: Path) -> tuple[int, str]:
    result = run([nginx_bin, "-p", str(conf.parent), "-c", str(conf), "-t"])
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def expect_ok(nginx_bin: str, conf: Path, message: str) -> tuple[bool, str]:
    rc, output = nginx_test(nginx_bin, conf)
    return rc == 0 and "syntax is ok" in output, message


def expect_reject(nginx_bin: str, conf: Path, pattern: str, message: str) -> tuple[bool, str]:
    rc, output = nginx_test(nginx_bin, conf)
    return rc != 0 and pattern.lower() in output.lower(), message


def run_checks(base: Path, nginx_bin: str = NGINX_BIN) -> list[tuple[bool, str]]:
    results: list[tuple[bool, str]] = []

    valid = base / "valid"
    results.append(
        expect_ok(
            nginx_bin,
            write_cache_config(valid, "brix_cache_high_watermark 90%;", "brix_cache_low_watermark 80%;"),
            "valid 90/80 pair accepted",
        )
    )

    inverted = base / "inverted"
    results.append(
        expect_reject(
            nginx_bin,
            write_cache_config(inverted, "brix_cache_high_watermark 70%;", "brix_cache_low_watermark 80%;"),
            "low_watermark must be greater than 0 and less than",
            "inverted pair rejected with EMERG",
        )
    )

    compat = base / "compat"
    results.append(
        expect_ok(
            nginx_bin,
            write_cache_config(compat, "brix_cache_eviction_threshold 0.85;"),
            "back-compat eviction_threshold loads",
        )
    )

    decimal = base / "decimal"
    results.append(
        expect_ok(
            nginx_bin,
            write_cache_config(decimal, "brix_cache_high_watermark 0.95;", "brix_cache_low_watermark 0.90;"),
            "decimal watermark form accepted",
        )
    )

    no_stage = base / "no_stage"
    results.append(
        expect_reject(
            nginx_bin,
            write_stage_config(no_stage, "brix_wt_stage_high_watermark 90%; brix_wt_stage_low_watermark 80%;"),
            "wt_stage_high_watermark requires",
            "staging watermark without stage_root rejected",
        )
    )

    stage = base / "stage"
    (stage / "stage").mkdir(parents=True, exist_ok=True)
    results.append(
        expect_ok(
            nginx_bin,
            write_stage_config(
                stage,
                f"brix_cache_wt_stage_root {stage / 'stage'}; "
                "brix_wt_stage_high_watermark 90%; brix_wt_stage_low_watermark 80%;",
            ),
            "staging valid pair accepted",
        )
    )

    stage_inverted = base / "stage_inverted"
    (stage_inverted / "stage").mkdir(parents=True, exist_ok=True)
    results.append(
        expect_reject(
            nginx_bin,
            write_stage_config(
                stage_inverted,
                f"brix_cache_wt_stage_root {stage_inverted / 'stage'}; "
                "brix_wt_stage_high_watermark 70%; brix_wt_stage_low_watermark 80%;",
            ),
            "wt_stage_low_watermark must be greater than 0",
            "staging inverted pair rejected",
        )
    )

    return results


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="wm_cfg.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_cache_watermark_config: ALL PASS")
        return 0
    print("run_cache_watermark_config: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
