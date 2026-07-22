"""Duplicate brix_credential warning config checks."""

from __future__ import annotations

from pathlib import Path

from cmdscripts import run
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, NGINX_BIN

WARN = 'brix_credential "origin" is defined more than once'


def write_config(base: Path, stream_body: str) -> Path:
    (base / "logs").mkdir(parents=True, exist_ok=True)
    (base / "export").mkdir(parents=True, exist_ok=True)
    conf = base / "nginx.conf"
    conf.write_text(
        f"""daemon off; error_log stderr info; pid {base / 'nginx.pid'};
events {{ worker_connections 64; }}
stream {{
{stream_body}
    server {{
        listen {BIND_HOST}:{cmdscript_ports("credential_dup_warn")[0]}; brix_root on; brix_export {base / 'export'}; brix_auth none;
    }}
}}
""",
        encoding="utf-8",
    )
    return conf


def nginx_test(nginx_bin: str, conf: Path) -> tuple[int, str]:
    result = run([nginx_bin, "-p", str(conf.parent), "-c", str(conf), "-t"])
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def run_checks(base: Path, nginx_bin: str = NGINX_BIN) -> list[tuple[bool, str]]:
    duplicate = base / "duplicate"
    rc, output = nginx_test(
        nginx_bin,
        write_config(
            duplicate,
            """
    brix_credential origin { x509_proxy /tmp/p.pem; }
    brix_credential origin { x509_cert /tmp/c.pem; x509_key /tmp/k.pem; }
""",
        ),
    )
    results = [
        (WARN in output, "duplicate same-name credential warned at config load"),
        (rc == 0 and "test is successful" in output, "config with the duplicate still loads (warning, not error)"),
    ]

    single = base / "single"
    _, output = nginx_test(
        nginx_bin,
        write_config(single, "    brix_credential origin { x509_proxy /tmp/p.pem; }"),
    )
    results.append((WARN not in output and "defined more than once" not in output, "single credential block: no false warning"))

    distinct = base / "distinct"
    _, output = nginx_test(
        nginx_bin,
        write_config(
            distinct,
            """
    brix_credential origin  { x509_proxy /tmp/p.pem; }
    brix_credential origin2 { x509_cert /tmp/c.pem; x509_key /tmp/k.pem; }
""",
        ),
    )
    results.append((WARN not in output and "defined more than once" not in output, "distinct credential names: no false warning"))
    return results


def entry(argv: list[str]) -> int:
    nginx_bin = argv[0] if argv else NGINX_BIN
    import tempfile

    with tempfile.TemporaryDirectory(prefix="cred_dup.") as tmp:
        results = run_checks(Path(tmp), nginx_bin=nginx_bin)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    if all(ok for ok, _ in results):
        print("run_credential_dup_warn: ALL PASS")
        return 0
    print("run_credential_dup_warn: FAILURES")
    return 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
