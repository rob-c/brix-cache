"""Dedicated fleet helpers replacing tests/lib/dedicated.sh."""

from __future__ import annotations

from pathlib import Path
import os
import subprocess

from .nginx import force_stop_nginx, start_nginx
from .pki import regenerate_pki, substitute_config
from .refxrootd import start_ref_instance, stop_ref_ports
from .util import run, wait_ready_xrdfs


def start_dedicated_nginx(name: str, template: str, port: int, upstream_port: int | None = None) -> bool:
    test_root = Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test"))
    configs_dir = Path(os.environ.get("CONFIGS_DIR", str(Path(__file__).resolve().parents[1] / "configs")))
    nginx_bin = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    prefix = test_root / "dedicated" / name
    conf = prefix / "conf/nginx.conf"
    data = test_root / f"data-{name}"
    logs = prefix / "logs"
    for path in (conf.parent, data, logs, prefix / "tmp"):
        path.mkdir(parents=True, exist_ok=True)
    env = {
        "NGINX_PORT": str(port),
        "PORT": str(port),
        "DATA_DIR": str(data),
        "LOG_DIR": str(logs),
        "TMP_DIR": str(prefix / "tmp"),
        "NGINX_PREFIX": str(prefix),
    }
    if upstream_port is not None:
        env["UPSTREAM_PORT"] = str(upstream_port)
    substitute_config(configs_dir / template, conf, env)
    tested = run([str(nginx_bin), "-p", str(prefix), "-c", "conf/nginx.conf", "-t"])
    if tested.returncode != 0:
        return False
    started = run([str(nginx_bin), "-p", str(prefix), "-c", "conf/nginx.conf"])
    return started.returncode == 0


def start_krb5_tier() -> bool:
    nginx_bin = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    ldd = run(["ldd", str(nginx_bin)])
    if "libkrb5.so" not in ldd.stdout:
        return True
    helper = Path(__file__).resolve().parents[1] / "kdc_helpers.py"
    proc = run(["python3", str(helper), "up"])
    if proc.returncode not in (0, 3):
        return True
    return start_dedicated_nginx("krb5", "nginx_krb5.conf", int(os.environ.get("NGINX_KRB5_PORT", "11116")))


def start_all_dedicated() -> bool:
    force_stop_nginx()
    test_root = Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test"))
    pki_dir = Path(os.environ.get("PKI_DIR", str(test_root / "pki")))
    regenerate_pki(pki_dir)
    (test_root / "tokens").mkdir(parents=True, exist_ok=True)
    run(["python3", "utils/make_token.py", "init", str(test_root / "tokens")], cwd=Path(__file__).resolve().parents[2])
    start_nginx()
    start_ref_instance("upstream-redirect", int(os.environ.get("UPSTREAM_REDIRECT_BACKEND_PORT", "12120")), test_root / "data-upstream-redirect")
    start_dedicated_nginx("readonly", "nginx_readonly.conf", int(os.environ.get("READONLY_PORT", "11102")))
    start_dedicated_nginx("manager", "nginx_manager.conf", int(os.environ.get("MANAGER_PORT", "11101")))
    start_krb5_tier()
    return True


def stop_all_dedicated() -> None:
    force_stop_nginx()
    stop_ref_ports(11098, 11099, 11111, 11112, 11113)

