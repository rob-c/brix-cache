"""nginx lifecycle helpers replacing tests/lib/nginx.sh."""

from __future__ import annotations

from pathlib import Path
import os

from .pki import substitute_config
from .util import kill_pid_list, pids_on_port, run, wait_ready_xrdfs
from settings import SERVER_HOST


FIXED_NGINX_PORTS = [
    11094, 11095, 11096, 11097, 11099, 11100, 11101, 11102, 11103, 11104,
    11105, 11106, 11107, 11108, 11109, 11110, 11112, 11113, 11114, 11115,
    11116, 11117, 11120, 11121, 11122, 11123, 11124, 11125, 11126, 11160,
    11161, 11162, 11163, 11164, 11165, 11166, 11167, 11168, 11169, 11170,
    11172, 11173, 11174, 11176, 11177, 11178, 11180, 11181, 11182, 11183,
    11184, 11185, 11187, 11190, 11191, 11192, 11193, 11194, 11195, 11196,
    11197, 11198, 11199, 11200, 11201, 11202, 11203, 11204, 11205, 11206,
    11207, 11208, 11209, 11211, 11212, 11213, 11215, 11216, 11217, 11240,
    11241, 11243, 11244, 11245, 11246, 12500, 12602, 12603, 12604, 12605,
    12607, 12608, 12980, 13210, 18444, 18445, 18450, 18451, 18452, 18453,
    18454, 18455, 18456, 18457, 18458, 19450, 19451, 19452, 19453, 19454,
    19455, 19456, 22014, 22017,
]


def _env_path(name: str, default: str) -> Path:
    return Path(os.environ.get(name, default))


def start_nginx() -> bool:
    nginx_bin = _env_path("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
    test_root = _env_path("TEST_ROOT", "/tmp/xrd-test")
    prefix = _env_path("NGINX_PREFIX", str(test_root / "nginx"))
    configs = _env_path("CONFIGS_DIR", str(Path(__file__).resolve().parents[1] / "configs"))
    log_dir = _env_path("LOG_DIR", str(test_root / "logs"))
    data_dir = _env_path("DATA_DIR", str(test_root / "data"))
    tmp_dir = _env_path("TMP_DIR", str(test_root / "tmp"))
    conf_rel = os.environ.get("NGINX_CONF_REL", "conf/nginx.conf")
    main_conf = prefix / conf_rel
    for path in (log_dir, data_dir, tmp_dir, main_conf.parent):
        path.mkdir(parents=True, exist_ok=True)
    if os.environ.get("NGINX_CONF_PREGENERATED") != "1":
        substitute_config(configs / "nginx_shared.conf", main_conf)
    pid = log_dir / "nginx.pid"
    if pid.exists():
        try:
            os.kill(int(pid.read_text().strip()), 0)
            return True
        except (OSError, ValueError):
            pass
    started = run([str(nginx_bin), "-p", str(prefix), "-c", conf_rel])
    if started.returncode != 0:
        raise RuntimeError(started.stderr or started.stdout)
    if not os.environ.get("SKIP_XRDFS_CHECK"):
        wait_ready_xrdfs(f"root://{SERVER_HOST}:{os.environ.get('NGINX_PORT', '11094')}")
    return True


def stop_nginx() -> None:
    nginx_bin = _env_path("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
    test_root = _env_path("TEST_ROOT", "/tmp/xrd-test")
    prefix = _env_path("NGINX_PREFIX", str(test_root / "nginx"))
    conf_rel = os.environ.get("NGINX_CONF_REL", "conf/nginx.conf")
    run([str(nginx_bin), "-p", str(prefix), "-c", conf_rel, "-s", "stop"])
    log_dir = _env_path("LOG_DIR", str(test_root / "logs"))
    for pid_file in log_dir.glob("*.pid"):
        try:
            kill_pid_list([int(pid_file.read_text().strip())])
        except (OSError, ValueError):
            pass


def force_stop_nginx() -> None:
    stop_nginx()
    test_root = _env_path("TEST_ROOT", "/tmp/xrd-test")
    for pid_file in test_root.glob("dedicated/*/logs/nginx.pid"):
        try:
            kill_pid_list([int(pid_file.read_text().strip())])
        except (OSError, ValueError):
            pass
    pids = []
    for port in FIXED_NGINX_PORTS:
        pids.extend(pids_on_port(port))
    kill_pid_list(sorted(set(pids)))

