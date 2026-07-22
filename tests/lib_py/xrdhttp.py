"""XrdHttp lifecycle helpers replacing tests/lib/xrdhttp.sh."""

from __future__ import annotations

from pathlib import Path
import os

from .refxrootd import ref_launch
from .util import find_xrd_library, find_xrd_sec_lib, kill_pid_list, pids_on_port, render_cfg, run, wait_tcp
from settings import BIND_HOST


def start_xrdhttp() -> bool:
    http_lib = find_xrd_library("libXrdHttp-5.so", "libXrdHttp.so")
    tpc_lib = find_xrd_library("libXrdHttpTPC-5.so", "libXrdHttpTPC.so")
    if http_lib is None or tpc_lib is None:
        return True
    test_root = Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test"))
    pki_dir = Path(os.environ.get("PKI_DIR", str(test_root / "pki")))
    configs_dir = Path(os.environ.get("CONFIGS_DIR", str(Path(__file__).resolve().parents[1] / "configs")))
    xrdhttp_dir = Path(os.environ.get("XRDHTTP_DIR", str(test_root / "xrdhttp")))
    data_dir = Path(os.environ.get("XRDHTTP_DATA_DIR", str(test_root / "data-xrdhttp")))
    port = int(os.environ.get("REF_XRDHTTP_HTTP_PORT", "11113"))
    root_port = int(os.environ.get("REF_XRDHTTP_ROOT_PORT", "11112"))
    if pids_on_port(port):
        return True
    cfg = xrdhttp_dir / "xrdhttp.cfg"
    log = xrdhttp_dir / "xrdhttp.log"
    for path in (xrdhttp_dir, data_dir, xrdhttp_dir / "admin-conf", xrdhttp_dir / "run-conf"):
        path.mkdir(parents=True, exist_ok=True)
    sec = find_xrd_sec_lib() or Path("/usr/lib64/libXrdSec-5.so")
    render_cfg(
        configs_dir / "xrootd_xrdhttp.conf",
        cfg,
        DATA_DIR=str(data_dir),
        ADMIN_DIR=str(xrdhttp_dir / "admin-conf"),
        RUN_DIR=str(xrdhttp_dir / "run-conf"),
        ROOT_PORT=str(root_port),
        SECLIB=str(sec),
        HTTP_PORT=str(port),
        HTTP_LIB=str(http_lib),
        SERVER_CERT=str(pki_dir / "server/hostcert.pem"),
        SERVER_KEY=str(pki_dir / "server/hostkey.pem"),
        CA_DIR=str(pki_dir / "ca"),
        TPC_LIB=str(tpc_lib),
    )
    ref_launch(cfg, log)
    return wait_tcp(BIND_HOST, port, timeout=10)


def stop_xrdhttp() -> None:
    test_root = Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test"))
    xrdhttp_dir = Path(os.environ.get("XRDHTTP_DIR", str(test_root / "xrdhttp")))
    pids = []
    for pid_file in (xrdhttp_dir / "xrdhttp.pid", xrdhttp_dir / "run-conf/brix.pid"):
        try:
            pids.append(int(pid_file.read_text().strip()))
        except (OSError, ValueError):
            pass
    pids.extend(pids_on_port(int(os.environ.get("REF_XRDHTTP_HTTP_PORT", "11113"))))
    pids.extend(pids_on_port(int(os.environ.get("REF_XRDHTTP_ROOT_PORT", "11112"))))
    kill_pid_list(sorted(set(pids)))


def status_xrdhttp() -> str:
    port = int(os.environ.get("REF_XRDHTTP_HTTP_PORT", "11113"))
    return "running" if pids_on_port(port) or wait_tcp(BIND_HOST, port, timeout=0.5) else "stopped"

