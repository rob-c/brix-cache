"""Python port of tests/manage_test_servers.sh."""

from __future__ import annotations

from pathlib import Path
import argparse
import os
import signal
import subprocess
import sys
import time

from cmdscripts.compile_run import REPO_ROOT
from lib_py import dedicated, nginx, refxrootd, xrdhttp
from lib_py.util import pids_on_port, run


TEST_ROOT = Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test"))


def _sanitize_env() -> None:
    if os.environ.get("SANITIZE") == "1":
        log_dir = Path(os.environ.get("SANITIZE_LOG_DIR", str(TEST_ROOT / "sanitize")))
        log_dir.mkdir(parents=True, exist_ok=True)
        os.environ["ASAN_OPTIONS"] = (
            f"detect_leaks=1:halt_on_error=0:abort_on_error=0:exitcode=0:"
            f"log_path={log_dir}/asan:print_legend=0:{os.environ.get('ASAN_OPTIONS', '')}"
        )
        os.environ["UBSAN_OPTIONS"] = f"halt_on_error=0:print_stacktrace=1:{os.environ.get('UBSAN_OPTIONS', '')}"
        supp = REPO_ROOT / "tests" / "lsan.supp"
        os.environ["LSAN_OPTIONS"] = f"suppressions={supp}:report_objects=0:{os.environ.get('LSAN_OPTIONS', '')}"
        print(f"SANITIZE=1: leak/UBSan logs -> {log_dir}/asan.<pid>", file=sys.stderr)
    if os.environ.get("VALGRIND") == "1":
        log_dir = Path(os.environ.get("VALGRIND_LOG_DIR", str(TEST_ROOT / "valgrind")))
        log_dir.mkdir(parents=True, exist_ok=True)
        print(f"VALGRIND=1: memcheck logs -> {log_dir}/vg.<pid>.log", file=sys.stderr)


def _status_port(label: str, port: int) -> int:
    pids = pids_on_port(port)
    if pids:
        print(f"{label}: listening on {port}: {' '.join(map(str, pids))}")
        return 0
    print(f"{label}: stopped on {port}")
    return 1


def _force_stop_ports(ports: list[int]) -> None:
    for port in ports:
        kill_pid_list(pids_on_port(port))


def _start_dedicated(target: str) -> None:
    if target == "cluster-redir":
        os.environ["CMS_PORT"] = os.environ.get("CLUSTER_REDIR_CMS_PORT", "11161")
        dedicated.start_dedicated_nginx(
            "cluster-redir",
            "nginx_cluster_redir.conf",
            int(os.environ.get("CLUSTER_REDIR_PORT", "11160")),
        )
    elif target == "cluster-ds":
        os.environ["CMS_PORT"] = os.environ.get("CLUSTER_REDIR_CMS_PORT", "11161")
        os.environ["CMS_PATHS"] = "/"
        dedicated.start_dedicated_nginx(
            "cluster-ds",
            "nginx_cluster_ds.conf",
            int(os.environ.get("CLUSTER_DS_PORT", "11162")),
        )
    elif target == "manager":
        dedicated.start_dedicated_nginx("manager", "nginx_manager.conf", int(os.environ.get("MANAGER_PORT", "11101")))
    elif target == "cluster-3t-meta":
        os.environ["CMS_PORT"] = os.environ.get("CLUSTER_3T_META_CMS_PORT", "11186")
        dedicated.start_dedicated_nginx(
            "cluster-3t-meta",
            "nginx_cluster_redir.conf",
            int(os.environ.get("CLUSTER_3T_META_PORT", "11185")),
        )
    elif target == "cluster-3t-sub":
        os.environ["CMS_PORT"] = os.environ.get("CLUSTER_3T_SUB_CMS_PORT", "11188")
        os.environ["META_CMS_PORT"] = os.environ.get("CLUSTER_3T_META_CMS_PORT", "11186")
        os.environ["SELF_REGISTER_PORT"] = os.environ.get("CLUSTER_3T_SELF_PORT", "11189")
        dedicated.start_dedicated_nginx(
            "cluster-3t-sub",
            "nginx_cluster_sub_manager.conf",
            int(os.environ.get("CLUSTER_3T_SUB_PORT", "11187")),
        )
    elif target == "cluster-3t-leaf":
        os.environ["CMS_PORT"] = os.environ.get("CLUSTER_3T_SUB_CMS_PORT", "11188")
        os.environ["CMS_PATHS"] = "/"
        dedicated.start_dedicated_nginx(
            "cluster-3t-leaf",
            "nginx_cluster_ds.conf",
            int(os.environ.get("CLUSTER_3T_LEAF_PORT", "11190")),
        )
    else:
        raise SystemExit(f"start-dedicated: unknown target '{target}'")


def _stop_processes(names: list[str]) -> None:
    for name in names:
        proc = run(["pgrep", "-x", name])
        for text in proc.stdout.split():
            try:
                os.kill(int(text), signal.SIGTERM)
            except OSError:
                pass
    time.sleep(0.25)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["start-all", "stop-all", "start-dedicated", "start", "stop", "force-stop", "restart", "status"])
    parser.add_argument("target", nargs="?", default="all")
    ns = parser.parse_args(argv)
    _sanitize_env()

    if ns.action == "start-all":
        dedicated.start_all_dedicated()
        return 0
    if ns.action == "stop-all":
        dedicated.stop_all_dedicated()
        return 0
    if ns.action == "start-dedicated":
        _start_dedicated(ns.target)
        return 0

    if ns.action == "start":
        if ns.target == "all":
            dedicated.start_all_dedicated()
        elif ns.target == "nginx":
            if os.environ.get("SKIP_NGINX_FORCE_STOP_ON_START") != "1":
                nginx.force_stop_nginx()
            nginx.start_nginx()
        elif ns.target == "ref":
            refxrootd.stop_ref_ports(int(os.environ.get("REF_PORT", "11098")))
            refxrootd.start_ref_instance("conformance", int(os.environ.get("REF_PORT", "11098")), TEST_ROOT / "data")
        elif ns.target == "xrdhttp":
            xrdhttp.stop_xrdhttp()
            xrdhttp.start_xrdhttp()
        else:
            parser.error(f"unknown target {ns.target}")
        return 0

    if ns.action == "stop":
        if ns.target == "all":
            dedicated.stop_all_dedicated()
        elif ns.target == "nginx":
            nginx.stop_nginx()
        elif ns.target == "ref":
            refxrootd.stop_ref_ports(int(os.environ.get("REF_PORT", "11098")))
        elif ns.target == "xrdhttp":
            xrdhttp.stop_xrdhttp()
        else:
            parser.error(f"unknown target {ns.target}")
        return 0

    if ns.action == "force-stop":
        if ns.target in ("all", "nginx"):
            nginx.force_stop_nginx()
        if ns.target in ("all", "ref"):
            refxrootd.stop_ref_ports(int(os.environ.get("REF_PORT", "11098")))
        if ns.target == "xrdhttp":
            xrdhttp.stop_xrdhttp()
        if ns.target not in ("all", "nginx", "ref", "xrdhttp"):
            parser.error(f"unknown target {ns.target}")
        return 0

    if ns.action == "restart":
        return main(["stop", ns.target]) or main(["start", ns.target])

    if ns.action == "status":
        rc = 0
        if ns.target in ("all", "nginx"):
            rc |= _status_port("nginx", int(os.environ.get("NGINX_PORT", "11094")))
        if ns.target in ("all", "ref"):
            rc |= _status_port("ref", int(os.environ.get("REF_PORT", "11098")))
        if ns.target == "xrdhttp":
            rc |= 0 if xrdhttp.status_xrdhttp() == "running" else 1
        if ns.target not in ("all", "nginx", "ref", "xrdhttp"):
            parser.error(f"unknown target {ns.target}")
        return rc

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
