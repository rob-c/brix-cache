"""Pure-Python fleet CLI — brings the registry-native test fleet up and down.

Successor to the retired ``tests/manage_test_servers.sh`` and its sourced
``tests/lib/*.sh`` helpers.  Every fixed-role instance is a ``NginxInstanceSpec``
in :mod:`fleet_specs`; ``start-all``/``stop-all``/``restart`` and the
single-instance ``start-dedicated`` are driven by :class:`RegistryLauncher` over
the declarative catalogue, with :func:`fleet_prep.prepare` generating the
session-wide PKI / token / CRL / authdb / stage-hook artifacts first (the work
the bash bridge did at the top of ``start_all_dedicated``).

Usage:
    python3 -m cmdscripts.manage_test_servers start-all
    python3 -m cmdscripts.manage_test_servers stop-all
    python3 -m cmdscripts.manage_test_servers restart
    python3 -m cmdscripts.manage_test_servers status
    python3 -m cmdscripts.manage_test_servers start-dedicated cluster-ds
"""

from __future__ import annotations

from pathlib import Path
import argparse
import os
import sys

TEST_ROOT = Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test"))


def _sanitize_env() -> None:
    """Propagate ASan/UBSan/LSan + Valgrind knobs to every launched daemon."""
    if os.environ.get("SANITIZE") == "1":
        log_dir = Path(os.environ.get("SANITIZE_LOG_DIR", str(TEST_ROOT / "sanitize")))
        log_dir.mkdir(parents=True, exist_ok=True)
        os.environ["ASAN_OPTIONS"] = (
            f"detect_leaks=1:halt_on_error=0:abort_on_error=0:exitcode=0:"
            f"log_path={log_dir}/asan:print_legend=0:{os.environ.get('ASAN_OPTIONS', '')}"
        )
        os.environ["UBSAN_OPTIONS"] = (
            f"halt_on_error=0:print_stacktrace=1:{os.environ.get('UBSAN_OPTIONS', '')}"
        )
        supp = Path(__file__).resolve().parents[1] / "lsan.supp"
        os.environ["LSAN_OPTIONS"] = (
            f"suppressions={supp}:report_objects=0:{os.environ.get('LSAN_OPTIONS', '')}"
        )
        print(f"SANITIZE=1: leak/UBSan logs -> {log_dir}/asan.<pid>", file=sys.stderr)
    if os.environ.get("VALGRIND") == "1":
        log_dir = Path(os.environ.get("VALGRIND_LOG_DIR", str(TEST_ROOT / "valgrind")))
        log_dir.mkdir(parents=True, exist_ok=True)
        print(f"VALGRIND=1: memcheck logs -> {log_dir}/vg.<pid>.log", file=sys.stderr)


def _register():
    """Register the full declarative fleet and return its dependency-ordered specs."""
    import fleet_specs  # noqa: PLC0415 — declarative fleet catalogue
    from server_registry import registered_specs  # noqa: PLC0415

    fleet_specs.register_full_fleet()
    return registered_specs()


def _launcher():
    from server_launcher import RegistryLauncher  # noqa: PLC0415

    return RegistryLauncher()


def start_all() -> int:
    import fleet_prep  # noqa: PLC0415 — session artifact generator

    fleet_prep.prepare()
    specs = _register()
    _launcher().start_registered(specs)
    print(f"start-all: {len(specs)} fleet instances launched")
    return 0


def stop_all() -> int:
    specs = _register()
    _launcher().stop_registered(specs)
    print("stop-all: fleet stopped")
    return 0


def start_dedicated(name: str) -> int:
    """Start a single named instance (and any specs it ``requires``) in order."""
    specs = _register()
    by_name = {spec.name: spec for spec in specs}
    if name not in by_name:
        raise SystemExit(f"start-dedicated: unknown instance '{name}'")

    wanted: set[str] = set()

    def _close(n: str) -> None:
        if n in wanted:
            return
        for dep in by_name[n].requires:
            _close(dep)
        wanted.add(n)

    _close(name)
    launcher = _launcher()
    from lib_py.util import pids_on_port  # noqa: PLC0415
    from server_registry import endpoint_for  # noqa: PLC0415

    # ``specs`` is already dependency-ordered, so iterating it starts requires first.
    # Skip any spec already listening on its port: start-dedicated is used to revive
    # ONE instance (e.g. cluster-ds after a test kills it) while its dependencies
    # (cluster-redir) are still up — restarting a live dependency just collides on
    # bind() and aborts the whole start, leaving the target instance down.
    started = 0
    for spec in specs:
        if spec.name not in wanted:
            continue
        port = endpoint_for(spec).port
        if port and pids_on_port(int(port)):
            continue
        launcher.start(spec)
        started += 1
    print(f"start-dedicated: started {started} instance(s) for {name}")
    return 0


def status() -> int:
    """Report a representative slice of fixed fleet ports (up/down)."""
    from lib_py.util import pids_on_port  # noqa: PLC0415
    import settings as S  # noqa: PLC0415

    probes = [
        ("main-nginx", S.NGINX_ANON_PORT),
        ("manager", S.MANAGER_PORT),
        ("readonly", S.READONLY_PORT),
        ("ref-anon", getattr(S, "REF_PORT", 11098)),
    ]
    rc = 0
    for label, port in probes:
        pids = pids_on_port(int(port))
        if pids:
            print(f"{label}: listening on {port}: {' '.join(map(str, pids))}")
        else:
            print(f"{label}: stopped on {port}")
            rc = 1
    return rc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="manage_test_servers")
    parser.add_argument(
        "action",
        choices=["start-all", "stop-all", "restart", "status", "start-dedicated"],
    )
    parser.add_argument("target", nargs="?", default="all")
    ns = parser.parse_args(argv)
    _sanitize_env()

    if ns.action == "start-all":
        return start_all()
    if ns.action == "stop-all":
        return stop_all()
    if ns.action == "restart":
        stop_all()
        return start_all()
    if ns.action == "start-dedicated":
        return start_dedicated(ns.target)
    if ns.action == "status":
        return status()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
