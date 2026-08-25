"""Python ports for top-level operator/runtime shell entrypoints."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
import argparse
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

from cmdscripts.compile_run import REPO_ROOT, result, run
from settings import BIND_HOST, HOST, TEST_PORT_START
from port_ladder import PORT_COUNT


TESTS = REPO_ROOT / "tests"


def _suite_parser():
    parser = argparse.ArgumentParser(prog="operator_runtime.py suite")
    parser.add_argument("--fast", action="store_true")
    parser.add_argument("--pr", action="store_true")
    parser.add_argument("--nightly", action="store_true")
    parser.add_argument("-n", type=int, default=max(2, min((os.cpu_count() or 8) - 2, 12)))
    parser.add_argument(
        "--first-percent", type=float, default=None, metavar="PERCENT",
        help="run one deterministic PERCENT sample instead of the full suite",
    )
    parser.add_argument(
        "--nginx-bin",
        default=os.environ.get("TEST_NGINX_BIN", os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")),
    )
    parser.add_argument(
        "--asan-nginx-bin",
        default=os.environ.get("TEST_ASAN_NGINX_BIN", ""),
        help="a dedicated ASan/UBSan nginx(+brix) binary for the sanitizer lane "
             "and sanitized-server tests (published as TEST_ASAN_NGINX_BIN); "
             "empty means the lane builds one from NGINX_SRC",
    )
    parser.add_argument(
        "--xrootd-bin",
        default=os.environ.get("TEST_BRIX_BIN", os.environ.get("XROOTD_BIN", os.environ.get("BRIX_BIN", "xrootd"))),
    )
    parser.add_argument(
        "--nginx-load-module", action="append", default=[], metavar="PATH",
        help="load a dynamic nginx module in this order; repeat for multiple modules",
    )
    parser.add_argument("extra", nargs=argparse.REMAINDER)
    return parser


def _suite_prepare_environment(ns):
    env = {"PYTHONPATH": f"tests{os.pathsep}{os.environ.get('PYTHONPATH', '')}",
           "TEST_OWN_FLEET": "1"}
    os.environ.update(env)
    if ns.asan_nginx_bin:
        path = Path(ns.asan_nginx_bin).expanduser().resolve()
        os.environ["TEST_ASAN_NGINX_BIN"] = str(path)
    if not _configure_suite_binaries(ns.nginx_bin, ns.xrootd_bin):
        return None
    if not _configure_nginx_modules(os.environ["TEST_NGINX_BIN"], ns.nginx_load_module):
        return None
    test_root = Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test")).expanduser().resolve()
    os.environ["TEST_ROOT"] = str(test_root)
    return test_root if _prepare_test_root(test_root) else None


def _suite_arguments(ns):
    extra = ns.extra[1:] if ns.extra[:1] == ["--"] else ns.extra
    destructive = _existing(DESTRUCTIVE)
    clientconf = _existing(CLIENTCONF)
    ignore = [f"--ignore={REPO_ROOT / 'tests/userns'}"]
    ignore += [f"--ignore={REPO_ROOT / rel}" for rel in [*destructive, *clientconf]]
    common = ["-ra", "-q", "-p", "no:randomly", "-p", "no:rerunfailures",
              "-o", "addopts=", "--color=no", *extra]
    return destructive, clientconf, ignore, common, str(REPO_ROOT / "tests")


def _suite_fast(ns, test_root, tests_root, ignore, common):
    selection = [tests_root, *ignore, "-m", "not slow and not serial"]
    parallel = ["-n", str(ns.n), "--dist", "loadgroup"]
    return 0 if _suite_lane(test_root, selection, parallel, common) else 1


def _suite_pr(ns, test_root, tests_root, ignore, common):
    rc = 0
    selection = [tests_root, *ignore, "-m", "not slow and not serial"]
    if not _suite_lane(test_root, selection, ["-n", str(ns.n), "--dist", "loadgroup"], common):
        rc = 1
    serial = [tests_root, f"--ignore={REPO_ROOT / 'tests/userns'}", "-m", "serial and not slow"]
    if not _suite_serial_lane(test_root, serial, common):
        rc = 1
    return rc


def _optional_serial_lane(test_root, paths, common):
    if not paths:
        return 0
    selection = [str(REPO_ROOT / rel) for rel in paths]
    return 0 if _suite_serial_lane(test_root, selection, common) else 1


def _optional_parallel_lane(test_root, paths, common, distribution):
    if not paths:
        return 0
    selection = [str(REPO_ROOT / rel) for rel in paths]
    parallel = ["-n", "2", "--dist", distribution]
    return 0 if _suite_lane(test_root, selection, parallel, common) else 1


def _suite_nightly(ns, test_root, tests_root, ignore, common, destructive, clientconf):
    rc = 0
    slow = [tests_root, *ignore, "-m", "slow and not serial"]
    if not _suite_lane(test_root, slow, ["-n", str(ns.n), "--dist", "loadgroup"], common):
        rc = 1
    serial = [tests_root, f"--ignore={REPO_ROOT / 'tests/userns'}", "-m", "slow and serial"]
    if not _suite_serial_lane(test_root, serial, common):
        rc = 1
    extra = _optional_serial_lane(test_root, destructive, common)
    clients = _optional_parallel_lane(test_root, clientconf, common, "loadgroup")
    return max(rc, extra, clients)


def _suite_sample(ns, test_root, tests_root, common):
    sample_common = ["-q", "--tb=short", *common[2:]]
    selection = [tests_root, f"--first-percent={ns.first_percent:g}"]
    parallel = ["-n", str(ns.n), "--dist", "loadgroup"]
    return 0 if _suite_lane(test_root, selection, parallel, sample_common) else 1


def _suite_full(ns, test_root, tests_root, ignore, common, destructive, clientconf):
    rc = 0
    selection = [tests_root, *ignore, "-m", "not serial"]
    parallel = ["-n", str(ns.n), "--dist", "loadgroup"]
    if not _suite_lane(test_root, selection, parallel, common):
        rc = 1
    serial = [tests_root, f"--ignore={REPO_ROOT / 'tests/userns'}", "-m", "serial"]
    if not _suite_serial_lane(test_root, serial, common):
        rc = 1
    extra = _optional_serial_lane(test_root, destructive, common)
    clients = _optional_parallel_lane(test_root, clientconf, common, "loadgroup")
    return max(rc, extra, clients)


def _suite_selected_mode(ns, test_root, arguments):
    destructive, clientconf, ignore, common, tests_root = arguments
    if ns.fast:
        return _suite_fast(ns, test_root, tests_root, ignore, common)
    if ns.pr:
        return _suite_pr(ns, test_root, tests_root, ignore, common)
    if ns.nightly:
        return _suite_nightly(
            ns, test_root, tests_root, ignore, common, destructive, clientconf
        )
    if ns.first_percent is not None:
        return _suite_sample(ns, test_root, tests_root, common)
    return _suite_full(
        ns, test_root, tests_root, ignore, common, destructive, clientconf
    )


def _report_sentinel_abort(abort):
    sys.stdout.write(str(abort).rstrip("\n") + "\n")
    sys.stdout.write(
        "SUITE HALTED by fleet sentinel — fix the offending test before "
        "re-running (set BRIX_FLEET_SENTINEL=0 to override).\n")
    sys.stdout.flush()


def run_suite(argv: list[str]) -> int:
    ns = _suite_parser().parse_args(argv)
    test_root = _suite_prepare_environment(ns)
    if test_root is None:
        return 2
    teardown_test_fleet(test_root)
    clear_sentinel_marker(test_root)
    arguments = _suite_arguments(ns)

    try:
        return _suite_selected_mode(ns, test_root, arguments)
    except FleetSentinelAbort as abort:
        _report_sentinel_abort(abort)
        return 1
    finally:
        teardown_test_fleet(test_root)


def _openssl(argv: list[str]) -> subprocess.CompletedProcess:
    return run(["openssl", *argv], cwd=REPO_ROOT)


def _generate_load_pki(root_dir: Path, load_root: Path) -> None:
    pki = load_root / "pki"
    ca = pki / "ca"
    server = pki / "server"
    user = pki / "user"
    shutil.rmtree(pki, ignore_errors=True)
    for path in (ca, server, user):
        path.mkdir(parents=True, exist_ok=True)
    _openssl(["genrsa", "-out", str(ca / "ca.key"), "2048"])
    (ca / "ca.key").chmod(0o400)
    _openssl(["req", "-x509", "-new", "-nodes", "-key", str(ca / "ca.key"), "-sha256", "-days", "3650", "-subj", "/C=XX/O=Test/CN=Test CA", "-out", str(ca / "ca.pem")])
    (ca / "signing-policy").write_text("access_id_CA   X509   '/C=XX/O=Test/CN=Test CA'\npos_rights     globus CA:sign\ncond_subjects  globus  '*'\n")
    new_hash = run(["openssl", "x509", "-in", str(ca / "ca.pem"), "-noout", "-subject_hash"], cwd=REPO_ROOT).stdout.strip()
    old_hash = run(["openssl", "x509", "-in", str(ca / "ca.pem"), "-noout", "-subject_hash_old"], cwd=REPO_ROOT).stdout.strip()
    for h in {new_hash, old_hash} - {""}:
        (ca / f"{h}.0").symlink_to(ca / "ca.pem")
        (ca / f"{h}.signing_policy").symlink_to(ca / "signing-policy")
    _openssl(["genrsa", "-out", str(server / "host.key"), "2048"])
    _openssl(["req", "-new", "-key", str(server / "host.key"), "-subj", "/C=XX/O=Test/CN=localhost", "-out", str(server / "host.csr")])  # net-literal-allow: X.509 host cert CN subject, not a dial target
    _openssl(["x509", "-req", "-in", str(server / "host.csr"), "-CA", str(ca / "ca.pem"), "-CAkey", str(ca / "ca.key"), "-CAcreateserial", "-out", str(server / "hostcert.pem"), "-days", "3650", "-sha256"])
    (server / "hostkey.pem").symlink_to(server / "host.key")
    _openssl(["genrsa", "-out", str(user / "user.key"), "2048"])
    _openssl(["req", "-new", "-key", str(user / "user.key"), "-subj", "/C=XX/O=Test/CN=Test User", "-out", str(user / "user.csr")])
    _openssl(["x509", "-req", "-in", str(user / "user.csr"), "-CA", str(ca / "ca.pem"), "-CAkey", str(ca / "ca.key"), "-CAcreateserial", "-out", str(user / "usercert.pem"), "-days", "3650", "-sha256"])
    make_crl = root_dir / "utils/make_crl.py"
    if make_crl.exists():
        run([sys.executable, str(make_crl), str(pki)], cwd=root_dir)


def _setup_load_data(load_root: Path) -> None:
    data = load_root / "data"
    tokens = load_root / "tokens"
    data.mkdir(parents=True, exist_ok=True)
    tokens.mkdir(parents=True, exist_ok=True)
    payload = data / "load_1g.bin"
    if not payload.exists():
        with payload.open("wb") as fh:
            fh.truncate(1024 * 1024 * 1024)
    _generate_load_pki(REPO_ROOT, load_root)
    if not (tokens / "jwks.json").exists():
        run([sys.executable, str(REPO_ROOT / "utils/make_token.py"), "init", str(tokens)], cwd=REPO_ROOT)


def _wait_port_or_raise(host: str, port: int, label: str) -> None:
    if not _wait_tcp(host, port, timeout=15.0):
        raise RuntimeError(f"{label} did not come up on {host}:{port}")


def _load_target(argv):
    if argv and not argv[0].startswith("-"):
        return argv[0], argv[1:]
    return "nginx", argv


def _consume_data_tls(extra, index):
    item = extra[index]
    if item == "--data-tls":
        next_index = index + 1
        value = extra[next_index] if next_index < len(extra) else "off"
        return value, next_index + 1
    if item.startswith("--data-tls="):
        return item.split("=", 1)[1], index + 1
    return None, index + 1


def _load_options(argv):
    target, extra = _load_target(argv)
    data_tls = "off"
    forwarded: list[str] = []
    idx = 0
    while idx < len(extra):
        value, next_index = _consume_data_tls(extra, idx)
        if value is None:
            forwarded.append(extra[idx])
        else:
            data_tls = value
        idx = next_index
    return target, data_tls, forwarded


def _load_paths(test_root):
    perf_root = test_root / "artifacts" / "load"
    return {
        "perf": perf_root,
        "fixtures": perf_root / "fixtures",
        "nginx": perf_root / "nginx",
        "xrd": perf_root / "xrootd",
        "anon": perf_root / "xrootd-anon",
    }


def _prepare_load_paths(paths):
    directories = (
        paths["nginx"] / "logs", paths["nginx"] / "tmp",
        paths["xrd"] / "logs", paths["xrd"] / "admin", paths["xrd"] / "run",
        paths["anon"] / "logs", paths["anon"] / "admin", paths["anon"] / "run",
    )
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)


def _render_load_configs(paths, data_tls):
    load_root = paths["fixtures"]
    nginx_conf = paths["nginx"] / "nginx.gen.conf"
    xrd_conf = paths["xrd"] / "brix.gen.conf"
    anon_conf = paths["anon"] / "brix.anon.gen.conf"
    nginx_text = (TESTS / "nginx.perf.conf").read_text()
    nginx_text = nginx_text.replace("{NGINX_DIR}", str(paths["nginx"]))
    nginx_text = nginx_text.replace("{LOAD_ROOT}", str(load_root))
    nginx_conf.write_text(nginx_text.replace("brix_tls on;", f"brix_tls {data_tls};"))
    xrd_text = (TESTS / "brix.perf.conf").read_text()
    xrd_text = xrd_text.replace("{XRD_DIR}", str(paths["xrd"]))
    xrd_conf.write_text(xrd_text.replace("{LOAD_ROOT}", str(load_root)))
    _append_load_tls(xrd_conf, load_root, data_tls)
    _write_anon_load_config(anon_conf, paths["anon"], load_root)
    return nginx_conf, xrd_conf, anon_conf


def _append_load_tls(config, load_root, data_tls):
    if data_tls != "on":
        return
    config.write_text(
        config.read_text()
        + f"\nxrd.tls {load_root}/pki/server/hostcert.pem "
        f"{load_root}/pki/server/hostkey.pem\n"
        f"xrd.tlsca certdir {load_root}/pki/ca\nxrootd.tls data\n"
    )


def _write_anon_load_config(config, anon_dir, load_root):
    config.write_text(
        f"all.adminpath {anon_dir}/admin\n"
        f"all.pidpath {anon_dir}/run\n"
        f"oss.localroot {load_root}/data\nall.export /\nxrd.port 12093\n"
        "xrd.network nodnr\nxrd.allow host *\nxrd.sched mint 8 avlt 16 maxt 256 idle 780\n"
    )


def _start_load_nginx(paths, nginx_bin, config):
    nginx_dir = paths["nginx"]
    clean_test_fleet(nginx_dir)
    argv = [str(nginx_bin), "-c", str(config), "-p", str(nginx_dir)]
    tested = run([*argv, "-t"], cwd=REPO_ROOT)
    if tested.returncode != 0:
        print(_tail(tested), file=sys.stderr)
        return False
    started = run(argv, cwd=REPO_ROOT)
    if started.returncode != 0:
        print(_tail(started), file=sys.stderr)
        return False
    _wait_port_or_raise(BIND_HOST, 12795, "nginx XRootD+GSI")
    _wait_port_or_raise(BIND_HOST, 12796, "nginx XRootD+TLS")
    _wait_port_or_raise(BIND_HOST, 12792, "nginx WebDAV+GSI")
    return True


def _start_xrootd_process(binary, config, log, name):
    return _popen(
        [str(binary), "-c", str(config), "-l", str(log), "-n", name, "-b"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _start_load_xrootd(paths, xrootd_bin, configs, children):
    if not xrootd_bin.exists():
        print(f"xrootd binary not found: {xrootd_bin}", file=sys.stderr)
        return False
    xrd_dir, anon_dir = paths["xrd"], paths["anon"]
    (xrd_dir / "data").mkdir(parents=True, exist_ok=True)
    link = xrd_dir / "data/xrd-test"
    if not link.exists():
        link.symlink_to(paths["fixtures"] / "data")
    (xrd_dir / "authdb").write_text("all.allow host any\nu * / rwld\n")
    children.append(_start_xrootd_process(
        xrootd_bin, configs[1], xrd_dir / "logs/brix.log", "perf"
    ))
    _wait_port_or_raise(BIND_HOST, 12094, "xrootd GSI")
    children.append(_start_xrootd_process(
        xrootd_bin, configs[2], anon_dir / "logs/brix.log", "perfanon"
    ))
    _wait_port_or_raise(BIND_HOST, 12093, "xrootd anon")
    return True


def _start_load_targets(target, paths, binaries, configs, children):
    nginx_bin, xrootd_bin = binaries
    if target in {"nginx", "both"} and not _start_load_nginx(paths, nginx_bin, configs[0]):
        return False
    if target in {"xrootd", "both"} and not _start_load_xrootd(
            paths, xrootd_bin, configs, children):
        return False
    return True


def _stop_load_nginx(paths, nginx_bin, config):
    nginx_dir = paths["nginx"]
    run([str(nginx_bin), "-c", str(config), "-p", str(nginx_dir), "-s", "quit"],
        cwd=REPO_ROOT)
    pidfile = nginx_dir / "logs/nginx.pid"
    if not pidfile.exists():
        return
    try:
        os.killpg(int(pidfile.read_text().strip()), signal.SIGKILL)
    except (OSError, ValueError):
        pass


def _stop_load_processes(target, paths, nginx_bin, nginx_conf, children):
    if target in {"nginx", "both"}:
        _stop_load_nginx(paths, nginx_bin, nginx_conf)
    for child in children:
        child.terminate()
    run(["pkill", "-f", "xrootd.*-n perf"], cwd=REPO_ROOT)


def run_load(argv: list[str]) -> int:
    target, data_tls, forwarded = _load_options(argv)
    if data_tls not in {"on", "off"}:
        print(f"bad --data-tls {data_tls}", file=sys.stderr)
        return 2

    test_root = Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test")).resolve()
    paths = _load_paths(test_root)
    nginx_bin = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    xrootd_bin = Path(os.environ.get("REF_BIN", os.environ.get("BRIX_BIN", "/usr/bin/xrootd")))
    _setup_load_data(paths["fixtures"])
    _prepare_load_paths(paths)
    configs = _render_load_configs(paths, data_tls)
    children: list[subprocess.Popen] = []
    try:
        if not _start_load_targets(target, paths, (nginx_bin, xrootd_bin), configs, children):
            return 1
        return _run_stream([
            sys.executable, str(TESTS / "load_test.py"), "--target", target,
            "--json", str(paths["perf"] / "load_test_results.json"), *forwarded,
        ])
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        _stop_load_processes(target, paths, nginx_bin, configs[0], children)
