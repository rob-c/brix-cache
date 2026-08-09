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


def run_suite(argv: list[str]) -> int:
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
    ns = parser.parse_args(argv)
    extra = ns.extra[1:] if ns.extra[:1] == ["--"] else ns.extra

    env = {"PYTHONPATH": f"tests{os.pathsep}{os.environ.get('PYTHONPATH', '')}", "TEST_OWN_FLEET": "1"}
    os.environ.update(env)
    # Publish a provided ASan nginx the same way as the plain fleet binary, so the
    # sanitizer lane (tools/ci/asan.py) and any sanitized-server test use it
    # instead of building one.  A relative path is resolved against the caller cwd.
    if ns.asan_nginx_bin:
        os.environ["TEST_ASAN_NGINX_BIN"] = str(Path(ns.asan_nginx_bin).expanduser().resolve())
    if not _configure_suite_binaries(ns.nginx_bin, ns.xrootd_bin):
        return 2
    if not _configure_nginx_modules(os.environ["TEST_NGINX_BIN"], ns.nginx_load_module):
        return 2
    test_root = Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test")).expanduser().resolve()
    os.environ["TEST_ROOT"] = str(test_root)
    if not _prepare_test_root(test_root):
        return 2
    teardown_test_fleet(test_root)
    # A prior aborted run may have left a fleet-sentinel marker on disk; drop it
    # so this fresh suite is not halted before it starts.  A lane that trips the
    # sentinel mid-run re-creates it, and the driver halts the remaining lanes.
    clear_sentinel_marker(test_root)
    destructive = _existing(DESTRUCTIVE)
    clientconf = _existing(CLIENTCONF)
    ignore = [f"--ignore={REPO_ROOT / 'tests/userns'}"]
    ignore += [f"--ignore={REPO_ROOT / rel}" for rel in [*destructive, *clientconf]]
    common = ["-ra", "-q", "-p", "no:randomly", "-p", "no:rerunfailures",
              "-o", "addopts=", "--color=no", *extra]
    tests_root = str(REPO_ROOT / "tests")
    rc = 0

    try:
        if ns.fast:
            ok = _suite_lane(test_root, [tests_root, *ignore, "-m", "not slow and not serial"], ["-n", str(ns.n), "--dist", "load"], common)
            return 0 if ok else 1
        if ns.pr:
            if not _suite_lane(test_root, [tests_root, *ignore, "-m", "not slow and not serial"], ["-n", str(ns.n), "--dist", "load"], common):
                rc = 1
            if not _suite_serial_lane(test_root, [tests_root, f"--ignore={REPO_ROOT / 'tests/userns'}", "-m", "serial and not slow"], common):
                rc = 1
            return rc
        if ns.nightly:
            if not _suite_lane(test_root, [tests_root, *ignore, "-m", "slow and not serial"], ["-n", str(ns.n), "--dist", "load"], common):
                rc = 1
            if not _suite_serial_lane(test_root, [tests_root, f"--ignore={REPO_ROOT / 'tests/userns'}", "-m", "slow and serial"], common):
                rc = 1
            if destructive and not _suite_serial_lane(test_root, [str(REPO_ROOT / rel) for rel in destructive], common):
                rc = 1
            if clientconf and not _suite_lane(test_root, [str(REPO_ROOT / rel) for rel in clientconf], ["-n", "2", "--dist", "load"], common):
                rc = 1
            return rc

        # An explicitly requested sample is a single deterministic collection. Keep
        # it byte-for-byte equivalent to the documented direct pytest command:
        # one collection (so 10% means 10% globally, not 10% of several lanes),
        # loadgroup scheduling, and no retry plugin. A failure is reported once
        # and must be fixed rather than re-executed automatically.
        if ns.first_percent is not None:
            sample_common = ["-q", "--tb=short", *common[2:]]
            ok = _suite_lane(
                test_root,
                [tests_root, f"--first-percent={ns.first_percent:g}"],
                ["-n", str(ns.n), "--dist", "loadgroup"],
                sample_common,
            )
            return 0 if ok else 1

        # Full default: parallel-safe tests, serial tests, destructive resilience
        # tests, then client-configuration tests. Every lane is single-pass.
        if not _suite_lane(test_root,
                           [tests_root, *ignore, "-m", "not serial"],
                           ["-n", str(ns.n), "--dist", "loadgroup"], common):
            rc = 1
        if not _suite_serial_lane(
                test_root,
                [tests_root, f"--ignore={REPO_ROOT / 'tests/userns'}", "-m", "serial"],
                common):
            rc = 1
        if destructive and not _suite_serial_lane(
                test_root, [str(REPO_ROOT / rel) for rel in destructive], common):
            rc = 1
        if clientconf and not _suite_lane(
                test_root, [str(REPO_ROOT / rel) for rel in clientconf],
                ["-n", "2", "--dist", "loadgroup"], common):
            rc = 1
        return rc

    except FleetSentinelAbort as abort:
        # A test killed or crashed a shared fleet server: halt the whole suite
        # here rather than run the remaining lanes against a damaged fleet.  The
        # banner (with the culprit test) already went to the lane's output; echo
        # it once more so it is the last thing the operator sees.
        sys.stdout.write(str(abort).rstrip("\n") + "\n")
        sys.stdout.write(
            "SUITE HALTED by fleet sentinel — fix the offending test before "
            "re-running (set BRIX_FLEET_SENTINEL=0 to override).\n")
        sys.stdout.flush()
        return 1
    finally:
        # Covers KeyboardInterrupt between lanes and exceptions in lane setup.
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


def run_load(argv: list[str]) -> int:
    target = argv[0] if argv and not argv[0].startswith("-") else "nginx"
    extra = argv[1:] if argv and not argv[0].startswith("-") else argv
    data_tls = "off"
    forwarded: list[str] = []
    idx = 0
    while idx < len(extra):
        item = extra[idx]
        if item == "--data-tls":
            idx += 1
            data_tls = extra[idx] if idx < len(extra) else "off"
        elif item.startswith("--data-tls="):
            data_tls = item.split("=", 1)[1]
        else:
            forwarded.append(item)
        idx += 1
    if data_tls not in {"on", "off"}:
        print(f"bad --data-tls {data_tls}", file=sys.stderr)
        return 2

    test_root = Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test")).resolve()
    perf_root = test_root / "artifacts" / "load"
    load_root = perf_root / "fixtures"
    nginx_dir = perf_root / "nginx"
    xrd_dir = perf_root / "xrootd"
    xrd_anon_dir = perf_root / "xrootd-anon"
    nginx_bin = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    xrootd_bin = Path(os.environ.get("REF_BIN", os.environ.get("BRIX_BIN", "/usr/bin/xrootd")))
    _setup_load_data(load_root)
    for path in (nginx_dir / "logs", nginx_dir / "tmp", xrd_dir / "logs", xrd_dir / "admin", xrd_dir / "run", xrd_anon_dir / "logs", xrd_anon_dir / "admin", xrd_anon_dir / "run"):
        path.mkdir(parents=True, exist_ok=True)

    nginx_conf = nginx_dir / "nginx.gen.conf"
    xrd_conf = xrd_dir / "brix.gen.conf"
    xrd_anon_conf = xrd_anon_dir / "brix.anon.gen.conf"
    ntls = "on" if data_tls == "on" else "off"
    nginx_text = (TESTS / "nginx.perf.conf").read_text()
    nginx_text = nginx_text.replace("{NGINX_DIR}", str(nginx_dir))
    nginx_text = nginx_text.replace("{LOAD_ROOT}", str(load_root))
    nginx_conf.write_text(nginx_text.replace("brix_tls on;", f"brix_tls {ntls};"))
    xrd_text = (TESTS / "brix.perf.conf").read_text()
    xrd_text = xrd_text.replace("{XRD_DIR}", str(xrd_dir))
    xrd_text = xrd_text.replace("{LOAD_ROOT}", str(load_root))
    xrd_conf.write_text(xrd_text)
    if data_tls == "on":
        xrd_conf.write_text(
            xrd_conf.read_text()
            + f"\nxrd.tls {load_root}/pki/server/hostcert.pem "
            f"{load_root}/pki/server/hostkey.pem\n"
            f"xrd.tlsca certdir {load_root}/pki/ca\nxrootd.tls data\n"
        )
    xrd_anon_conf.write_text(
        f"all.adminpath {xrd_anon_dir}/admin\n"
        f"all.pidpath {xrd_anon_dir}/run\n"
        f"oss.localroot {load_root}/data\nall.export /\nxrd.port 12093\n"
        "xrd.network nodnr\nxrd.allow host *\nxrd.sched mint 8 avlt 16 maxt 256 idle 780\n"
    )

    children: list[subprocess.Popen] = []
    try:
        if target in {"nginx", "both"}:
            clean_test_fleet(nginx_dir)
            tested = run([str(nginx_bin), "-c", str(nginx_conf), "-p", str(nginx_dir), "-t"], cwd=REPO_ROOT)
            if tested.returncode != 0:
                print(_tail(tested), file=sys.stderr)
                return 1
            started = run([str(nginx_bin), "-c", str(nginx_conf), "-p", str(nginx_dir)], cwd=REPO_ROOT)
            if started.returncode != 0:
                print(_tail(started), file=sys.stderr)
                return 1
            _wait_port_or_raise(BIND_HOST, 12795, "nginx XRootD+GSI")
            _wait_port_or_raise(BIND_HOST, 12796, "nginx XRootD+TLS")
            _wait_port_or_raise(BIND_HOST, 12792, "nginx WebDAV+GSI")
        if target in {"xrootd", "both"}:
            if not xrootd_bin.exists():
                print(f"xrootd binary not found: {xrootd_bin}", file=sys.stderr)
                return 1
            (xrd_dir / "data").mkdir(parents=True, exist_ok=True)
            link = xrd_dir / "data/xrd-test"
            if not link.exists():
                link.symlink_to(load_root / "data")
            (xrd_dir / "authdb").write_text("all.allow host any\nu * / rwld\n")
            children.append(_popen([str(xrootd_bin), "-c", str(xrd_conf), "-l", str(xrd_dir / "logs/brix.log"), "-n", "perf", "-b"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            _wait_port_or_raise(BIND_HOST, 12094, "xrootd GSI")
            children.append(_popen([str(xrootd_bin), "-c", str(xrd_anon_conf), "-l", str(xrd_anon_dir / "logs/brix.log"), "-n", "perfanon", "-b"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            _wait_port_or_raise(BIND_HOST, 12093, "xrootd anon")
        return _run_stream([
            sys.executable, str(TESTS / "load_test.py"), "--target", target,
            "--json", str(perf_root / "load_test_results.json"), *forwarded,
        ])
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        if target in {"nginx", "both"}:
            run([str(nginx_bin), "-c", str(nginx_conf), "-p", str(nginx_dir), "-s", "quit"], cwd=REPO_ROOT)
            pidfile = nginx_dir / "logs/nginx.pid"
            if pidfile.exists():
                try:
                    os.killpg(int(pidfile.read_text().strip()), signal.SIGKILL)
                except (OSError, ValueError):
                    pass
        for child in children:
            child.terminate()
        run(["pkill", "-f", "xrootd.*-n perf"], cwd=REPO_ROOT)


