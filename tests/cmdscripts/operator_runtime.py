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


TESTS = REPO_ROOT / "tests"


def _tail(proc: subprocess.CompletedProcess, limit: int = 3000) -> str:
    return (proc.stderr or proc.stdout or "")[-limit:]


def _popen(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    stdout=None,
    stderr=None,
    stdin=None,
    start_new_session: bool = False,
) -> subprocess.Popen:
    return subprocess.Popen(
        argv,
        cwd=str(cwd or REPO_ROOT),
        env={**os.environ, **(env or {})},
        text=True,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        start_new_session=start_new_session,
    )


def _run_stream(argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> int:
    proc = _popen(argv, cwd=cwd, env=env)
    return int(proc.wait())


def _wait_tcp(host: str, port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _safe_kill(pid: int, sig: int = signal.SIGTERM) -> None:
    try:
        os.kill(pid, sig)
    except OSError:
        pass


def _process_cmdline(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "ignore")
    except OSError:
        return ""


def _pgrep_name(name: str) -> list[int]:
    proc = run(["pgrep", "-x", name], cwd=REPO_ROOT)
    if proc.returncode != 0:
        return []
    pids = []
    for text in proc.stdout.split():
        try:
            pids.append(int(text))
        except ValueError:
            pass
    return pids


def clean_test_fleet(test_root: Path = Path("/tmp/xrd-test")) -> None:
    # Cross-lane shared state: the default credential store on tmpfs is owned
    # by whichever lane's worker identity touched it last (root lane -> nobody,
    # unprivileged lane -> the test user).  A store left by the OTHER lane is
    # 0700 foreign-owned, so this lane's workers EACCES every delegation PUT
    # and the config-time ensure shouts ownership warnings that trip the
    # credential tests.  It holds only throwaway test delegations — wipe it
    # (best-effort: unprivileged we may not own it, but then the pre-existing
    # skip guards apply).
    shutil.rmtree("/dev/shm/brix-creds", ignore_errors=True)
    for name in ("nginx", "xrootd", "krb5kdc", "kadmind"):
        for pid in _pgrep_name(name):
            cmdline = _process_cmdline(pid)
            if "/tmp/xrd" in cmdline or "/tmp/hsproto" in cmdline or str(test_root) in cmdline:
                _safe_kill(pid, signal.SIGTERM)
    for _ in range(3):
        for pid in _pgrep_name("nginx"):
            cmdline = _process_cmdline(pid)
            if "/tmp/xrd" in cmdline or str(test_root) in cmdline:
                _safe_kill(pid, signal.SIGKILL)


def _existing(paths: Iterable[str]) -> list[str]:
    kept = []
    for rel in paths:
        if (REPO_ROOT / rel).exists():
            kept.append(rel)
        else:
            print(f"WARNING: path missing, skipping: {rel}", file=sys.stderr)
    return kept


DESTRUCTIVE = [
    "tests/test_chaos_mesh.py",
    "tests/test_chaos_mixed_auth.py",
    "tests/test_cms_resilience.py",
    "tests/test_compression_fuse_resilience.py",
    "tests/test_evil_actor.py",
    "tests/test_evil_actor_v2.py",
    "tests/test_evil_actor_v3.py",
    "tests/test_evil_actor_v3_b.py",
    "tests/test_evil_paths.py",
    "tests/test_netfault_stream.py",
    "tests/test_net_resilience.py",
    "tests/test_official_xrootd_resilience.py",
    "tests/test_phase51_resilience.py",
    "tests/test_xrootdfs_resilience.py",
    "tests/resilience",
]

CLIENTCONF = [
    "tests/test_clientconf_cksum.py",
    "tests/test_clientconf_narrative.py",
    "tests/test_clientconf_surface.py",
    "tests/test_clientconf_xrdcp.py",
    "tests/test_clientconf_xrdfs.py",
    "tests/test_clientconf_xrdgsiproxy.py",
    "tests/test_clientconf_xrdmapc.py",
]


def _pytest_lane(selection: list[str], main: list[str], common: list[str]) -> bool:
    # Single pass, no retry ladder: a first-run failure is the signal to fix,
    # not something to launder through --lf reruns.
    return _run_stream([sys.executable, "-m", "pytest", *selection, *main, *common]) == 0


def run_suite(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="operator_runtime.py suite")
    parser.add_argument("--fast", action="store_true")
    parser.add_argument("--pr", action="store_true")
    parser.add_argument("--nightly", action="store_true")
    parser.add_argument("-n", type=int, default=max(2, min((os.cpu_count() or 8) - 2, 12)))
    parser.add_argument("extra", nargs=argparse.REMAINDER)
    ns = parser.parse_args(argv)
    extra = ns.extra[1:] if ns.extra[:1] == ["--"] else ns.extra

    env = {"PYTHONPATH": f"tests{os.pathsep}{os.environ.get('PYTHONPATH', '')}", "TEST_OWN_FLEET": "1"}
    os.environ.update(env)
    clean_test_fleet()
    destructive = _existing(DESTRUCTIVE)
    clientconf = _existing(CLIENTCONF)
    ignore = [f"--ignore={REPO_ROOT / 'tests/userns'}"]
    ignore += [f"--ignore={REPO_ROOT / rel}" for rel in [*destructive, *clientconf]]
    common = ["-ra", "-q", "-p", "no:randomly", "--color=no", *extra]
    tests_root = str(REPO_ROOT / "tests")
    rc = 0

    if ns.fast:
        ok = _pytest_lane([tests_root, *ignore, "-m", "not slow and not serial"], ["-n", str(ns.n), "--dist", "load"], common)
        return 0 if ok else 1
    if ns.pr:
        if not _pytest_lane([tests_root, *ignore, "-m", "not slow and not serial"], ["-n", str(ns.n), "--dist", "load"], common):
            rc = 1
        if not _pytest_lane([tests_root, f"--ignore={REPO_ROOT / 'tests/userns'}", "-m", "serial and not slow"], ["-p", "no:xdist"], common):
            rc = 1
        return rc
    if ns.nightly:
        if not _pytest_lane([tests_root, *ignore, "-m", "slow and not serial"], ["-n", str(ns.n), "--dist", "load"], common):
            rc = 1
        if not _pytest_lane([tests_root, f"--ignore={REPO_ROOT / 'tests/userns'}", "-m", "slow and serial"], ["-p", "no:xdist"], common):
            rc = 1
        if destructive and not _pytest_lane([str(REPO_ROOT / rel) for rel in destructive], ["-p", "no:xdist"], common):
            rc = 1
        if clientconf and not _pytest_lane([str(REPO_ROOT / rel) for rel in clientconf], ["-n", "2", "--dist", "load"], common):
            rc = 1
        return rc

    if not _pytest_lane([tests_root, *ignore, "-m", "not serial"], ["-n", str(ns.n), "--dist", "load"], common):
        rc = 1
    if not _pytest_lane([tests_root, f"--ignore={REPO_ROOT / 'tests/userns'}", "-m", "serial"], ["-p", "no:xdist"], common):
        rc = 1
    if destructive and not _pytest_lane([str(REPO_ROOT / rel) for rel in destructive], ["-p", "no:xdist"], common):
        rc = 1
    if clientconf and not _pytest_lane([str(REPO_ROOT / rel) for rel in clientconf], ["-n", "2", "--dist", "load"], common):
        rc = 1
    return rc


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
    _openssl(["req", "-new", "-key", str(server / "host.key"), "-subj", "/C=XX/O=Test/CN=localhost", "-out", str(server / "host.csr")])
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

    load_root = Path("/tmp/xrd-load")
    nginx_dir = Path("/tmp/xrd-perf-test")
    xrd_dir = Path("/tmp/xrd-perf-xrd")
    xrd_anon_dir = Path("/tmp/xrd-perf-xrd-anon")
    nginx_bin = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    xrootd_bin = Path(os.environ.get("REF_BIN", os.environ.get("BRIX_BIN", "/usr/bin/xrootd")))
    _setup_load_data(load_root)
    for path in (nginx_dir / "logs", nginx_dir / "tmp", xrd_dir / "logs", xrd_dir / "admin", xrd_dir / "run", xrd_anon_dir / "logs", xrd_anon_dir / "admin", xrd_anon_dir / "run"):
        path.mkdir(parents=True, exist_ok=True)

    nginx_conf = nginx_dir / "nginx.gen.conf"
    xrd_conf = xrd_dir / "brix.gen.conf"
    xrd_anon_conf = xrd_anon_dir / "brix.anon.gen.conf"
    ntls = "on" if data_tls == "on" else "off"
    nginx_conf.write_text((TESTS / "nginx.perf.conf").read_text().replace("brix_tls on;", f"brix_tls {ntls};"))
    xrd_conf.write_text((TESTS / "brix.perf.conf").read_text())
    if data_tls == "on":
        xrd_conf.write_text(xrd_conf.read_text() + "\nxrd.tls /tmp/xrd-load/pki/server/hostcert.pem /tmp/xrd-load/pki/server/hostkey.pem\nxrd.tlsca certdir /tmp/xrd-load/pki/ca\nxrootd.tls data\n")
    xrd_anon_conf.write_text(
        "all.adminpath /tmp/xrd-perf-xrd-anon/admin\n"
        "all.pidpath /tmp/xrd-perf-xrd-anon/run\n"
        "oss.localroot /tmp/xrd-load/data\nall.export /\nxrd.port 12093\n"
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
            _wait_port_or_raise("127.0.0.1", 12795, "nginx XRootD+GSI")
            _wait_port_or_raise("127.0.0.1", 12796, "nginx XRootD+TLS")
            _wait_port_or_raise("127.0.0.1", 12792, "nginx WebDAV+GSI")
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
            _wait_port_or_raise("127.0.0.1", 12094, "xrootd GSI")
            children.append(_popen([str(xrootd_bin), "-c", str(xrd_anon_conf), "-l", str(xrd_anon_dir / "logs/brix.log"), "-n", "perfanon", "-b"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            _wait_port_or_raise("127.0.0.1", 12093, "xrootd anon")
        return _run_stream([sys.executable, str(TESTS / "load_test.py"), "--target", target, "--json", "/tmp/load_test_results.json", *forwarded])
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


class LifecycleProfiler:
    def __init__(self) -> None:
        self.nginx = Path(os.environ.get("NGINX", "/tmp/nginx-1.28.3/objs/nginx"))
        self.prefix = Path(os.environ.get("PREFIX", "/tmp/xrd-lifecycle-prof"))
        self.port_anon = int(os.environ.get("PORT_ANON", "21094"))
        self.port_gsi = int(os.environ.get("PORT_GSI", "21095"))
        self.workers = int(os.environ.get("WORKERS", "2"))
        self.timeout = float(os.environ.get("TIMEOUT_S", "15"))
        self.conf = self.prefix / "conf/nginx.conf"
        self.error_log = self.prefix / "logs/error.log"
        self.pidfile = self.prefix / "logs/nginx.pid"

    def provision(self) -> None:
        shutil.rmtree(self.prefix, ignore_errors=True)
        for path in (self.prefix / "conf", self.prefix / "logs", self.prefix / "data", self.prefix / "tmp"):
            path.mkdir(parents=True, exist_ok=True)
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", str(self.prefix / "conf/host.key"), "-out", str(self.prefix / "conf/host.crt"), "-subj", "/CN=lifecycle-prof"], cwd=REPO_ROOT)
        self.conf.write_text(f"""worker_processes {self.workers};
daemon on;
master_process on;
pid {self.pidfile};
error_log {self.error_log} notice;
thread_pool default threads=4 max_queue=512;
events {{ worker_connections 1024; }}
stream {{
    server {{ listen {self.port_anon}; brix_root on; brix_storage_backend posix:{self.prefix}/data; brix_auth none; }}
    server {{ listen {self.port_gsi}; brix_root on; brix_storage_backend posix:{self.prefix}/data; brix_auth gsi; brix_certificate {self.prefix}/conf/host.crt; brix_certificate_key {self.prefix}/conf/host.key; brix_trusted_ca {self.prefix}/conf/host.crt; }}
}}
""")

    def init_count(self) -> int:
        if not self.error_log.exists():
            return 0
        return len(re.findall(r"init_process\[", self.error_log.read_text(errors="ignore")))

    def master_pid(self) -> int | None:
        try:
            return int(self.pidfile.read_text().strip())
        except (OSError, ValueError):
            return None

    def worker_pids(self) -> list[int]:
        master = self.master_pid()
        if master is None:
            return []
        proc = run(["pgrep", "-P", str(master)], cwd=REPO_ROOT)
        return [int(p) for p in proc.stdout.split() if p.isdigit()]

    def wait_new_worker(self, base: int) -> None:
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            if self.init_count() > base:
                return
            time.sleep(0.01)

    def settle(self) -> None:
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            before = self.init_count()
            if len(self.worker_pids()) == self.workers:
                time.sleep(0.15)
                if self.init_count() == before:
                    return
            time.sleep(0.05)

    def profile(self) -> int:
        if not self.nginx.exists():
            print(f"FATAL: nginx binary not found/executable: {self.nginx}", file=sys.stderr)
            return 1
        self.provision()
        self.error_log.write_text("")
        start = time.time()
        if run([str(self.nginx), "-p", str(self.prefix), "-c", str(self.conf)], cwd=REPO_ROOT).returncode != 0:
            return 1
        if not _wait_tcp("127.0.0.1", self.port_anon, self.timeout):
            return 1
        cold_ms = int((time.time() - start) * 1000)
        self.settle()
        base = self.init_count()
        start = time.time()
        run([str(self.nginx), "-p", str(self.prefix), "-c", str(self.conf), "-s", "reload"], cwd=REPO_ROOT)
        self.wait_new_worker(base)
        _wait_tcp("127.0.0.1", self.port_anon, self.timeout)
        reload_ms = int((time.time() - start) * 1000)
        self.settle()
        workers = self.worker_pids()
        base = self.init_count()
        start = time.time()
        if workers:
            _safe_kill(workers[0], signal.SIGKILL)
        self.wait_new_worker(base)
        respawn_ms = int((time.time() - start) * 1000)
        self.settle()
        master = self.master_pid()
        start = time.time()
        run([str(self.nginx), "-p", str(self.prefix), "-c", str(self.conf), "-s", "quit"], cwd=REPO_ROOT)
        if master:
            while time.time() - start < self.timeout:
                try:
                    os.kill(master, 0)
                    time.sleep(0.01)
                except OSError:
                    break
        shutdown_ms = int((time.time() - start) * 1000)
        print("============================================================")
        print(f" nginx-xrootd lifecycle profile  (workers={self.workers})")
        print("============================================================")
        print(f"  cold start (boot -> first accept) : {cold_ms:6d} ms")
        print(f"  reload     (HUP  -> serving again): {reload_ms:6d} ms")
        print(f"  respawn    (kill -> worker back)  : {respawn_ms:6d} ms")
        print(f"  shutdown   (quit -> master gone)  : {shutdown_ms:6d} ms")
        print("------------------------------------------------------------")
        for line in sorted(set(re.findall(r".*(?:postconfig:|init_process\[).*", self.error_log.read_text(errors="ignore")))):
            print(re.sub(r"^.*: xrootd ", "    xrootd ", line))
        print(f" (scratch prefix: {self.prefix})")
        return 0


def run_profile_lifecycle(argv: list[str]) -> int:
    return LifecycleProfiler().profile()


def _worker_pids_csv(pidfile: Path) -> str:
    try:
        master = int(pidfile.read_text().strip())
    except (OSError, ValueError):
        return ""
    proc = run(["pgrep", "-P", str(master)], cwd=REPO_ROOT)
    return ",".join(pid for pid in proc.stdout.split() if pid.isdigit())


def run_profile_load(argv: list[str]) -> int:
    mode = argv[0] if argv else "read"
    if mode not in {"read", "write", "both"}:
        print("mode must be read|write|both", file=sys.stderr)
        return 2
    rest = argv[1:]
    concurrency = "32"
    if rest and re.match(r"^[0-9,]+$", rest[0]):
        concurrency, rest = rest[0], rest[1:]
    flame = Path(os.environ.get("FLAMEGRAPH_DIR", str(Path.home() / "FlameGraph")))
    if not shutil.which("perf") or not (flame / "stackcollapse-perf.pl").exists() or not (flame / "flamegraph.pl").exists():
        print("SKIP: perf or FlameGraph scripts unavailable", file=sys.stderr)
        return 0
    outdir = Path("/tmp/xrd-perf-test/flame")
    outdir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    passes = ["read", "write"] if mode == "both" else [mode]
    folded: list[tuple[str, Path]] = []
    for pass_mode in passes:
        base = outdir / f"{pass_mode}-{ts}"
        with (base.with_suffix(".loadlog")).open("w") as log:
            load = _popen([sys.executable, "-m", "cmdscripts.operator_runtime", "load", "nginx", "--mode", pass_mode, "--concurrency", concurrency, *rest], cwd=REPO_ROOT, env={"PYTHONPATH": "tests"}, stdout=log, stderr=log, start_new_session=True)
            pidfile = Path("/tmp/xrd-perf-test/logs/nginx.pid")
            pids = ""
            for _ in range(120):
                if load.poll() is not None:
                    break
                pids = _worker_pids_csv(pidfile)
                if pids:
                    break
                time.sleep(1)
            if not pids:
                load.terminate()
                return 1
            perf_data = base.with_suffix(".perf.data")
            perf = _popen(["perf", "record", "-F", os.environ.get("PERF_FREQ", "997"), "-e", os.environ.get("PERF_EVENT", "task-clock"), "--call-graph", os.environ.get("CALLGRAPH", "dwarf") + ",8192", "-p", pids, "-o", str(perf_data), "--", "sleep", os.environ.get("MAX_RECORD_SECS", "180")])
            while load.poll() is None and perf.poll() is None:
                time.sleep(1)
            _safe_kill(perf.pid, signal.SIGINT)
            perf.wait(timeout=10)
            load.wait()
        script = _popen(["perf", "script", "-i", str(perf_data)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        collapse = _popen([str(flame / "stackcollapse-perf.pl")], stdout=(base.with_suffix(".folded")).open("w"), stdin=script.stdout)
        if script.stdout is not None:
            script.stdout.close()
        script.wait()
        collapse.wait()
        folded.append((pass_mode, base.with_suffix(".folded")))
    if mode == "both":
        combined = outdir / f"readwrite-{ts}.folded"
        with combined.open("w") as out:
            for name, path in folded:
                for line in path.read_text(errors="ignore").splitlines():
                    out.write(f"{name};{line}\n")
        svg = outdir / f"readwrite-{ts}.svg"
        with svg.open("w") as out:
            proc = _popen([str(flame / "flamegraph.pl"), "--title", "nginx-xrootd read | write", "--width", "1800", str(combined)], stdout=out)
            proc.wait()
    else:
        svg = outdir / f"{mode}-{ts}.svg"
        with svg.open("w") as out:
            proc = _popen([str(flame / "flamegraph.pl"), "--title", f"nginx-xrootd {mode}", "--width", "1600", str(folded[0][1])], stdout=out)
            proc.wait()
    print(svg)
    return 0


def _vg_module_frame_hits(logdir: Path) -> list[str]:
    """Triage: module-frame lines (exclude nginx core), mirroring the shell grep."""
    frame = re.compile(
        r"in (brix_|ngx_http_xrootd|ngx_stream_xrootd)"
        r"|/src/(token|webdav|s3|gsi|crypto|dashboard|read|session|cache|metrics|aio|path|fattr|tpc)/"
    )
    hits: list[str] = []
    for log in sorted(logdir.glob("vg.*.log")):
        for number, line in enumerate(log.read_text(errors="ignore").splitlines(), 1):
            if frame.search(line) and "src/core" not in line:
                hits.append(f"{log}:{number}:{line}")
    return hits


def run_valgrind(argv: list[str]) -> int:
    nginx = Path(os.environ.get("NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx"))
    test_root = Path(os.environ.get("TEST_ROOT", "/tmp/xrd-test"))
    pki_dir = Path(os.environ.get("PKI_DIR", str(test_root / "pki")))
    token_dir = Path(os.environ.get("TOKEN_DIR", str(test_root / "tokens")))
    vg_work = Path(os.environ.get("VG_WORK", "/tmp/xrd-vg"))
    template = Path(os.environ.get("TEMPLATE", str(TESTS / "valgrind/nginx.conf.in")))
    supp = Path(os.environ.get("SUPP", str(TESTS / "valgrind/valgrind.supp")))
    results = vg_work / "results.txt"
    logdir = vg_work / "logs"
    for path in (logdir, vg_work / "tmp", vg_work / "data", vg_work / "conf"):
        path.mkdir(parents=True, exist_ok=True)
    results.write_text("")

    def note(text: str) -> None:
        with results.open("a") as handle:
            handle.write(text + "\n")

    if not shutil.which("valgrind"):
        note("MISSING valgrind")
        note("FINISHED")
        return 1
    if not os.access(nginx, os.X_OK):
        note(f"MISSING nginx binary {nginx}")
        note("FINISHED")
        return 1
    ca_cert = pki_dir / "ca/ca.pem"
    client_cert, client_key = pki_dir / "user/usercert.pem", pki_dir / "user/userkey.pem"
    required = [ca_cert, pki_dir / "server/hostcert.pem", pki_dir / "server/hostkey.pem", token_dir / "jwks.json"]
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        note("MISSING fixture " + ", ".join(missing))
        note("FINISHED")
        return 1
    (vg_work / "data/vgtest.txt").write_text(f"valgrind harness payload {int(time.time())}\n")
    values = {
        "{WORK}": str(vg_work),
        "{CA_DIR}": str(pki_dir / "ca"),
        "{CA_CERT}": str(ca_cert),
        "{SERVER_CERT}": str(pki_dir / "server/hostcert.pem"),
        "{SERVER_KEY}": str(pki_dir / "server/hostkey.pem"),
        "{CLIENT_CERT}": str(client_cert),
        "{CLIENT_KEY}": str(client_key),
        "{TOKEN_DIR}": str(token_dir),
        "{GSI_TLS_PORT}": os.environ.get("GSI_TLS_PORT", "28444"),
        "{HTTP_PORT}": os.environ.get("HTTP_PORT", "28080"),
        "{S3_PORT}": os.environ.get("S3_PORT", "29051"),
        "{METRICS_PORT}": os.environ.get("METRICS_PORT", "29100"),
    }
    conf = vg_work / "conf/nginx.conf"
    rendered = template.read_text()
    for key, value in values.items():
        rendered = rendered.replace(key, value)
    conf.write_text(rendered)
    tested = run([str(nginx), "-t", "-p", str(vg_work), "-c", str(conf)], cwd=REPO_ROOT)
    if tested.returncode != 0:
        note("CONFIG INVALID")
        note("FINISHED")
        return 1
    # Reap any prior harness bound to this unique config path (valgrind's visible
    # cmdline is the nginx invocation, so match the config, not the process name).
    run(["pkill", "-9", "-f", str(conf)], cwd=REPO_ROOT)
    time.sleep(2)
    for old in logdir.glob("vg.*.log"):
        old.unlink()
    vg = _popen(
        [
            "valgrind",
            "--leak-check=full",
            "--show-leak-kinds=definite,indirect",
            "--track-fds=yes",
            "--trace-children=yes",
            "--child-silent-after-fork=no",
            "--error-exitcode=0",
            "--num-callers=30",
            f"--suppressions={supp}",
            f"--log-file={logdir}/vg.%p.log",
            str(nginx),
            "-p",
            str(vg_work),
            "-c",
            str(conf),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    http_port, gsi_port = values["{HTTP_PORT}"], values["{GSI_TLS_PORT}"]
    s3_port, metrics_port = values["{S3_PORT}"], values["{METRICS_PORT}"]
    # Valgrind boots the worker ~20x slower than native.
    for second in range(1, 121):
        if _wait_tcp("127.0.0.1", int(http_port), 1.0):
            note(f"up after {second}s")
            break
    curl = shutil.which("curl") or "curl"

    def code(*args: str) -> str:
        return run([curl, "-s", "-o", "/dev/null", "-w", "%{http_code}", *args], cwd=REPO_ROOT).stdout.strip()

    # ---- Exercise every external-handle path (mirrors run_valgrind.sh) ----
    jwt_path = token_dir / "upstream.jwt"
    jwt = jwt_path.read_text().strip() if jwt_path.exists() else ""
    base = f"http://127.0.0.1:{http_port}"
    note(
        f"jwt valid={code('-H', f'Authorization: Bearer {jwt}', f'{base}/vgtest.txt')}"
        f" garbage={code('-H', 'Authorization: Bearer aa.bb.cc', f'{base}/vgtest.txt')}"
        f" malformed={code('-H', 'Authorization: Bearer xyz', f'{base}/vgtest.txt')}"
        f" put={code('-T', str(vg_work / 'data/vgtest.txt'), '-H', f'Authorization: Bearer {jwt}', f'{base}/put.txt')}"
    )
    tls = f"https://127.0.0.1:{gsi_port}"
    x509 = ["--cert", str(client_cert), "--key", str(client_key), "--cacert", str(ca_cert)]
    gsi_line = f"gsi usercert={code('-k', *x509, f'{tls}/vgtest.txt')}"
    proxy_cert, proxy_key = pki_dir / "user/proxy.pem", pki_dir / "user/proxykey.pem"
    if proxy_cert.exists() and proxy_key.exists():
        gsi_line += f" proxycert={code('-k', '--cert', str(proxy_cert), '--key', str(proxy_key), '--cacert', str(ca_cert), f'{tls}/vgtest.txt')}"
    gsi_line += f" noclientcert={code('-k', f'{tls}/vgtest.txt')}"
    note(gsi_line)
    minted = run(
        [
            curl, "-s", "-X", "POST",
            "-d", "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&scope=storage.read:/ storage.write:/&expires_in=600",
            f"{base}/.oauth2/token",
        ],
        cwd=REPO_ROOT,
    ).stdout
    macaroon_line = f"macaroon mint_bytes={len(minted)}"
    token = re.search(r'"(?:macaroon|access_token)"[: ]*"([^"]*)"', minted)
    if token:
        macaroon_line += f" use={code('-H', f'Authorization: Bearer {token.group(1)}', f'{base}/vgtest.txt')}"
    note(macaroon_line)
    note(
        f"tpc pull={code('-k', *x509, '-X', 'COPY', '-H', f'Source: {tls}/vgtest.txt', f'{tls}/tpc_pulled.txt')}"
        f" push_unreach={code('-k', *x509, '-X', 'COPY', '-H', 'Destination: https://127.0.0.1:1/dead.txt', f'{tls}/vgtest.txt')}"
    )
    note(
        f"s3 badsig={code('-H', 'Authorization: AWS4-HMAC-SHA256 Credential=x/y, SignedHeaders=host, Signature=dead', f'http://127.0.0.1:{s3_port}/testbucket/vgtest.txt')}"
        f" anon={code(f'http://127.0.0.1:{s3_port}/testbucket/vgtest.txt')}"
        f" | metrics={code(f'http://127.0.0.1:{metrics_port}/metrics')}"
    )

    # ---- Shutdown: SIGQUIT the master so the worker exits cleanly and its
    # valgrind dumps a complete report; the master's own log is discarded below
    # (its reap NULL-derefs in nginx-core ngx_unlock_mutexes under valgrind). ----
    time.sleep(2)
    pidfile = logdir / "nginx.pid"
    master = pidfile.read_text().strip() if pidfile.exists() else ""
    bound = run(["pgrep", "-f", str(conf)], cwd=REPO_ROOT).stdout.split()
    workers = [p for p in bound if p not in (str(vg.pid), master)]
    if master.isdigit():
        _safe_kill(int(master), signal.SIGQUIT)
    if workers:
        worker = int(workers[0])
        for _ in range(180):
            try:
                os.kill(worker, 0)
            except OSError:
                break
            time.sleep(1)
    time.sleep(2)
    for pid in run(["pgrep", "-f", str(conf)], cwd=REPO_ROOT).stdout.split():
        _safe_kill(int(pid), signal.SIGKILL)
    _safe_kill(vg.pid, signal.SIGKILL)
    time.sleep(1)
    master_log = logdir / f"vg.{master}.log"
    if master.isdigit() and master_log.exists():
        master_log.rename(logdir / f"vg.master-{master}.discarded")

    note("---- vg logs ----")
    logs = sorted(logdir.glob("vg.*.log"))
    for log in logs:
        text = log.read_text(errors="ignore")
        leakish = len(re.findall(r"definitely lost|indirectly lost|Invalid (?:read|write)|uninitialised", text))
        summary = ""
        for line in text.splitlines():
            if "ERROR SUMMARY" in line:
                summary = line
        note(f"{log.name}: leakish={leakish}  {summary}")
    note("---- MODULE-FRAME HITS (should be empty) ----")
    hits = _vg_module_frame_hits(logdir)
    for hit in hits or ["(none)"]:
        note(hit)
    note(f"DONE logs={len(logs)}")
    print(results)
    return 0


RUNNERS = {
    "suite": run_suite,
    "load": run_load,
    "profile-lifecycle": run_profile_lifecycle,
    "profile-load": run_profile_load,
    "valgrind": run_valgrind,
}


def run_checks(base: Path, names: Iterable[str] | None = None) -> list[tuple[bool, str]]:
    selected = list(names or [])
    if not selected:
        return [result(True, "operator runtime ports are importable; execution is opt-in")]
    results = []
    for name in selected:
        runner = RUNNERS.get(name)
        if runner is None:
            results.append(result(False, f"unknown operator runtime port: {name}"))
            continue
        if os.environ.get("PHASE81_RUN_OPERATOR_RUNTIME") != "1":
            results.append(result(True, f"SKIP {name}: set PHASE81_RUN_OPERATOR_RUNTIME=1 to execute"))
            continue
        rc = runner([])
        results.append(result(rc == 0, f"{name} exited {rc}"))
    return results


def entry(argv: list[str]) -> int:
    if argv and argv[0] in RUNNERS:
        return RUNNERS[argv[0]](argv[1:])
    with tempfile.TemporaryDirectory(prefix="operator_runtime.") as tmp:
        results = run_checks(Path(tmp), argv)
    for ok, message in results:
        print(f"  {'ok  ' if ok else 'FAIL'} {message}")
    return 0 if all(ok for ok, _ in results) else 1


if __name__ == "__main__":
    from cmdscripts import main

    raise SystemExit(main(entry))
