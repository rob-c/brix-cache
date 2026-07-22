"""Direct Python ports of the phase-68 CVMFS comparison-matrix shell scripts.

Ported shell scripts (kept in place; these are their Python replacements):
  tests/cvmfs/run_matrix.sh     -> matrix
  tests/cvmfs/run_baselines.sh  -> cvmfs-baselines
  tests/cvmfs/spike_cas_hash.sh -> spike-cas-hash
  tests/cvmfs/netem_lab.sh      -> netem-lab

The matrix and netem-lab scenarios need root (network namespaces + tc netem)
and skip cleanly otherwise. spike-cas-hash contacts a real Stratum-1 and skips
when offline. cvmfs-baselines skips each proxy that is not installed.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import zlib
from pathlib import Path

from cmdscripts.live_common import LiveFailure, LiveRun, REPO_ROOT
from cmdscripts.brixcvmfs_live import LiveSkip, _checks
from lib_py.util import wait_tcp
from fleet_ports import cmdscript_ports
from settings import BIND_HOST, HOST

_PORTS = cmdscript_ports("cvmfs_matrix")

CVMFS_DIR = REPO_ROOT / "tests/cvmfs"
BASELINES_DIR = REPO_ROOT / "deploy/cvmfs/baselines"

# --- netem lab (port of tests/cvmfs/netem_lab.sh) --------------------------
# Host side 10.199.0.1 (cache under test) <-> ns "cvmfslab" 10.199.0.2 (origin).
# Impairment is applied on BOTH veth ends so loss/reorder hits each direction.

NS, VETH_HOST, VETH_NS = "cvmfslab", "cvmfs-h", "cvmfs-n"
HOST_IP, NS_IP = "10.199.0.1", "10.199.0.2"

NETEM_PROFILES = {
    "clean": "",
    "loss": "loss 3%",
    "reorder": "delay 10ms reorder 25% 50%",
    "corrupt": "corrupt 0.5%",
    "jitter": "delay 80ms 40ms distribution normal",
    "site": "delay 30ms 15ms loss 1% reorder 10% 50% corrupt 0.1%",
}

MATRIX_PROFILES = ["clean", "loss", "reorder", "corrupt", "jitter", "site"]
MATRIX_CACHES = ["module-reverse", "module-proxy", "stock-nginx", "squid", "varnish"]

RESULT_KEYS = [
    "cold_ttfb_p50_ms",
    "cold_ttfb_p99_ms",
    "warm_ttfb_p50_ms",
    "error_rate",
    "stampede_origin_fetches",
    "corrupt_served",
]


def _sh(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run([str(item) for item in argv], capture_output=True, text=True)
    if check and proc.returncode:
        raise LiveFailure(f"{' '.join(str(a) for a in argv)} failed ({proc.returncode}): {proc.stderr or proc.stdout}")
    return proc


def _netem_usable() -> bool:
    """True only if the sch_netem qdisc can actually be instantiated. A network
    namespace can be created on hosts where the sch_netem kernel module is
    absent, so `tc qdisc add ... netem` then fails with 'qdisc kind is unknown'.
    Probe inside a throwaway netns so the host loopback the fleet runs on is
    never perturbed."""
    probe_ns = "cvmfs_netem_probe"
    subprocess.run(["ip", "netns", "del", probe_ns], capture_output=True, text=True)
    if subprocess.run(["ip", "netns", "add", probe_ns], capture_output=True, text=True).returncode:
        return False
    try:
        subprocess.run(["ip", "netns", "exec", probe_ns, "ip", "link", "set", "lo", "up"], capture_output=True, text=True)
        probe = subprocess.run(
            ["ip", "netns", "exec", probe_ns, "tc", "qdisc", "add", "dev", "lo", "root", "netem", "delay", "1ms"],
            capture_output=True, text=True,
        )
        return probe.returncode == 0
    finally:
        subprocess.run(["ip", "netns", "del", probe_ns], capture_output=True, text=True)


def _require_root_netem() -> None:
    if os.geteuid() != 0:
        raise LiveSkip("must run as root (netem network namespace lab)")
    for tool in ("ip", "tc"):
        if shutil.which(tool) is None:
            raise LiveSkip(f"{tool} not installed")
    if not _netem_usable():
        raise LiveSkip("netem qdisc unavailable (sch_netem kernel module missing)")


def lab_up() -> None:
    _sh(["ip", "netns", "add", NS])
    _sh(["ip", "link", "add", VETH_HOST, "type", "veth", "peer", "name", VETH_NS])
    _sh(["ip", "link", "set", VETH_NS, "netns", NS])
    _sh(["ip", "addr", "add", f"{HOST_IP}/24", "dev", VETH_HOST])
    _sh(["ip", "link", "set", VETH_HOST, "up"])
    _sh(["ip", "netns", "exec", NS, "ip", "addr", "add", f"{NS_IP}/24", "dev", VETH_NS])
    _sh(["ip", "netns", "exec", NS, "ip", "link", "set", VETH_NS, "up"])
    _sh(["ip", "netns", "exec", NS, "ip", "link", "set", "lo", "up"])
    print(f"lab up: host {HOST_IP} <-> ns {NS} {NS_IP}")


def lab_profile(name: str) -> None:
    if name not in NETEM_PROFILES:
        raise LiveFailure(f"unknown profile: {name}")
    args = NETEM_PROFILES[name]
    _sh(["tc", "qdisc", "del", "dev", VETH_HOST, "root"], check=False)
    _sh(["ip", "netns", "exec", NS, "tc", "qdisc", "del", "dev", VETH_NS, "root"], check=False)
    if args:
        _sh(["tc", "qdisc", "add", "dev", VETH_HOST, "root", "netem", *args.split()])
        _sh(["ip", "netns", "exec", NS, "tc", "qdisc", "add", "dev", VETH_NS, "root", "netem", *args.split()])
    print(f"profile: {name} ({args})")


def lab_status() -> str:
    proc = _sh(["tc", "qdisc", "show", "dev", VETH_HOST], check=False)
    return proc.stdout if proc.returncode == 0 else "lab not up"


def lab_down() -> None:
    _sh(["ip", "link", "del", VETH_HOST], check=False)
    _sh(["ip", "netns", "del", NS], check=False)
    print("lab down")


def netem_lab(nginx: Path | None = None) -> int:
    """Lifecycle exercise of the impaired-network lab: up, every profile, down."""
    _require_root_netem()
    checks: list[tuple[bool, str]] = []
    lab_down()  # clear any stale lab first (idempotent)
    try:
        lab_up()
        ping = _sh(["ip", "netns", "exec", NS, "ping", "-c", "1", "-W", "2", HOST_IP], check=False)
        checks.append((ping.returncode == 0, "ns origin can reach the host cache side"))
        for name, args in NETEM_PROFILES.items():
            lab_profile(name)
            status = lab_status()
            applied = ("netem" in status) if args else ("netem" not in status)
            checks.append((applied, f"profile {name}: qdisc state matches ({args or 'no impairment'})"))
        checks.append((lab_status() != "lab not up", "status reports the live lab"))
    finally:
        lab_down()
    checks.append(("lab not up" in lab_status() or "netem" not in lab_status(), "lab torn down"))
    return _checks(checks)


# --- spike-cas-hash (port of tests/cvmfs/spike_cas_hash.sh) -----------------


def spike_cas_hash(nginx: Path | None = None) -> int:
    """Determine the CVMFS CAS hashing convention empirically against a real
    Stratum-1: fetch the root catalog object and hash it raw and inflated."""
    stratum1 = os.environ.get("SPIKE_S1", "http://cvmfs-stratum-one.cern.ch/cvmfs/cvmfs-config.cern.ch")
    with LiveRun("cvmfs_spike", nginx) as run:
        # .cvmfspublished is a *signed* manifest: ASCII header lines followed by
        # a binary signature after the "--" marker, so it must be fetched as
        # bytes (a text fetch chokes decoding the signature). We only need the
        # ASCII header, so decode leniently up to the signature boundary.
        try:
            manifest = run.curl_bytes(f"{stratum1}/.cvmfspublished", "-f", timeout=15)
        except LiveFailure:
            raise LiveSkip(f"Stratum-1 unreachable ({stratum1})")
        header = manifest.split(b"\n--\n", 1)[0].decode("ascii", errors="replace")
        root = next((line[1:] for line in header.splitlines() if line.startswith("C")), "")
        if not root:
            raise LiveFailure("manifest has no root catalog (C) line")
        print(f"repo manifest root catalog: {root}")
        url = f"{stratum1}/data/{root[:2]}/{root[2:]}C"
        raw = run.curl_bytes(url, "-f")
        raw_sha1 = hashlib.sha1(raw).hexdigest()
        try:
            inflated_sha1 = hashlib.sha1(zlib.decompress(raw)).hexdigest()
            print(f"inflated sha1: {inflated_sha1}")
        except zlib.error as exc:
            inflated_sha1 = ""
            print(f"inflate failed: {exc}")
        print(f"raw sha1:      {raw_sha1}")
        print(f"expected:      {root}")
        convention = "inflated" if inflated_sha1 == root else "raw" if raw_sha1 == root else None
        print(f"VERDICT: {convention or 'NO'} hashing convention matches the CAS name")
        return _checks([(convention is not None, f"CAS name matches a hashing convention ({convention})")])


# --- baselines (port of tests/cvmfs/run_baselines.sh) -----------------------


def run_baseline(run: LiveRun, name: str, port: int, origin: str, out_dir: Path) -> tuple[bool, str]:
    """Run the harness against a squid or varnish baseline; SKIP when the proxy
    binary is not installed. Writes <out_dir>/baseline_<name>.json."""
    origin_host, origin_port = origin.rsplit(":", 1)
    work = run.mkdir(f"baseline_{name}")
    out = out_dir / f"baseline_{name}.json"
    harness_env: dict[str, str] = {}
    if name == "squid":
        if shutil.which("squid") is None:
            return True, "SKIP: squid not installed"
        (work / "cache").mkdir(exist_ok=True)
        # The baseline conf follows WLCG guidance whose default pid/log/coredump
        # paths (/run/squid.pid, /var/log/squid) are only writable by root. Pin
        # them into the per-run work dir so the baseline stands up unprivileged.
        squid_conf = (
            (BASELINES_DIR / "squid.conf").read_text()
            .replace("@PORT@", str(port))
            .replace("@CACHEDIR@", f"{work}/cache")
            .replace("@ORIGINHOST@", origin_host)
        ) + (
            f"\npid_filename {work}/squid.pid\n"
            f"access_log {work}/access.log\n"
            f"cache_log {work}/cache.log\n"
            f"coredump_dir {work}/cache\n"
        )
        conf = run.write(work / "squid.conf", squid_conf)
        # squid drops to the unprivileged "squid" user, which must traverse the
        # 0700 mkdtemp run root and write pid/log/swap files into the work dir.
        # Open the chain (root o+rx, work + cache o+rwx) so it stands up as root.
        run.root.chmod(0o755)
        work.chmod(0o777)
        (work / "cache").chmod(0o777)
        run.call(["squid", "-f", conf, "-z"], check=False)
        run.call(["squid", "-f", conf])
        stop = ["squid", "-f", str(conf), "-k", "shutdown"]
        # squid is a forward proxy: harness must use proxy-style URLs
        harness_env["http_proxy"] = f"http://{HOST}:{port}"
        cache_base = f"http://{origin}"
    elif name == "varnish":
        if shutil.which("varnishd") is None:
            return True, "SKIP: varnishd not installed"
        vcl = run.write(
            work / "default.vcl",
            (BASELINES_DIR / "varnish.vcl").read_text()
            .replace("@ORIGINHOST@", origin_host)
            .replace("@ORIGINPORT@", origin_port),
        )
        # varnishd jails the VCL compiler under the unprivileged "varnish" user,
        # which cannot traverse the 0700 mkdtemp run root nor read the VCL. Open
        # the path chain so the compiler can read -f (dirs o+rx, file o+r).
        run.root.chmod(0o755)
        work.chmod(0o755)
        vcl.chmod(0o644)
        run.call(["varnishd", "-a", f"{BIND_HOST}:{port}", "-f", vcl, "-n", work / "vn", "-s", "malloc,256m"])
        stop = ["pkill", "-f", f"varnishd .*{work}/vn"]
        cache_base = f"http://{HOST}:{port}"
    else:
        raise LiveFailure(f"unknown baseline: {name}")
    try:
        if not wait_tcp(BIND_HOST, port, 10):
            return False, f"{name} did not listen on {port}"
        harness = run.call(
            [sys.executable, CVMFS_DIR / "harness.py", "--cache", cache_base, "--mock", f"http://{origin}", "--out", out],
            env=harness_env,
            check=False,
        )
    finally:
        run.call(stop, check=False)
    if harness.returncode != 0:
        return False, f"{name} harness failed: {(harness.stderr or harness.stdout)[-2000:]}"
    return True, f"wrote {out}"


def _start_mock(run: LiveRun, argv_prefix: list[str], bind: str, port: int) -> subprocess.Popen:
    proc = run.spawn([*argv_prefix, sys.executable, CVMFS_DIR / "mock_stratum1.py", "--bind", bind, "--port", str(port), "--objects", "16", "--seed", "68"])
    time.sleep(0.5)
    if proc.poll() is not None:
        raise LiveFailure(f"mock Stratum-1 on {bind}:{port} did not start")
    return proc


def cvmfs_baselines(nginx: Path | None = None) -> int:
    """Standalone squid/varnish baseline runs against a local mock Stratum-1."""
    out_dir = Path(os.environ.get("CVMFS_BASELINE_OUT", os.getcwd()))
    with LiveRun("cvmfs_baseline", nginx) as run:
        mock_port, squid_port, varnish_port = _PORTS[0:3]  # was free_ports(3)
        _start_mock(run, [], BIND_HOST, mock_port)
        origin = f"{HOST}:{mock_port}"
        checks = [
            run_baseline(run, "squid", squid_port, origin, out_dir),
            run_baseline(run, "varnish", varnish_port, origin, out_dir),
        ]
        return _checks(checks)


# --- matrix (port of tests/cvmfs/run_matrix.sh) ------------------------------


def _module_conf_body(listen_port: int, location: str, directives: str, work: Path) -> str:
    return f"""daemon on; error_log {work}/e.log warn; pid {work}/nginx.pid;
thread_pool default threads=4;
events {{ worker_connections 512; }}
http {{ access_log off;
    keepalive_timeout 3600s; keepalive_requests 1000000;
    send_timeout 300s; client_header_timeout 300s;
    reset_timedout_connection off;
    server {{
    listen {BIND_HOST}:{listen_port} so_keepalive=60s:10s:6 backlog=2048;
    location {location} {{
{directives}
    }}
}} }}
"""


def _stop_pidfile(pidfile: Path) -> None:
    try:
        os.kill(int(pidfile.read_text().strip()), signal.SIGTERM)
    except (OSError, ValueError):
        pass


def matrix(nginx: Path | None = None) -> int:
    """The phase-68 comparison matrix: each cache implementation x each netem
    profile gets a fresh lab, a mock origin inside the impaired ns, one harness
    run, one JSON. Renders RESULTS.md rows at the end. Requires root (netem);
    squid/varnish cells are skipped when not installed."""
    _require_root_netem()
    out_dir = Path(os.environ.get("CVMFS_MATRIX_OUT", BASELINES_DIR))
    out_dir.mkdir(parents=True, exist_ok=True)
    rows_path = out_dir / "matrix_rows.tsv"
    rows_path.write_text("")
    with LiveRun("cvmfs_matrix", nginx) as run:
        if not run.nginx.exists():
            raise LiveSkip(f"nginx binary not found: {run.nginx}")
        mock_port, cache_port, proxy_port = _PORTS[3:6]  # was free_ports(3)
        netns = ["ip", "netns", "exec", NS]
        try:
            for cache in MATRIX_CACHES:
                for profile in MATRIX_PROFILES:
                    lab_down()
                    lab_up()
                    lab_profile(profile)
                    mock = _start_mock(run, netns, NS_IP, mock_port)
                    work = run.mkdir(f"w_{cache}_{profile}")
                    result_json = _matrix_cell(run, cache, profile, work, out_dir, mock_port, cache_port, proxy_port)
                    if result_json:
                        with rows_path.open("a") as rows:
                            rows.write(f"{cache}\t{profile}\t{result_json}\n")
                    mock.terminate()
        finally:
            lab_down()
        appended = _render_results(out_dir)
        print(f"appended {appended} rows to RESULTS.md")
        return 0 if appended else 1


def _matrix_cell(run: LiveRun, cache: str, profile: str, work: Path, out_dir: Path, mock_port: int, cache_port: int, proxy_port: int) -> str:
    """Run one cache x profile cell; return the result JSON path ('' on failure)."""
    origin = f"{NS_IP}:{mock_port}"
    harness_env: dict[str, str] = {}
    pidfile = work / "nginx.pid"
    if cache == "module-reverse":
        config = run.write(work / "nginx.conf", _module_conf_body(cache_port, "/cvmfs/", f"""        brix_storage_backend http://{origin};
        brix_cache_store posix:{work}/cache;
        brix_cache_verify cvmfs-cas;
        brix_cvmfs on;
        brix_cvmfs_client_hold 25;""", work))
        (work / "cache").mkdir(exist_ok=True)
        (work / "logs").mkdir(exist_ok=True)
        run.call([run.nginx, "-c", config, "-p", work])
        cache_base = f"http://{HOST}:{cache_port}"
    elif cache == "module-proxy":
        config = run.write(work / "nginx.conf", _module_conf_body(proxy_port, "/", f"""        brix_cache_store posix:{work}/cache;
        brix_cache_verify cvmfs-cas;
        brix_cvmfs on;
        brix_cvmfs_client_hold 25;
        brix_cvmfs_upstream_allow {NS_IP};""", work))
        (work / "cache").mkdir(exist_ok=True)
        (work / "logs").mkdir(exist_ok=True)
        run.call([run.nginx, "-c", config, "-p", work])
        harness_env["http_proxy"] = f"http://{HOST}:{proxy_port}"
        cache_base = f"http://{origin}"
    elif cache == "stock-nginx":
        template = (REPO_ROOT / "deploy/cvmfs/nginx-proxy-cache.conf").read_text()
        config = run.write(
            work / "nginx.conf",
            template.replace("@PORT@", str(cache_port))
            .replace("@PPORT@", str(proxy_port))
            .replace("@CACHEDIR@", str(work))
            .replace("@ORIGIN@", origin)
            .replace("@ORIGINHOST@", NS_IP)
            .replace("@ORIGINPORT@", str(mock_port)),
        )
        (work / "store").mkdir(exist_ok=True)
        (work / "logs").mkdir(exist_ok=True)
        run.call([run.nginx, "-c", config, "-p", work])
        cache_base = f"http://{HOST}:{cache_port}"
    elif cache in ("squid", "varnish"):
        # delegate to the baseline runner; it sets its own proxy env/base
        ok, message = run_baseline(run, cache, cache_port, origin, out_dir)
        print(f"  {'ok  ' if ok else 'FAIL'} baseline {cache}/{profile}: {message}")
        if ok and not message.startswith("SKIP"):
            return str(out_dir / f"baseline_{cache}.json")
        return ""
    else:
        raise LiveFailure(f"unknown cache implementation: {cache}")

    result_json = out_dir / f"results_{cache}_{profile}.json"
    harness = run.call(
        [sys.executable, CVMFS_DIR / "harness.py", "--cache", cache_base, "--mock", f"http://{origin}", "--out", result_json],
        env=harness_env,
        check=False,
    )
    _stop_pidfile(pidfile)
    if harness.returncode != 0:
        print(f"  FAIL harness {cache}/{profile}: {(harness.stderr or harness.stdout)[-1000:]}")
        return ""
    return str(result_json)


def _render_results(out_dir: Path) -> int:
    rows = [line.split("\t") for line in (out_dir / "matrix_rows.tsv").read_text().splitlines() if line]
    today = datetime.date.today().isoformat()
    lines = []
    for cache, profile, path in rows:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = out_dir / path
        try:
            data = json.loads(candidate.read_text())
        except (OSError, ValueError):
            continue
        cells = [
            f"{data.get(key, ''):.1f}" if isinstance(data.get(key), float) else str(data.get(key, ""))
            for key in RESULT_KEYS
        ]
        note = f"conn_failures={data.get('conn_failures', '?')}"
        lines.append(f"| {cache} | {profile} | " + " | ".join(cells) + f" | {today} | {note} |")
    if lines:
        with (out_dir / "RESULTS.md").open("a") as results:
            results.write("\n".join(lines) + "\n")
    return len(lines)


SCENARIOS = {
    "matrix": matrix,
    "cvmfs-baselines": cvmfs_baselines,
    "spike-cas-hash": spike_cas_hash,
    "netem-lab": netem_lab,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("nginx", nargs="?", type=Path)
    ns = parser.parse_args(argv)
    try:
        return SCENARIOS[ns.scenario](ns.nginx)
    except LiveSkip as exc:
        print(f"SKIP: {exc}")
        return 0
    except LiveFailure as exc:
        print(f"CVMFS matrix scenario failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
