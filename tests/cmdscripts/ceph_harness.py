"""Direct Python port of tests/ceph_harness.sh — single-node Ceph (RADOS) test
cluster in Docker.

WHAT: brings up the all-in-one `quay.io/ceph/demo` container (MON+MGR+OSD) on
      the host network, creates the test pool, and extracts a ceph.conf +
      admin keyring so host-side librados clients (the nginx sd_ceph driver and
      the standalone tests) can connect. Drives the phase-60 Ceph backend.
WHY:  phase-60 / scan phase-4b need a real RADOS pool to exercise the catalog
      enumerate verb + inventory/drift orphan detection cross-backend.
HOW:  `python3 -m cmdscripts.ceph_harness start|stop|status|env|pool-reset`.
      `env` prints the shell exports (TEST_CEPH=1, CEPH_CONF, CEPH_KEYRING,
      CEPH_POOL, CEPH_MON_HOST) for `eval`.

Overridable: CEPH_IMAGE, CEPH_POOL, CEPH_CONTAINER, CEPH_DIR, MON_IP,
PROBE_IMAGE.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

from cmdscripts.compile_run import REPO_ROOT, run


def _env(name: str, default: str) -> str:
    return os.environ.get(name) or default


def ceph_image() -> str:
    return _env("CEPH_IMAGE", "quay.io/ceph/demo:latest-reef")


def ceph_container() -> str:
    return _env("CEPH_CONTAINER", "xrd-ceph-demo")


def ceph_pool() -> str:
    return _env("CEPH_POOL", "xrdtest")


def ceph_dir() -> Path:
    return Path(_env("CEPH_DIR", "/tmp/ceph-harness"))


def ceph_conf() -> Path:
    return ceph_dir() / "ceph.conf"


def ceph_keyring() -> Path:
    return ceph_dir() / "ceph.client.admin.keyring"


def probe_image() -> str:
    return _env("PROBE_IMAGE", "alpine")


def have_docker() -> bool:
    return shutil.which("docker") is not None


def _docker(argv: list[str]) -> subprocess.CompletedProcess:
    return run(["docker", *argv], cwd=REPO_ROOT)


def _container_running(name: str) -> bool:
    proc = _docker(["ps", "--format", "{{.Names}}"])
    return proc.returncode == 0 and name in proc.stdout.splitlines()


# --------------------------------------------------------------------------- #
# Address detection: the container-visible primary IPv4 CIDR, probed from
# INSIDE a host-net container so it is correct whether the daemon shares the
# real host network (native Docker) or the Docker-Desktop VM. Skips lo, /32
# addresses, and 172.1x.* docker-bridge ranges (as the shell awk did).
# --------------------------------------------------------------------------- #
def detect_container_cidr() -> str:
    proc = _docker(["run", "--rm", "--network", "host", probe_image(),
                    "ip", "-4", "-o", "addr", "show"])
    if proc.returncode != 0:
        return ""
    for line in proc.stdout.splitlines():
        fields = line.split()
        if len(fields) < 4:
            continue
        iface, cidr = fields[1], fields[3]
        if iface == "lo" or cidr.endswith("/32") or re.match(r"^172\.1[0-9]\.", cidr):
            continue
        return cidr
    return ""


def cidr_net(cidr: str) -> str:
    """Network of a CIDR, e.g. 192.168.65.3/24 -> 192.168.65.0/24."""
    return str(ipaddress.ip_network(cidr, strict=False))


def cidr_ip(cidr: str) -> str:
    return cidr.split("/", 1)[0]


def detect_ip() -> str:
    """The MON's reachable address — an explicit MON_IP override wins."""
    mon_ip = os.environ.get("MON_IP")
    if mon_ip:
        return mon_ip
    return cidr_ip(detect_container_cidr())


def wait_health(tries: int = 90, delay: float = 2.0) -> bool:
    container = ceph_container()
    for _ in range(tries):
        proc = _docker(["exec", container, "ceph", "-s"])
        if proc.returncode == 0 and re.search(r"HEALTH_OK|HEALTH_WARN", proc.stdout):
            return True
        time.sleep(delay)
    print("ceph_harness: cluster did not become healthy in time", file=sys.stderr)
    logs = _docker(["logs", "--tail", "40", container])
    print(logs.stdout + logs.stderr, file=sys.stderr)
    return False


def _ensure_pool() -> None:
    """Idempotent test pool. Single-OSD demo: 1 replica so the pool is fully
    active (the demo's own default pools may still warn — harmless)."""
    container, pool = ceph_container(), ceph_pool()
    listing = _docker(["exec", container, "ceph", "osd", "pool", "ls"])
    if listing.returncode == 0 and pool in listing.stdout.splitlines():
        return
    _docker(["exec", container, "ceph", "osd", "pool", "create", pool, "32", "32"])
    _docker(["exec", container, "ceph", "osd", "pool", "application", "enable", pool, "rados"])
    _docker(["exec", container, "ceph", "osd", "pool", "set", pool, "size", "1"])
    _docker(["exec", container, "ceph", "osd", "pool", "set", pool, "min_size", "1"])


def cmd_start() -> int:
    if not have_docker():
        print("ceph_harness: docker not found", file=sys.stderr)
        return 2
    container = ceph_container()
    if _container_running(container):
        print(f"ceph_harness: {container} already running")
    else:
        _docker(["rm", "-f", container])
        # The demo image needs an explicit MON_IP + CEPH_PUBLIC_NETWORK; derive
        # both from the container-visible interface. An explicit MON_IP wins.
        mon_ip = os.environ.get("MON_IP")
        if mon_ip:
            mon = mon_ip
            net = os.environ.get("CEPH_PUBLIC_NETWORK") or cidr_net(f"{mon_ip}/24")
        else:
            cidr = detect_container_cidr()
            if not cidr:
                print("ceph_harness: cannot detect container IP", file=sys.stderr)
                return 1
            mon, net = cidr_ip(cidr), cidr_net(cidr)
        print(f"ceph_harness: starting {ceph_image()}  MON_IP={mon}  NET={net}")
        started = _docker([
            "run", "-d", "--name", container, "--network", "host",
            "-e", f"MON_IP={mon}", "-e", f"CEPH_PUBLIC_NETWORK={net}",
            "-e", "CEPH_DAEMON=demo", "-e", "DEMO_DAEMONS=mon,mgr,osd",
            "-e", "RGW_NAME=localhost",
            ceph_image(),
        ])
        if started.returncode != 0:
            print(f"ceph_harness: docker run failed: {started.stderr or started.stdout}",
                  file=sys.stderr)
            return 1
        if not wait_health():
            return 1

    ceph_dir().mkdir(parents=True, exist_ok=True)
    for src, dst in (("/etc/ceph/ceph.conf", ceph_conf()),
                     ("/etc/ceph/ceph.client.admin.keyring", ceph_keyring())):
        copied = _docker(["cp", f"{container}:{src}", str(dst)])
        if copied.returncode != 0:
            print(f"ceph_harness: docker cp {src} failed: {copied.stderr}", file=sys.stderr)
            return 1

    _ensure_pool()
    print(f"ceph_harness: pool '{ceph_pool()}' ready; conf={ceph_conf()} keyring={ceph_keyring()}")
    return cmd_env()


def cmd_env() -> int:
    print("export TEST_CEPH=1")
    print(f"export CEPH_CONF='{ceph_conf()}'")
    print(f"export CEPH_KEYRING='{ceph_keyring()}'")
    print(f"export CEPH_POOL='{ceph_pool()}'")
    print(f"export CEPH_MON_HOST='{detect_ip()}'")
    return 0


def cmd_status() -> int:
    proc = _docker(["exec", ceph_container(), "ceph", "-s"])
    print(proc.stdout, end="")
    if proc.returncode != 0:
        print(proc.stderr, end="", file=sys.stderr)
    return proc.returncode


def cmd_pool_reset() -> int:
    container, pool = ceph_container(), ceph_pool()
    _docker(["exec", container, "ceph", "osd", "pool", "delete", pool, pool,
             "--yes-i-really-really-mean-it"])
    created = _docker(["exec", container, "ceph", "osd", "pool", "create", pool, "32", "32"])
    if created.returncode != 0:
        print(f"ceph_harness: pool create failed: {created.stderr}", file=sys.stderr)
        return 1
    _docker(["exec", container, "ceph", "osd", "pool", "application", "enable", pool, "rados"])
    print(f"ceph_harness: pool '{pool}' recreated")
    return 0


def cmd_stop() -> int:
    _docker(["rm", "-f", ceph_container()])
    print("ceph_harness: stopped")
    return 0


COMMANDS = {
    "start": cmd_start,
    "stop": cmd_stop,
    "status": cmd_status,
    "env": cmd_env,
    "pool-reset": cmd_pool_reset,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=COMMANDS)
    ns = parser.parse_args(argv)
    return COMMANDS[ns.command]()


if __name__ == "__main__":
    raise SystemExit(main())
