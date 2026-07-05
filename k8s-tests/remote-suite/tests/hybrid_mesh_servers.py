#!/usr/bin/env python3
"""
Bring the hybrid two-tier cross-backend mesh up (or down) for the test harness.

manage_test_servers.sh start-all invokes `hybrid_mesh_servers.py start`, which
launches all 7 nodes (a-g) on the dedicated band in hybrid_mesh_lib.PORTS
(daemons detach via -b / nginx pid file, so this process exits once they are up).
`stop` tears them all down.

Usage:  python3 hybrid_mesh_servers.py {start|stop}

If the required binaries (xrootd, cmsd, xrdfs, xrdcp, nginx) are missing, start
is a no-op — tests then skip on closed ports rather than erroring.
"""

import sys

import hybrid_mesh_lib as lib


def main(argv):
    cmd = argv[1] if len(argv) > 1 else "start"

    if cmd == "stop":
        lib.stop_all()
        print("hybrid-mesh: stopped")
        return 0

    if cmd != "start":
        print(f"usage: {argv[0]} {{start|stop}}", file=sys.stderr)
        return 2

    if not lib.have_binaries():
        print("hybrid-mesh: required binaries missing — skipping mesh startup")
        return 0

    lib.stop_all()              # clean any stale instances first
    lib.build_all()

    up = sum(1 for p in lib.MANAGER_PORTS if lib.wait_port(p))
    ready, total, pending = lib.wait_ready(timeout=120)
    if pending:
        names = ", ".join(f"{m}{path}" for m, path in pending)
        print(f"hybrid-mesh: WARNING {total - ready}/{total} probes never "
              f"redirected: {names}", file=sys.stderr)
    print(f"hybrid-mesh: {up}/{len(lib.MANAGER_PORTS)} front doors up, "
          f"{ready}/{total} topologies ready")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
