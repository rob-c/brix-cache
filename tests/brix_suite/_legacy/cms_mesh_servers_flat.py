#!/usr/bin/env python3
"""
Bring the CMS-mesh interop topologies up (or down) for the test harness.

manage_test_servers.sh start-all invokes `cms_mesh_servers.py start`, which
launches every real xrootd/cmsd + nginx instance the mesh tests need on the
fixed ports in cms_mesh_lib.PORTS (daemons detach via -b / nginx pid file, so
this process exits once they are up).  `stop` tears them all down.

Usage:  python3 cms_mesh_servers.py {start|stop}

If the required binaries (xrootd, cmsd, xrdfs, xrdcp, nginx) are missing, start
is a no-op — the tests then skip on closed ports rather than erroring.
"""

import sys

import cms_mesh_lib as lib


def main(argv):
    cmd = argv[1] if len(argv) > 1 else "start"

    if cmd == "stop":
        lib.stop_all()
        print("cms-mesh: stopped")
        return 0

    if cmd != "start":
        print(f"usage: {argv[0]} {{start|stop}}", file=sys.stderr)
        return 2

    if not lib.have_binaries():
        print("cms-mesh: required binaries missing — skipping mesh startup")
        return 0

    lib.stop_all()              # clean any stale instances first
    lib.build_all()

    # First wait for the manager front doors to bind (cheap liveness gate).
    # Poll all front doors together and stop when they are up: a permanent
    # laggard (a misconfig) caps the gate at its timeout instead of serially
    # burning a full per-port budget on it.  expected_manager_ports() drops
    # topologies this box cannot launch (e.g. sss without xrdsssadmin-brix) so the
    # gate never blocks on a manager that was never started.
    managers = lib.expected_manager_ports()
    up = lib.wait_managers_up(managers)

    # ...then actively probe each topology until its manager redirects a known
    # path.  A redirect proves the data node registered and selection works, so
    # this replaces a blind settle-sleep that raced the cluster's formation.
    ready, total, pending = lib.wait_ready(timeout=120)
    if pending:
        names = ", ".join(f"{m}{p}" for m, p in pending)
        print(f"cms-mesh: WARNING {total - ready}/{total} probes never "
              f"redirected: {names}", file=sys.stderr)
    print(f"cms-mesh: started ({up}/{len(managers)} managers listening, "
          f"{ready}/{total} topologies ready)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
