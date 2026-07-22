"""OS-assigned ephemeral-port allocation for the DOCUMENTED fixed-port EXEMPTIONS.

Phase 5 of the harness refactor retired dynamic port allocation for every server
that goes through the registry: nginx/xrootd/haproxy fleet servers draw fixed
ports from ``fleet_ports``; lifecycle-subject instances draw fixed ports from
``fleet_lifecycle_ports``.  ``settings.free_port`` / ``free_ports`` /
``reserve_ports`` were deleted.

A small, explicitly-enumerated set of binds legitimately still needs an
OS-assigned ephemeral port and is NOT a registry server — those live here so the
distinction stays auditable (``grep free_port`` lands only on this module and its
documented importers, never on a registry spec):

  * **native-xrootd sources** — a dedicated stock ``/usr/bin/xrootd`` a test
    stands up as the *upstream* of the brix instance under test (differential
    comparison, mirror-upstream, native-GSI/TPC source legs).  Not a brix server;
    the brix front DIALS it, so any free port serves.
  * **in-process Python mocks** — a CMS ManagerPeer / firefly UDP sink / stub the
    brix instance DIALS.  Client-side listeners, not registry servers.
  * **docker-published lab ports** — a container (ARC-CE, …) publishes a host
    port via ``-p 127.0.0.1:<port>:443``; the host side must be OS-assigned.
  * **raw-lab proxies / self-contained suites** — brix-fault-proxy and kindred
    hostile-network labs, and self-contained proxy-edge suites that bind their
    own fronts+backends and never touch the managed fleet (env-overridable).
  * **client-flood exhaustion tests** — evil-actor/evil-paths deliberately burn
    ephemeral *client* sockets (Phase 6); those keep their own local helpers.
  * **``cmdscripts/fwd_matrix_live.py``** — the forward-matrix live harness
    rebinds ports inside a per-combination loop (deferred; see the Phase-5 note
    in ``fleet_ports``).

If you are adding a NEW nginx/xrootd/haproxy server a test starts, it does NOT
belong here — give it a fixed port in ``fleet_ports`` (fleet singleton) or
``fleet_lifecycle_ports`` (lifecycle-subject) and let the registry own it.
"""

import socket


def free_port(host="127.0.0.1"):
    """Return one OS-assigned free TCP port (bind :0, read it, release).

    EXEMPTIONS ONLY — see the module docstring.  A registry server must take a
    fixed port from ``fleet_ports`` / ``fleet_lifecycle_ports`` instead.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, 0))
        return s.getsockname()[1]
    finally:
        s.close()


def free_ports(n, host="127.0.0.1"):
    """Return n DISTINCT free TCP ports (sockets held open during allocation so
    the OS hands out different numbers).  EXEMPTIONS ONLY — see the docstring."""
    socks = []
    try:
        for _ in range(n):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, 0))
            socks.append(s)
        return [s.getsockname()[1] for s in socks]
    finally:
        for s in socks:
            s.close()
