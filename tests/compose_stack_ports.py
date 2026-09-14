"""Bindability checks for ports leased to local compose-stack fixtures."""

import socket

from ephemeral_port import free_port


def _lease_bindable(attempts=32):
    """A mock-range lease that is actually free on this host right now.

    `free_port()` hands out deterministic slots from the lane's mock range; it
    never probes the kernel. A slot can still be busy — a stray listener, or a
    lane based above the ephemeral floor whose range overlaps live outgoing
    connections (`bind() ... failed (98)` on a compose boot). Skip those.
    """
    for _ in range(attempts):
        port = free_port()
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("0.0.0.0", port))  # net-literal-allow: a wildcard probe bind, deliberately not the lane host
            except OSError:
                continue
        return port
    raise RuntimeError(f"no bindable mock port after {attempts} leases")
