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

def _bindable(port):
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("0.0.0.0", port))  # net-literal-allow: a wildcard probe bind, deliberately not the lane host
        except OSError:
            return False
    return True


def lease_port_range(width, attempts=64):
    """A CONTIGUOUS block of ``width`` free ports, as ``(low, high)``.

    A compose config that pins one (an FTP passive data range, say) makes every
    concurrent copy of that stack fight for the same numbers: the second one
    answers 425 because it can open no data connection.  Each fixture leases
    its own block instead.

    Every port in the block is CONSUMED from the lane's mock-range allocator,
    so a later lease cannot overlap it, and each is probed — a slot the
    allocator believes is free can still be held by a stray listener.
    """
    for _ in range(attempts):
        block = [free_port() for _ in range(width)]
        if block != list(range(block[0], block[0] + width)):
            continue                      # the allocator wrapped or skipped
        if all(_bindable(port) for port in block):
            return block[0], block[-1]
    raise RuntimeError(f"no {width}-port block free after {attempts} attempts")
