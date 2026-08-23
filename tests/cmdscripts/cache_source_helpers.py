"""Shared process and result helpers for cache-source live checks."""

from __future__ import annotations


def start_servers(nginx_bin, specifications, launcher, stop_server):
    """Start ordered server specifications and return paths plus any failure."""
    started = []
    for name, prefix, config in specifications:
        result = launcher([nginx_bin, "-p", str(prefix), "-c", str(config)])
        if result.returncode != 0:
            stop_servers(started, stop_server)
            output = result.stderr or result.stdout
            return [], (False, f"{name} start failed: {output[-4000:]}")
        started.append(prefix)
    return started, None


def stop_servers(started, stop_server):
    for prefix in reversed(started):
        stop_server(prefix)


def exact_transfer(cat, port, source, destination, expected, client):
    result = cat(port, source, destination, client)
    if result.returncode != 0:
        return False
    return destination.read_bytes() == expected

