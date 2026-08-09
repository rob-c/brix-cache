"""
test_fault_proxy_fidelity.py — behaviour tests for the brix-fault-proxy
feature-expansion levers (docs/refactor/brix-fault-proxy-feature-expansion.md,
Track U): per-direction toxicity (B1), slow-close (B2), connect-delay (B3),
refuse (B4), latency distribution shaping (B6), persistent control sessions
(A1) and the Prometheus metrics command (D1).

Each lever follows the house 3-test ritual:

* SUCCESS  — the lever changes observable relay behaviour (or the status/metrics
             snapshot) the way its grammar promises.
* ERROR    — a malformed argument (negative delay, unknown distribution, missing
             operand) is rejected with an `err` reply and does *not* mutate state.
* SECURITY / NEG — the boundary that keeps the lever safe: toxicity 0 must fully
             suppress an otherwise-armed fault, refuse must actually drop the
             connection (fail-closed), and an over-long control line must be
             refused rather than overrun the parser buffer.

Self-contained: reuses the echo upstreams + spawn/ctl helpers from
test_brix_fault_proxy on ephemeral ports. No fleet server, so no registry
declaration is required.
"""

import json
import socket
import subprocess
import time

import pytest

from settings import HOST
from _test_brix_fault_proxy_helpers import (  # noqa: F401
    _Echo,
    _StreamEcho,
    _ctl,
    _drain,
    _free_port,
    _spawn,
    bfp,
)

pytestmark = pytest.mark.timeout(120)


def _session(port, cmds):
    """Send several newline-delimited commands over ONE control connection and
    return the concatenated replies — exercises the A1 persistent session."""
    with socket.create_connection((HOST, port), timeout=3) as s:
        s.sendall(("".join(c + "\n" for c in cmds)).encode())
        s.settimeout(1.0)
        out = b""
        end = time.time() + 2.0
        while time.time() < end:
            try:
                d = s.recv(4096)
            except socket.timeout:
                break
            if not d:
                break
            out += d
        return out.decode(errors="replace")


# --------------------------------------------------------------------------- #
# B1 — per-connection toxicity gate                                            #
# --------------------------------------------------------------------------- #
