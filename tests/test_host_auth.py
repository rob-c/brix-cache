"""XRootD ``host`` (host-based) auth — Phase 52 WS-C.

The native client selects ``host`` (asserting no identity); the server reverse-
resolves the peer socket and authenticates it against ``brix_host_allow`` (exact
hostnames or ``.suffix`` domains), fail-closed.  Covers the mandated trio: success
(peer host in the allowlist), error/security-negative (peer host NOT in the
allowlist must be denied — the allowlist is the only gate).

Throwaway nginx instances come from the registry lifecycle harness; skips if the
client isn't built.  The loopback peer reverse-resolves to ``localhost`` on
essentially every host.
"""
import os
import subprocess
from pathlib import Path

import pytest

from settings import BIND_HOST  # noqa: E402
from server_registry import NginxInstanceSpec

pytestmark = pytest.mark.uses_lifecycle_harness

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NATIVE_XRDCP = os.path.join(REPO, "client", "bin", "xrdcp")


def _loopback_host():
    r = subprocess.run(
        ["bash", "-c", "getent hosts 127.0.0.1 | awk '{print $2}' | head -1"],
        capture_output=True, text=True, timeout=30)
    return r.stdout.strip()


def _start(lifecycle, name, allow):
    """Start a host-auth nginx whose allowlist is ``allow``; seed one file."""
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_host_auth.conf",
        template_values={"BIND_HOST": BIND_HOST, "ALLOWLIST": allow},
        reason="phase-52 host-auth allowlist coverage"))
    Path(endpoint.data_root, "h.txt").write_text("hello-host-auth\n")
    return f"root://127.0.0.1:{endpoint.port}"


@pytest.fixture
def host_servers(lifecycle):
    if not os.path.exists(NATIVE_XRDCP):
        pytest.skip("native client/bin/xrdcp must be built (make -C client)")
    lh = _loopback_host()
    if not lh:
        pytest.skip("127.0.0.1 has no reverse-DNS name on this host")

    # ok allows the loopback name; deny allows only an unrelated host.
    ok = _start(lifecycle, "lc-host-ok", f"{lh} localhost localhost.localdomain")
    deny = _start(lifecycle, "lc-host-deny", "not-this-host.invalid .nope.example")
    return {"ok": ok, "deny": deny}


# ---- success ---------------------------------------------------------------- #

def test_host_allowed(lifecycle, host_servers, tmp_path):
    out = str(tmp_path / "got.txt")
    r = lifecycle.run_cmd([NATIVE_XRDCP, "--auth", "host", "-f",
                           f"{host_servers['ok']}//h.txt", out], timeout=120)
    assert r.returncode == 0, f"host auth (allowed) failed: {r.stderr}"
    assert open(out).read() == "hello-host-auth\n"


# ---- error / security-negative ---------------------------------------------- #

def test_host_not_in_allowlist_denied(lifecycle, host_servers, tmp_path):
    """Peer host absent from brix_host_allow must be denied — the reverse-DNS
    allowlist is the only gate, and it is fail-closed."""
    out = str(tmp_path / "deny.txt")
    r = lifecycle.run_cmd([NATIVE_XRDCP, "--auth", "host", "-f",
                           f"{host_servers['deny']}//h.txt", out], timeout=120)
    assert r.returncode != 0, "host not in allowlist must be denied"
    assert not os.path.exists(out) or os.path.getsize(out) == 0
